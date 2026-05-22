"""
Aegis — Quantum Cryptographic Intelligence Platform.

FastAPI application entry point with CORS middleware,
lifespan management, and health check endpoint.
"""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from backend.api.v1.router import api_router
from backend.core.config import get_settings
from backend.core.database import async_session_factory
from backend.models.enums import ScanStatus
from backend.models.scan_event import ScanEvent
from backend.models.scan_job import ScanJob
from backend.pipeline import (
    PipelineOrchestrator,
    ScanNotFoundError,
    ScanReadService,
    ScanRuntimeStore,
)

settings = get_settings()


def _initialize_app_state(app: FastAPI) -> None:
    runtime_store = ScanRuntimeStore()
    app.state.scan_tasks = {}
    app.state.scan_runtime_store = runtime_store
    app.state.pipeline_orchestrator = PipelineOrchestrator(runtime_store=runtime_store)
    app.state.scan_read_service = ScanReadService(runtime_store=runtime_store)


async def _reconcile_inflight_scans_on_startup() -> None:
    """Mark in-flight scans as failed when the process restarts.

    Background scan tasks live in process memory. After a reload/restart there is no task to
    continue those scans, so we fail them explicitly instead of leaving them stuck in running.
    """
    async with async_session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(ScanJob).where(
                        ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
                        ScanJob.completed_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )

        if not rows:
            return

        now = datetime.now(UTC)
        for scan in rows:
            scan.status = ScanStatus.FAILED
            scan.completed_at = now
            session.add(
                ScanEvent(
                    scan_id=scan.id,
                    timestamp=now,
                    kind="error",
                    stage="failed",
                    message=(
                        "Scan marked failed after backend restart because in-memory "
                        "worker state was lost. Please retry the scan."
                    ),
                )
            )

        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan — startup and shutdown hooks."""
    # ── Startup ─────────────────────────────────────────
    # Database engine is created lazily on first query;
    # explicit table creation will be handled by Alembic migrations.
    _initialize_app_state(app)
    await _reconcile_inflight_scans_on_startup()
    yield
    # ── Shutdown ────────────────────────────────────────
    from backend.core.database import engine

    await engine.dispose()


# ── Application Instance ───────────────────────────────
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Autonomous Cryptographic Intelligence Platform — "
        "discovers, inventories, evaluates, and certifies "
        "quantum-safe cryptographic posture for banking infrastructure."
    ),
    version="0.1.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)
_initialize_app_state(app)


def _error_payload(error_type: str, message: str) -> dict[str, dict[str, str]]:
    return {"error": {"type": error_type, "message": message}}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload("http_error", str(exc.detail)),
    )


@app.exception_handler(RequestValidationError)
async def request_validation_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=_error_payload("validation_error", str(exc)),
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content=_error_payload("invalid_request", str(exc)),
    )


@app.exception_handler(ScanNotFoundError)
async def scan_not_found_handler(request: Request, exc: ScanNotFoundError) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content=_error_payload("not_found", str(exc)),
    )


@app.exception_handler(Exception)
async def unexpected_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=_error_payload("internal_error", "An unexpected server error occurred."),
    )


# ── CORS Middleware ─────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount API v1 ────────────────────────────────────────
app.include_router(api_router, prefix=settings.API_V1_STR)


# ── Health Check ────────────────────────────────────────
@app.get("/health", tags=["Infrastructure"])
async def health_check() -> dict[str, str]:
    """Basic health check endpoint."""
    return {"status": "ok"}


# ── Serve Frontend SPA ────────────────────────────────────────
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount(
        "/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets"
    )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Serve exact file if it exists and is safely within the dist directory
        # (e.g. favicon.ico, logo.jpeg)
        requested_path = os.path.abspath(os.path.join(frontend_dist, full_path))

        # Prevent directory traversal attacks
        if not requested_path.startswith(os.path.abspath(frontend_dist)):
            return FileResponse(os.path.join(frontend_dist, "index.html"))

        if os.path.isfile(requested_path):
            return FileResponse(requested_path)

        # Otherwise, serve index.html for SPA routing
        return FileResponse(os.path.join(frontend_dist, "index.html"))
