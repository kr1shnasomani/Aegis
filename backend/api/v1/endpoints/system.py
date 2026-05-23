"""System health and dependency status endpoints."""

from __future__ import annotations

import os
import platform
import time
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.routing import APIRoute
from qdrant_client import QdrantClient
from sqlalchemy import text

from backend.core.config import get_settings
from backend.core.database import async_session_factory

router = APIRouter(tags=["System"])
_APP_START_TS = time.time()


def _status_priority(status: str) -> int:
    if status == "healthy":
        return 0
    if status == "degraded":
        return 1
    if status == "unhealthy":
        return 2
    return 3


def _summarize_health(states: list[str]) -> str:
    if not states:
        return "unknown"
    worst = max(states, key=_status_priority)
    return worst


def _route_inventory(request: Request, api_prefix: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    api_endpoints: list[dict[str, object]] = []
    infra_endpoints: list[dict[str, object]] = []
    for route in request.app.routes:
        if not isinstance(route, APIRoute):
            continue
        methods = sorted(method for method in (route.methods or set()) if method not in {"HEAD", "OPTIONS"})
        if not methods:
            continue
        record: dict[str, object] = {
            "path": route.path,
            "methods": methods,
            "name": route.name,
            "status": "healthy",
        }
        if route.path.startswith(api_prefix):
            api_endpoints.append(record)
        else:
            infra_endpoints.append(record)
    api_endpoints.sort(key=lambda endpoint: (str(endpoint["path"]), ",".join(endpoint["methods"])))
    infra_endpoints.sort(key=lambda endpoint: (str(endpoint["path"]), ",".join(endpoint["methods"])))
    return api_endpoints, infra_endpoints


@router.get("/system/health")
async def get_system_health(request: Request) -> dict[str, object]:
    settings = get_settings()
    now = datetime.now(UTC)
    uptime_seconds = max(int(time.time() - _APP_START_TS), 0)

    backend_status: dict[str, object] = {
        "name": "backend_api",
        "status": "healthy",
        "details": {
            "api_prefix": settings.API_V1_STR,
            "project_name": settings.PROJECT_NAME,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "uptime_seconds": uptime_seconds,
        },
    }

    db_status: dict[str, object] = {
        "name": "postgres",
        "status": "unknown",
        "details": {},
    }
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
            current_database = await session.scalar(text("SELECT current_database()"))
            migration_revision = await session.scalar(
                text("SELECT version_num FROM alembic_version ORDER BY version_num DESC LIMIT 1")
            )
        db_status["status"] = "healthy"
        db_status["details"] = {
            "database_url_configured": bool(settings.DATABASE_URL),
            "database_name": current_database,
            "migration_revision": migration_revision,
        }
    except Exception as exc:
        db_status["status"] = "unhealthy"
        db_status["details"] = {"error": str(exc)[:220]}

    qdrant_status: dict[str, object] = {
        "name": "qdrant",
        "status": "unknown",
        "details": {
            "url": settings.QDRANT_URL,
            "collection": settings.QDRANT_COLLECTION_NAME,
        },
    }
    try:
        client = QdrantClient(url=settings.QDRANT_URL)
        collection_exists = client.collection_exists(settings.QDRANT_COLLECTION_NAME)
        collection_points_count: int | None = None
        if collection_exists:
            collection_info = client.get_collection(settings.QDRANT_COLLECTION_NAME)
            collection_points_count = getattr(collection_info, "points_count", None)
        qdrant_status["status"] = "healthy" if collection_exists else "degraded"
        qdrant_status["details"] = {
            "url": settings.QDRANT_URL,
            "collection": settings.QDRANT_COLLECTION_NAME,
            "collection_exists": collection_exists,
            "points_count": collection_points_count,
        }
    except Exception as exc:
        qdrant_status["status"] = "unhealthy"
        qdrant_status["details"] = {
            "url": settings.QDRANT_URL,
            "collection": settings.QDRANT_COLLECTION_NAME,
            "error": str(exc)[:220],
        }

    docs_source = Path(settings.DOCS_SOURCE_DIR)
    docs_file_count = 0
    docs_dir_exists = docs_source.exists()
    if docs_dir_exists:
        docs_file_count = sum(1 for item in docs_source.rglob("*") if item.is_file())
    docs_check = {
        "name": "docs_corpus",
        "status": "healthy" if docs_dir_exists and docs_file_count > 0 else "degraded",
        "details": {
            "path": str(docs_source),
            "exists": docs_dir_exists,
            "file_count": docs_file_count,
        },
    }

    frontend_dist = Path("frontend/dist")
    assets_dir = frontend_dist / "assets"
    frontend_check = {
        "name": "frontend_bundle",
        "status": "healthy" if frontend_dist.exists() and assets_dir.exists() else "degraded",
        "details": {
            "dist_exists": frontend_dist.exists(),
            "assets_exists": assets_dir.exists(),
        },
    }

    app_state_checks = {
        "name": "app_runtime",
        "status": "healthy",
        "details": {
            "scan_runtime_store_ready": bool(getattr(request.app.state, "scan_runtime_store", None)),
            "pipeline_orchestrator_ready": bool(getattr(request.app.state, "pipeline_orchestrator", None)),
            "scan_read_service_ready": bool(getattr(request.app.state, "scan_read_service", None)),
            "active_scan_tasks": len(getattr(request.app.state, "scan_tasks", {})),
        },
    }

    api_endpoints, infra_endpoints = _route_inventory(request, settings.API_V1_STR)

    services = [backend_status, db_status, qdrant_status]
    system_checks = [docs_check, frontend_check, app_state_checks]
    overall = _summarize_health(
        [str(service["status"]) for service in services] + [str(check["status"]) for check in system_checks]
    )

    return {
        "timestamp": now.isoformat(),
        "overall_status": overall,
        "services": services,
        "system_checks": system_checks,
        "api_endpoints": api_endpoints,
        "infra_endpoints": infra_endpoints,
        "route_totals": {
            "api": len(api_endpoints),
            "infra": len(infra_endpoints),
            "total": len(api_endpoints) + len(infra_endpoints),
        },
        "runtime": {
            "amass_timeout_seconds": int(os.getenv("AEGIS_AMASS_TIMEOUT_SECONDS", "180")),
            "fallback_max_hostnames": int(os.getenv("AEGIS_ENUM_FALLBACK_MAX_HOSTNAMES", "600")),
            "port_scan_concurrency": int(os.getenv("AEGIS_PORT_SCAN_CONCURRENCY", "20")),
            "tls_probe_concurrency": int(os.getenv("AEGIS_TLS_PROBE_CONCURRENCY", "50")),
            "max_scan_ips": int(os.getenv("AEGIS_MAX_SCAN_IPS", "8")),
            "qdrant_collection": settings.QDRANT_COLLECTION_NAME,
            "docs_source_dir": settings.DOCS_SOURCE_DIR,
            "llm_provider_mode": settings.LLM_PROVIDER_MODE,
            "embedding_provider_mode": settings.EMBEDDING_PROVIDER_MODE,
            "rag_enabled": bool(
                settings.QDRANT_URL
                and settings.QDRANT_COLLECTION_NAME
                and settings.DOCS_SOURCE_DIR
            ),
        },
    }
