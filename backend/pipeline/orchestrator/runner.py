"""
PipelineOrchestrator — end-to-end scan execution coordinator.

The orchestrator is composed of three mixins that each own a distinct
pipeline responsibility:

  DiscoveryMixin     — DNS enumeration, port scanning, TLS probing
  PersistenceMixin   — asset persistence, IP/domain enrichment
  AssessmentMixin    — TLS crypto analysis, risk scoring, artifact generation

This file keeps only the public entry-point (run_scan), the lifecycle
helpers (_transition_scan_to_running, _mark_scan_terminal, etc.), and
the __init__ wiring. Debugging any specific phase is now a matter of
opening the relevant mixin file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

from qdrant_client import QdrantClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.analysis import CertificateAnalyzer
from backend.cbom import CycloneDxMapper
from backend.cert import CertificateSigner
from backend.compliance import RulesEngine
from backend.core.config import get_settings
from backend.core.database import async_session_factory
from backend.discovery import (
    AmassEnumerator,
    CertificateExtractor,
    DNSxValidator,
    PortScanner,
    TLSProbe,
    TLSProbeResult,
    VPNProbe,
    APIInspector,
)
from backend.intelligence import (
    RagOrchestrator,
    RetrievalService,
    create_embedding_provider,
)
from backend.models.discovered_asset import DiscoveredAsset
from backend.models.enums import ScanStatus, ServiceType
from backend.repositories import ScanEventRepository, ScanJobRepository

from .exceptions import ScanNotFoundError, ScanAlreadyRunningError, ScanAlreadyTerminalError
from .models import ScanRuntimeStore
from .serializers import _artifact_key_from_asset
from ._discovery_mixin import DiscoveryMixin
from ._persistence_mixin import PersistenceMixin
from ._assessment_mixin import AssessmentMixin

logger = logging.getLogger(__name__)


class PipelineOrchestrator(DiscoveryMixin, PersistenceMixin, AssessmentMixin):
    """Coordinate the end-to-end Aegis pipeline for one persisted scan job."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        runtime_store: ScanRuntimeStore | None = None,
        enumerator: AmassEnumerator | None = None,
        dns_validator: DNSxValidator | None = None,
        port_scanner: PortScanner | None = None,
        tls_probe: TLSProbe | None = None,
        certificate_extractor: CertificateExtractor | None = None,
        certificate_analyzer: CertificateAnalyzer | None = None,
        rules_engine: RulesEngine | None = None,
        cbom_mapper: CycloneDxMapper | None = None,
        rag_orchestrator: RagOrchestrator | None = None,
        certificate_signer: CertificateSigner | None = None,
    ) -> None:
        self.settings = get_settings()
        self.session_factory = session_factory or async_session_factory
        self.runtime_store = runtime_store
        self.enumerator = enumerator or AmassEnumerator(
            timeout_seconds=max(30, int(os.getenv("AEGIS_AMASS_TIMEOUT_SECONDS", "180"))),
            fallback_max_hostnames=max(
                50,
                int(os.getenv("AEGIS_ENUM_FALLBACK_MAX_HOSTNAMES", "600")),
            ),
        )
        self.dns_validator = dns_validator or DNSxValidator()
        self.port_scanner = port_scanner or PortScanner()
        self.tls_probe = tls_probe or TLSProbe()
        self.vpn_probe = VPNProbe()
        self.api_inspector = APIInspector()
        self.certificate_extractor = certificate_extractor or CertificateExtractor()
        self.certificate_analyzer = certificate_analyzer or CertificateAnalyzer()
        self.rules_engine = rules_engine or RulesEngine()
        self.cbom_mapper = cbom_mapper or CycloneDxMapper()
        self.certificate_signer = certificate_signer or CertificateSigner()
        self.rag_orchestrator = rag_orchestrator or RagOrchestrator(
            retrieval_service=RetrievalService(
                client=QdrantClient(url=self.settings.QDRANT_URL),
                collection_name=self.settings.QDRANT_COLLECTION_NAME,
                embedding_provider=create_embedding_provider(self.settings),
                default_top_k=self.settings.RAG_TOP_K,
            )
        )
        self._ensure_retrieval_runtime_compatibility()
        self._ip_enrichment_cache: dict[str, dict[str, Any]] = {}
        self._domain_enrichment_cache: dict[str, dict[str, Any]] = {}
        self.tls_probe_concurrency = max(
            1,
            int(os.getenv("AEGIS_TLS_PROBE_CONCURRENCY", "50")),
        )
        self.port_scan_concurrency = max(
            1,
            int(os.getenv("AEGIS_PORT_SCAN_CONCURRENCY", "20")),
        )
        self.asset_processing_concurrency = max(
            1,
            int(os.getenv("AEGIS_ASSET_PROCESSING_CONCURRENCY", "24")),
        )
        self.max_tls_sni_targets_per_ip = max(
            1,
            int(os.getenv("AEGIS_MAX_TLS_SNI_PER_IP", "3")),
        )

    def _ensure_retrieval_runtime_compatibility(self) -> None:
        retrieval_service = getattr(self.rag_orchestrator, "retrieval_service", None)
        if retrieval_service is None:
            return
        try:
            retrieval_service.ensure_runtime_collection_compatibility(
                source_dir=Path(self.settings.DOCS_SOURCE_DIR),
                auto_recreate_on_mismatch=self.settings.RAG_AUTO_REBUILD_ON_VECTOR_MISMATCH,
            )
        except Exception:
            logger.exception(
                "Failed retrieval runtime compatibility check; scans will continue with existing collection state."
            )

    def _profile_requests_full_port_scan(self, profile: str | None) -> bool:
        if not profile:
            return False
        normalized = profile.lower()
        # "Deep" inherently maps to full port scan now.
        return "deep" in normalized or "full port scan" in normalized

    def _resolve_skip_enumeration(self, profile: str | None) -> bool:
        if not profile:
            return True
        normalized = profile.lower()
        # "Deep" implies enumeration. "Quick" skips it.
        if "deep" in normalized or "full enumeration" in normalized:
            return False
        return True

    # ── Public entry-point ────────────────────────────────────────────────────

    async def run_scan(self, *, scan_id: uuid.UUID, target: str) -> None:
        """Run the full Phase 3-to-7 pipeline for one existing scan job."""
        terminal_status: ScanStatus | None = None
        terminal_timestamp: datetime | None = None
        scan_profile = await self._get_scan_profile(scan_id)
        full_port_scan_enabled = self._profile_requests_full_port_scan(scan_profile)
        skip_enumeration = self._resolve_skip_enumeration(scan_profile)
        self._add_runtime_event(
            scan_id,
            (
                "Resolved scan profile options: "
                f"full_port_scan={'enabled' if full_port_scan_enabled else 'disabled'}, "
                f"full_enumeration={'enabled' if not skip_enumeration else 'disabled'}."
            ),
            kind="info",
            stage="preparing_scan",
        )

        try:
            if self.runtime_store is not None:
                self.runtime_store.register_scan(scan_id=scan_id, target=target)
                self.runtime_store.set_stage(
                    scan_id,
                    stage="preparing_scan",
                    detail=target,
                    message="Scan execution started.",
                )
            await self._transition_scan_to_running(scan_id)
            discovery = await self._run_discovery(
                target,
                scan_id=scan_id,
                full_port_scan_enabled=full_port_scan_enabled,
                skip_enumeration=skip_enumeration,
            )
            persisted_assets = await self._persist_discovered_assets(
                scan_id=scan_id,
                aggregated_assets=discovery.aggregated_assets,
                port_findings=discovery.port_findings,
                validated_hostnames=discovery.validated_hostnames,
            )
            if self.runtime_store is not None:
                self.runtime_store.add_event(
                    scan_id,
                    f"Persisted {len(persisted_assets)} discovered assets.",
                    kind="success",
                )

            await self._process_tls_assets_for_scan(
                scan_id=scan_id,
                persisted_assets=persisted_assets,
                tls_results_by_key=discovery.tls_results_by_key,
            )

            await self._update_network_graph(target, persisted_assets)

            terminal_status = ScanStatus.COMPLETED
            terminal_timestamp = datetime.now(UTC)
        except (ScanAlreadyRunningError, ScanAlreadyTerminalError):
            raise
        except Exception:
            logger.exception("Unrecoverable scan orchestration failure for %s.", scan_id)
            terminal_status = ScanStatus.FAILED
            terminal_timestamp = datetime.now(UTC)
            if self.runtime_store is not None:
                self.runtime_store.add_event(
                    scan_id,
                    "Scan orchestration failed before completion.",
                    kind="error",
                )
        finally:
            if terminal_status is not None and terminal_timestamp is not None:
                if self.runtime_store is not None:
                    terminal_message = (
                        "Scan completed and all terminal artifacts are available."
                        if terminal_status is ScanStatus.COMPLETED
                        else "Scan failed and entered a terminal state."
                    )
                    self.runtime_store.mark_terminal(
                        scan_id,
                        status=terminal_status,
                        message=terminal_message,
                    )
                await self._mark_scan_terminal(
                    scan_id=scan_id,
                    status=terminal_status,
                    completed_at=terminal_timestamp,
                )
                await self._flush_runtime_events(scan_id)

    # ── TLS asset fan-out ──────────────────────────────────────────────────────

    async def _process_tls_assets_for_scan(
        self,
        *,
        scan_id: uuid.UUID,
        persisted_assets: Sequence[DiscoveredAsset],
        tls_results_by_key: dict[tuple[str | None, str, int, str, str], TLSProbeResult],
    ) -> None:
        semaphore = asyncio.Semaphore(self.asset_processing_concurrency)

        async def _run_asset(asset: DiscoveredAsset, tls_result: TLSProbeResult) -> None:
            async with semaphore:
                await self._process_tls_asset(
                    asset_id=asset.id,
                    tls_result=tls_result,
                    scan_id=scan_id,
                )

        tasks: list[asyncio.Task[None]] = []
        for asset in persisted_assets:
            if asset.service_type is not ServiceType.TLS:
                continue

            tls_result = tls_results_by_key.get(_artifact_key_from_asset(asset))
            if tls_result is None:
                tls_result = TLSProbeResult(
                    hostname=asset.hostname,
                    ip_address=asset.ip_address,
                    port=asset.port,
                    protocol=asset.protocol,
                    tls_version="Handshake Failed",
                    cipher_suite="BROKEN",
                    certificate_chain_pem=(),
                    metadata={"source": "orchestrator-fallback", "handshake_failed": True},
                )

            tasks.append(asyncio.create_task(_run_asset(asset, tls_result)))

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for asset_task, result in zip(tasks, results, strict=True):
            if not isinstance(result, Exception):
                continue
            _ = asset_task
            if self.runtime_store is not None:
                self.runtime_store.add_event(
                    scan_id,
                    "Asset pipeline failed for one or more assets; continued with remaining assets.",
                    kind="error",
                )
            logger.exception(
                "Per-asset pipeline failure for scan %s.",
                scan_id,
                exc_info=result,
            )

    # ── Graph DB ───────────────────────────────────────────────────────────────

    async def _update_network_graph(self, target: str, assets: Sequence[DiscoveredAsset]) -> None:
        try:
            async with self.session_factory() as session:
                await session.execute(text("LOAD 'age'"))
                await session.execute(text('SET search_path = ag_catalog, "$user", public'))

                query1 = text(
                    "SELECT * FROM cypher('aegis_network_graph', $$ MERGE (d:Domain {name: $target}) $$, CAST(:params AS agtype)) as (v agtype);"
                )
                await session.execute(query1, {"params": json.dumps({"target": target})})

                for asset in assets:
                    if not asset.ip_address:
                        continue
                    ip = asset.ip_address
                    port = asset.port
                    service = asset.service_type.value if asset.service_type else "unknown"
                    hostname = asset.hostname or target

                    query2 = text("""
                        SELECT * FROM cypher('aegis_network_graph', $$
                            MATCH (d:Domain {name: $target})
                            MERGE (h:Domain {name: $hostname})
                            MERGE (i:IP {address: $ip})
                            MERGE (p:Port {number: $port, service: $service})
                            MERGE (d)-[:SUBDOMAIN]->(h)
                            MERGE (h)-[:RESOLVES_TO]->(i)
                            MERGE (i)-[:EXPOSES]->(p)
                        $$, CAST(:params AS agtype)) as (v agtype);
                    """)
                    params2 = json.dumps(
                        {
                            "target": target,
                            "hostname": hostname,
                            "ip": str(ip),
                            "port": port,
                            "service": service,
                        }
                    )
                    await session.execute(query2, {"params": params2})

                await session.commit()
        except Exception:
            logger.exception("Failed to update network graph for %s.", target)

    # ── Runtime telemetry helpers ──────────────────────────────────────────────

    def _set_runtime_stage(
        self,
        scan_id: uuid.UUID | None,
        *,
        stage: str,
        detail: str | None = None,
        message: str | None = None,
    ) -> None:
        if scan_id is None or self.runtime_store is None:
            return
        self.runtime_store.set_stage(scan_id, stage=stage, detail=detail, message=message)

    def _add_runtime_event(
        self,
        scan_id: uuid.UUID | None,
        message: str,
        *,
        kind: str = "info",
        stage: str | None = None,
    ) -> None:
        if scan_id is None or self.runtime_store is None:
            return
        self.runtime_store.add_event(scan_id, message, kind=kind, stage=stage)

    def _add_degraded_mode(self, scan_id: uuid.UUID | None, message: str) -> None:
        if scan_id is None or self.runtime_store is None:
            return
        self.runtime_store.add_degraded_mode(scan_id, message)

    # ── Scan lifecycle DB helpers ──────────────────────────────────────────────

    async def _transition_scan_to_running(self, scan_id: uuid.UUID) -> None:
        async with self.session_factory() as session:
            repository = ScanJobRepository(session)
            scan_job = await repository.get_by_id(scan_id)
            if scan_job is None:
                raise ScanNotFoundError(f"Scan {scan_id} does not exist.")
            if scan_job.status is ScanStatus.RUNNING:
                raise ScanAlreadyRunningError(f"Scan {scan_id} is already running.")
            if scan_job.status in {ScanStatus.COMPLETED, ScanStatus.FAILED}:
                raise ScanAlreadyTerminalError(
                    f"Scan {scan_id} is already in terminal state {scan_job.status.value}."
                )
            await repository.update(scan_id, status=ScanStatus.RUNNING, completed_at=None)
            await session.commit()

    async def _mark_scan_terminal(
        self,
        *,
        scan_id: uuid.UUID,
        status: ScanStatus,
        completed_at: datetime,
    ) -> None:
        async with self.session_factory() as session:
            repository = ScanJobRepository(session)
            scan_job = await repository.get_by_id(scan_id)
            if scan_job is None:
                return
            await repository.update(scan_id, status=status, completed_at=completed_at)
            await session.commit()

    async def _get_scan_profile(self, scan_id: uuid.UUID) -> str | None:
        async with self.session_factory() as session:
            repository = ScanJobRepository(session)
            scan_job = await repository.get_by_id(scan_id)
            if scan_job is None:
                return None
            return scan_job.scan_profile

    async def _flush_runtime_events(self, scan_id: uuid.UUID) -> None:
        """Persist in-memory runtime events to the database after scan completion."""
        try:
            if self.runtime_store is None:
                return
            snapshot = self.runtime_store.get_snapshot(scan_id)
            if not snapshot or not snapshot.events:
                return
            async with self.session_factory() as session:
                repo = ScanEventRepository(session)
                for event in snapshot.events:
                    try:
                        async with session.begin_nested():
                            await repo.create(
                                scan_id=scan_id,
                                timestamp=event.timestamp,
                                kind=event.kind,
                                stage=event.stage,
                                message=event.message,
                            )
                    except Exception:
                        logger.exception("Failed to persist scan event for scan %s.", scan_id)
                await session.commit()
        except Exception:
            logger.exception("Failed to persist runtime events for scan %s.", scan_id)
