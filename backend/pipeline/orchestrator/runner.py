"""
PipelineOrchestrator — end-to-end scan execution coordinator.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import uuid
from pathlib import Path
from collections import defaultdict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Sequence

from qdrant_client import QdrantClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.analysis import (
    CertificateAnalyzer,
    HandshakeMetadataResolutionError,
    calculate_risk_score,
    generate_score_explanation,
    parse_tls12_cipher_suite,
    resolve_tls13_handshake_metadata,
)
from backend.analysis.constants import canonicalize_algorithm, lookup_vulnerability
from backend.cbom import AssetCbomBundle, CycloneDxMapper
from backend.cert import CertificateRequest, CertificateSigner
from backend.compliance import ComplianceInput, RulesEngine
from backend.core.config import get_settings
from backend.core.database import async_session_factory
from backend.discovery import (
    AggregatedAsset,
    AmassEnumerator,
    AuthorizedScope,
    CertificateExtractor,
    DNSxValidator,
    PortFinding,
    PortScanner,
    TLSProbe,
    TLSProbeResult,
    TLSScanTarget,
    ValidatedHostname,
    VPNProbe,
    APIInspector,
    URLProbeTarget,
    aggregate_assets,
)
from backend.discovery.dns_enumerator import DNSEnumerationError
from backend.intelligence import (
    RagOrchestrator,
    RemediationInput,
    RetrievalService,
    create_embedding_provider,
)
from backend.models.asset_fingerprint import AssetFingerprint
from backend.models.crypto_assessment import CryptoAssessment
from backend.models.discovered_asset import DiscoveredAsset
from backend.models.certificate_chain import CertificateChain
from backend.models.dns_record import DNSRecord
from backend.models.enums import CertLevel, ComplianceTier, ScanStatus, ServiceType
from backend.models.scan_job import ScanJob
from backend.models.scan_event import ScanEvent
from backend.models.remediation_action import (
    RemediationAction,
    RemediationEffort,
    RemediationPriority,
    RemediationStatus,
)
from backend.repositories import (
    AssetFingerprintRepository,
    CbomDocumentRepository,
    CertificateChainRepository,
    ComplianceCertificateRepository,
    CryptoAssessmentRepository,
    DNSRecordRepository,
    DiscoveredAssetRepository,
    RemediationBundleRepository,
    ScanEventRepository,
    ScanJobRepository,
)
from .exceptions import ScanNotFoundError, ScanAlreadyRunningError, ScanAlreadyTerminalError
from .models import (
    _AssessmentInputs,
    _DiscoveryExecution,
    ScanRuntimeStore,
    ScanRuntimeState,
    ScanRuntimeEvent,
    RUNTIME_EVENT_DEDUP_WINDOW_SECONDS,
    MAX_SCAN_RUNTIME_EVENTS,
    ETA_STAGE_WEIGHTS_SECONDS,
    ETA_STAGE_ORDER,
    COMMON_ENUMERATION_PREFIXES,
)
from .serializers import (
    select_latest_cbom,
    select_latest_certificate,
    select_latest_remediation,
    serialize_assessment,
    serialize_cbom,
    serialize_remediation,
    serialize_certificate,
    serialize_leaf_certificate,
    serialize_asset_certificate,
    serialize_asset_fingerprint,
    serialize_asset_fingerprint_history_entry,
    serialize_remediation_action,
    serialize_dns_record,
    serialize_runtime_event,
    serialize_persisted_scan_event,
    _artifact_key_from_tls_result,
    _artifact_key_from_asset,
    build_asset_fingerprint_key,
    _normalize_hostname,
    extract_subject_cn,
)

logger = logging.getLogger(__name__)

class PipelineOrchestrator:
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

            # Update Graph DB
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
                try:
                    if self.runtime_store is not None:
                        snapshot = self.runtime_store.get_snapshot(scan_id)
                        if snapshot and snapshot.events:
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
                                        logger.exception(
                                            "Failed to persist scan event for scan %s.",
                                            scan_id,
                                        )
                                await session.commit()
                except Exception:
                    logger.exception(
                        "Failed to persist runtime events for scan %s.",
                        scan_id,
                    )

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

            # Pull the asset label from the task name context when available.
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

    async def _update_network_graph(self, target: str, assets: Sequence[DiscoveredAsset]) -> None:
        try:
            async with self.session_factory() as session:
                await session.execute(text("LOAD 'age'"))
                await session.execute(text('SET search_path = ag_catalog, "$user", public'))

                query1 = f"SELECT * FROM cypher('aegis_network_graph', $$ MERGE (d:Domain {{name: '{target}'}}) $$) as (v agtype);"
                await session.execute(text(query1))

                for asset in assets:
                    if not asset.ip_address:
                        continue
                    ip = asset.ip_address
                    port = asset.port
                    service = asset.service_type.value if asset.service_type else "unknown"
                    hostname = asset.hostname or target

                    query2 = f"""
                        SELECT * FROM cypher('aegis_network_graph', $$
                            MATCH (d:Domain {{name: '{target}'}})
                            MERGE (h:Domain {{name: '{hostname}'}})
                            MERGE (i:IP {{address: '{ip}'}})
                            MERGE (p:Port {{number: '{port}', service: '{service}'}})
                            MERGE (d)-[\:SUBDOMAIN]->(h)
                            MERGE (h)-[\:RESOLVES_TO]->(i)
                            MERGE (i)-[\:EXPOSES]->(p)
                        $$) as (v agtype);
                    """
                    await session.execute(text(query2))

                await session.commit()
        except Exception:
            logger.exception("Failed to update network graph for %s.", target)

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
        self.runtime_store.set_stage(
            scan_id,
            stage=stage,
            detail=detail,
            message=message,
        )

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
        self.runtime_store.add_event(
            scan_id,
            message,
            kind=kind,
            stage=stage,
        )

    def _add_degraded_mode(self, scan_id: uuid.UUID | None, message: str) -> None:
        if scan_id is None or self.runtime_store is None:
            return
        self.runtime_store.add_degraded_mode(scan_id, message)

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

            await repository.update(
                scan_id,
                status=ScanStatus.RUNNING,
                completed_at=None,
            )
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
            await repository.update(
                scan_id,
                status=status,
                completed_at=completed_at,
            )
            await session.commit()

    async def _get_scan_profile(self, scan_id: uuid.UUID) -> str | None:
        async with self.session_factory() as session:
            repository = ScanJobRepository(session)
            scan_job = await repository.get_by_id(scan_id)
            if scan_job is None:
                return None
            return scan_job.scan_profile

    @staticmethod
    def _profile_requests_full_port_scan(scan_profile: str | None) -> bool:
        if not scan_profile:
            return False

        normalized = scan_profile.lower()
        return (
            "full-port" in normalized
            or "full_port" in normalized
            or "full port" in normalized
            or "all-ports" in normalized
            or "all_ports" in normalized
            or "all ports" in normalized
        )

    def _resolve_skip_enumeration(self, scan_profile: str | None) -> bool:
        # Start from global setting and allow per-scan override.
        if not scan_profile:
            return self.settings.SKIP_ENUMERATION

        normalized = scan_profile.lower()
        if "full enumeration" in normalized or "enumeration enabled" in normalized:
            return False
        if "no enumeration" in normalized or "enumeration disabled" in normalized:
            return True
        return self.settings.SKIP_ENUMERATION

    def _select_tls_hostnames(self, scope: AuthorizedScope, hostnames: set[str]) -> list[str]:
        if not hostnames:
            return []

        normalized = sorted(
            {hostname.strip().lower().rstrip(".") for hostname in hostnames if hostname}
        )
        if len(normalized) <= self.max_tls_sni_targets_per_ip:
            return normalized

        prioritized: list[str] = []
        if scope.domain:
            root = scope.domain.strip().lower().rstrip(".")
            www = f"www.{root}"
            for candidate in (root, www):
                if candidate in normalized and candidate not in prioritized:
                    prioritized.append(candidate)

        for hostname in normalized:
            if hostname in prioritized:
                continue
            prioritized.append(hostname)
            if len(prioritized) >= self.max_tls_sni_targets_per_ip:
                break

        return prioritized[: self.max_tls_sni_targets_per_ip]

    @staticmethod
    def _augment_hostname_candidates(base_domain: str, hostnames: set[str]) -> int:
        before = len(hostnames)
        for prefix in COMMON_ENUMERATION_PREFIXES:
            hostnames.add(f"{prefix}.{base_domain}")
        return len(hostnames) - before

    @staticmethod
    def _format_enumeration_reason(exc: Exception) -> str:
        reason = str(exc).strip()
        if not reason:
            return "unknown"
        return reason[:180]

    async def _run_discovery(
        self,
        target: str,
        *,
        scan_id: uuid.UUID | None = None,
        full_port_scan_enabled: bool = False,
        skip_enumeration: bool = False,
    ) -> _DiscoveryExecution:
        scope = AuthorizedScope.from_target(target)
        supports_streaming_enumerator = callable(getattr(self.enumerator, "enumerate_stream", None))
        if scope.scope_type == "domain" and not skip_enumeration and supports_streaming_enumerator:
            return await self._run_discovery_streaming(
                target=target,
                scope=scope,
                scan_id=scan_id,
                full_port_scan_enabled=full_port_scan_enabled,
            )

        validated_hostnames = await self._resolve_hostnames(
            target,
            scope,
            scan_id=scan_id,
            skip_enumeration=skip_enumeration,
        )
        ip_addresses = self._collect_scan_ips(scope, validated_hostnames)
        self._add_runtime_event(
            scan_id,
            f"Prepared {len(ip_addresses)} address(es) for port scanning.",
            kind="info",
            stage="scanning_ports",
        )
        port_findings = await self._scan_ports(
            ip_addresses,
            scan_id=scan_id,
            full_port_scan_enabled=full_port_scan_enabled,
        )
        tls_results = await self._probe_tls_targets(
            scope=scope,
            validated_hostnames=validated_hostnames,
            port_findings=port_findings,
            scan_id=scan_id,
        )

        if len(port_findings) == 0:
            fallback_tls_results = await self._probe_tls_fallback_without_port_findings(
                scope=scope,
                validated_hostnames=validated_hostnames,
                ip_addresses=ip_addresses,
                scan_id=scan_id,
            )
            if fallback_tls_results:
                tls_results.extend(fallback_tls_results)

        # Call optional probes for VPN and API metadata
        vpn_results = []
        for pf in port_findings:
            if pf.service_type == ServiceType.VPN:
                vpn_results.append(self.vpn_probe.probe(pf.ip_address, pf.port, pf.protocol))

        api_tasks = []
        # Check all discovered web-like ports for JWT/mTLS
        for pf in port_findings:
            if pf.port in {80, 443, 8080, 8443}:
                scheme = "https" if pf.port in {443, 8443} else "http"
                target_url = f"{scheme}://{pf.ip_address}:{pf.port}"
                api_tasks.append(self.api_inspector.inspect(URLProbeTarget(url=target_url)))
        api_results = await asyncio.gather(*api_tasks) if api_tasks else []

        aggregated_assets = aggregate_assets(
            target,
            validated_hostnames,
            port_findings,
            tls_results,
            vpn_results,
            api_results,
        )
        self._add_runtime_event(
            scan_id,
            f"Discovery produced {len(aggregated_assets)} aggregated asset candidate(s).",
            kind="success",
            stage="persisting_assets",
        )
        return _DiscoveryExecution(
            aggregated_assets=tuple(aggregated_assets),
            port_findings=tuple(port_findings),
            validated_hostnames=tuple(validated_hostnames),
            tls_results_by_key={
                _artifact_key_from_tls_result(result): result for result in tls_results
            },
        )

    async def _run_discovery_streaming(
        self,
        *,
        target: str,
        scope: AuthorizedScope,
        scan_id: uuid.UUID | None,
        full_port_scan_enabled: bool,
    ) -> _DiscoveryExecution:
        hostnames: set[str] = {scope.domain} if scope.domain else set()
        if scope.domain:
            hostnames.add(f"www.{scope.domain}")

        validated_hostnames_stream: dict[str, ValidatedHostname] = {}
        ip_to_hostnames: dict[str, set[str]] = defaultdict(set)
        queued_ips: set[str] = set()
        port_findings: list[PortFinding] = []
        tls_results: list[TLSProbeResult] = []
        seen_port_keys: set[tuple[str, int, str]] = set()
        seen_tls_targets: set[tuple[str | None, str, int, str]] = set()

        tls_semaphore = asyncio.Semaphore(self.tls_probe_concurrency)
        port_semaphore = asyncio.Semaphore(self.port_scan_concurrency)
        lock = asyncio.Lock()
        tls_tasks: set[asyncio.Task[None]] = set()
        port_tasks: set[asyncio.Task[None]] = set()
        port_stage_announced = False
        tls_stage_announced = False

        async def _probe_tls_target(target_item: TLSScanTarget) -> None:
            async with tls_semaphore:
                try:
                    result = await self.tls_probe.probe(target_item)
                except Exception:
                    logger.exception(
                        "TLS probing failed for %s:%s.",
                        target_item.server_name,
                        target_item.port,
                    )
                    self._add_runtime_event(
                        scan_id,
                        f"TLS probing failed for {target_item.server_name}; continuing with remaining endpoints.",
                        kind="error",
                        stage="probing_tls",
                    )
                    return

            async with lock:
                tls_results.append(result)

        def _schedule_tls_target(target_item: TLSScanTarget) -> None:
            nonlocal tls_stage_announced
            target_key = (
                target_item.hostname,
                target_item.ip_address,
                target_item.port,
                target_item.protocol,
            )
            if target_key in seen_tls_targets:
                return
            seen_tls_targets.add(target_key)

            if not tls_stage_announced:
                self._set_runtime_stage(
                    scan_id,
                    stage="probing_tls",
                    detail="streaming",
                    message="Negotiating TLS handshakes for discovered endpoints.",
                )
                tls_stage_announced = True

            task = asyncio.create_task(_probe_tls_target(target_item))
            tls_tasks.add(task)
            task.add_done_callback(tls_tasks.discard)

        async def _scan_ip(ip_address: str) -> None:
            nonlocal port_stage_announced
            if not port_stage_announced:
                self._set_runtime_stage(
                    scan_id,
                    stage="scanning_ports",
                    detail="streaming",
                    message="Running streaming port scans for discovered addresses.",
                )
                port_stage_announced = True

            async with port_semaphore:
                try:
                    findings = await self._scan_host_with_profile(
                        ip_address,
                        full_port_scan_enabled,
                    )
                except Exception:
                    logger.exception("Port scan failed for %s.", ip_address)
                    self._add_runtime_event(
                        scan_id,
                        f"Port scan failed for {ip_address}; continuing with remaining addresses.",
                        kind="error",
                        stage="scanning_ports",
                    )
                    return

            async with lock:
                known_hostnames = self._select_tls_hostnames(
                    scope, ip_to_hostnames.get(ip_address, set())
                )
                for finding in findings:
                    finding_key = (finding.ip_address, finding.port, finding.protocol)
                    if finding_key in seen_port_keys:
                        continue
                    seen_port_keys.add(finding_key)
                    port_findings.append(finding)
                    if finding.service_type is not ServiceType.TLS:
                        continue

                    if known_hostnames:
                        for hostname in known_hostnames:
                            _schedule_tls_target(
                                TLSScanTarget(
                                    hostname=hostname,
                                    ip_address=finding.ip_address,
                                    port=finding.port,
                                    protocol=finding.protocol,
                                )
                            )
                    else:
                        _schedule_tls_target(
                            TLSScanTarget(
                                hostname=None,
                                ip_address=finding.ip_address,
                                port=finding.port,
                                protocol=finding.protocol,
                            )
                        )

        async def _resolve_hostname_streaming(hostname: str, source: str) -> None:
            normalized_hostname = hostname.strip().lower().rstrip(".")
            if not normalized_hostname or not scope.contains(hostname=normalized_hostname):
                return

            try:
                resolved = await asyncio.to_thread(socket.getaddrinfo, normalized_hostname, None)
            except socket.gaierror:
                return

            ip_addresses = tuple(
                sorted({info[4][0] for info in resolved if info and len(info) >= 5 and info[4]})
            )
            if not ip_addresses:
                return

            scan_ipv6 = os.getenv("AEGIS_SCAN_IPV6", "false").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            ipv4_addresses = tuple(
                address for address in ip_addresses if ipaddress.ip_address(address).version == 4
            )
            selected_ip_addresses = ip_addresses if scan_ipv6 else (ipv4_addresses or ip_addresses)

            async with lock:
                validated_hostnames_stream[normalized_hostname] = ValidatedHostname(
                    hostname=normalized_hostname,
                    ip_addresses=selected_ip_addresses,
                    source=source,
                )
                for ip_address in selected_ip_addresses:
                    ip_to_hostnames[ip_address].add(normalized_hostname)
                    if ip_address in queued_ips:
                        continue
                    queued_ips.add(ip_address)
                    scan_task = asyncio.create_task(_scan_ip(ip_address))
                    port_tasks.add(scan_task)
                    scan_task.add_done_callback(port_tasks.discard)

                    self._add_runtime_event(
                        scan_id,
                        f"Discovered {normalized_hostname} -> {ip_address}; queued port scan.",
                        kind="info",
                        stage="scanning_ports",
                    )

                # If this hostname arrived after ports were already found, immediately queue SNI probes.
                for finding in port_findings:
                    if (
                        finding.ip_address not in selected_ip_addresses
                        or finding.service_type is not ServiceType.TLS
                    ):
                        continue
                    selected_hostnames = self._select_tls_hostnames(
                        scope,
                        ip_to_hostnames.get(finding.ip_address, set()),
                    )
                    if normalized_hostname not in selected_hostnames:
                        continue
                    _schedule_tls_target(
                        TLSScanTarget(
                            hostname=normalized_hostname,
                            ip_address=finding.ip_address,
                            port=finding.port,
                            protocol=finding.protocol,
                        )
                    )

        self._set_runtime_stage(
            scan_id,
            stage="enumerating_domains",
            detail=target,
            message=f"Enumerating hostnames for {target} with streaming pipeline.",
        )

        if scope.domain is not None:
            seeded_count = self._augment_hostname_candidates(scope.domain, hostnames)
            if seeded_count > 0:
                self._add_runtime_event(
                    scan_id,
                    f"Prepared {seeded_count} deterministic hostname seed(s) for streaming enumeration fallback.",
                    kind="info",
                    stage="enumerating_domains",
                )

        hostname_tasks = [
            asyncio.create_task(_resolve_hostname_streaming(candidate, "seed"))
            for candidate in sorted(hostnames)
        ]

        try:
            async for record in self.enumerator.enumerate_stream(target):
                normalized = record.hostname.strip().lower().rstrip(".")
                if not normalized or normalized in hostnames:
                    continue
                hostnames.add(normalized)
                hostname_tasks.append(
                    asyncio.create_task(_resolve_hostname_streaming(normalized, record.source))
                )
        except DNSEnumerationError as exc:
            logger.warning(
                "Domain enumeration unavailable for %s; continuing with streaming seeds. Reason: %s",
                target,
                exc,
            )
            self._add_degraded_mode(
                scan_id,
                (
                    f"Domain enumeration unavailable for {target}; "
                    f"continued with deterministic seeds. Reason: {self._format_enumeration_reason(exc)}"
                ),
            )
        except Exception:
            logger.exception(
                "Domain enumeration failed for %s; continuing with streaming seeds.",
                target,
            )
            self._add_degraded_mode(
                scan_id,
                f"Domain enumeration failed for {target}; continued with deterministic seeds.",
            )

        if hostname_tasks:
            await asyncio.gather(*hostname_tasks, return_exceptions=True)

        if port_tasks:
            await asyncio.gather(*list(port_tasks), return_exceptions=True)
        if tls_tasks:
            await asyncio.gather(*list(tls_tasks), return_exceptions=True)

        self._set_runtime_stage(
            scan_id,
            stage="validating_dns",
            detail=f"{len(hostnames)} hostname(s)",
            message="Validating DNS resolution for discovered hostnames.",
        )
        validated_hostnames = await self.dns_validator.validate(hostnames)

        if scan_id is not None and validated_hostnames:
            try:
                async with self.session_factory() as session:
                    dns_record_repository = DNSRecordRepository(session)
                    for validated_hostname in validated_hostnames:
                        try:
                            async with session.begin_nested():
                                await dns_record_repository.create(
                                    scan_id=scan_id,
                                    hostname=validated_hostname.hostname,
                                    resolved_ips=list(validated_hostname.ip_addresses),
                                    cnames=list(validated_hostname.cnames),
                                    discovery_source=validated_hostname.source,
                                    is_in_scope=True,
                                )
                        except Exception:
                            logger.exception(
                                "Failed to persist DNS record for scan %s hostname %s.",
                                scan_id,
                                validated_hostname.hostname,
                            )
                    await session.commit()
            except Exception:
                logger.exception(
                    "Failed to persist DNS records for scan %s.",
                    scan_id,
                )

        ip_addresses = sorted(
            {ip for validated in validated_hostnames for ip in validated.ip_addresses}
            | set(queued_ips)
        )

        if len(port_findings) == 0:
            fallback_tls_results = await self._probe_tls_fallback_without_port_findings(
                scope=scope,
                validated_hostnames=validated_hostnames,
                ip_addresses=ip_addresses,
                scan_id=scan_id,
            )
            if fallback_tls_results:
                tls_results.extend(fallback_tls_results)

        vpn_results = []
        for pf in port_findings:
            if pf.service_type == ServiceType.VPN:
                vpn_results.append(self.vpn_probe.probe(pf.ip_address, pf.port, pf.protocol))

        api_tasks = []
        for pf in port_findings:
            if pf.port in {80, 443, 8080, 8443}:
                scheme = "https" if pf.port in {443, 8443} else "http"
                target_url = f"{scheme}://{pf.ip_address}:{pf.port}"
                api_tasks.append(self.api_inspector.inspect(URLProbeTarget(url=target_url)))
        api_results = await asyncio.gather(*api_tasks) if api_tasks else []

        aggregated_assets = aggregate_assets(
            target,
            validated_hostnames,
            port_findings,
            tls_results,
            vpn_results,
            api_results,
        )

        self._add_runtime_event(
            scan_id,
            f"Discovery produced {len(aggregated_assets)} aggregated asset candidate(s).",
            kind="success",
            stage="persisting_assets",
        )
        return _DiscoveryExecution(
            aggregated_assets=tuple(aggregated_assets),
            port_findings=tuple(port_findings),
            validated_hostnames=tuple(validated_hostnames),
            tls_results_by_key={
                _artifact_key_from_tls_result(result): result for result in tls_results
            },
        )

    async def _resolve_hostnames(
        self,
        target: str,
        scope: AuthorizedScope,
        *,
        scan_id: uuid.UUID | None = None,
        skip_enumeration: bool = False,
    ) -> list[ValidatedHostname]:
        if scope.scope_type != "domain" or scope.domain is None:
            self._add_runtime_event(
                scan_id,
                "Target scope does not require domain enumeration; continuing with direct address handling.",
                kind="info",
                stage="validating_dns",
            )
            return []

        hostnames = {scope.domain}
        www_candidate = f"www.{scope.domain}"
        hostnames.add(www_candidate)
        if skip_enumeration:
            self._add_runtime_event(
                scan_id,
                (
                    "Domain enumeration skipped via configuration; "
                    f"using root and www candidate hostnames: {target}, {www_candidate}"
                ),
                kind="info",
                stage="enumerating_domains",
            )
        else:
            seeded_count = self._augment_hostname_candidates(scope.domain, hostnames)
            if seeded_count > 0:
                self._add_runtime_event(
                    scan_id,
                    f"Prepared {seeded_count} deterministic hostname seed(s) for full enumeration.",
                    kind="info",
                    stage="enumerating_domains",
                )
            self._set_runtime_stage(
                scan_id,
                stage="enumerating_domains",
                detail=target,
                message=f"Enumerating hostnames for {target}.",
            )
            try:
                enumerated = await self.enumerator.enumerate(target)
                hostnames.update(record.hostname for record in enumerated)
                self._add_runtime_event(
                    scan_id,
                    f"Enumeration completed with {len(hostnames)} hostname candidate(s).",
                    kind="success",
                    stage="enumerating_domains",
                )
            except DNSEnumerationError as exc:
                logger.warning(
                    "Domain enumeration unavailable for %s; continuing with deterministic seeds. Reason: %s",
                    target,
                    exc,
                )
                self._add_degraded_mode(
                    scan_id,
                    (
                        f"Domain enumeration unavailable for {target}; "
                        f"continued with deterministic seeds. Reason: {self._format_enumeration_reason(exc)}"
                    ),
                )
            except Exception:
                logger.exception(
                    "Domain enumeration failed for %s; continuing with deterministic seeds.",
                    target,
                )
                self._add_degraded_mode(
                    scan_id,
                    f"Domain enumeration failed for {target}; continued with deterministic seeds.",
                )

        self._set_runtime_stage(
            scan_id,
            stage="validating_dns",
            detail=f"{len(hostnames)} hostname(s)",
            message="Validating DNS resolution for discovered hostnames.",
        )
        validated = await self.dns_validator.validate(hostnames)
        if scan_id is not None and validated:
            try:
                async with self.session_factory() as session:
                    dns_record_repository = DNSRecordRepository(session)
                    for validated_hostname in validated:
                        try:
                            async with session.begin_nested():
                                await dns_record_repository.create(
                                    scan_id=scan_id,
                                    hostname=validated_hostname.hostname,
                                    resolved_ips=list(validated_hostname.ip_addresses),
                                    cnames=list(validated_hostname.cnames),
                                    discovery_source=validated_hostname.source,
                                    is_in_scope=True,
                                )
                        except Exception:
                            logger.exception(
                                "Failed to persist DNS record for scan %s hostname %s.",
                                scan_id,
                                validated_hostname.hostname,
                            )
                    await session.commit()
            except Exception:
                logger.exception(
                    "Failed to persist DNS records for scan %s.",
                    scan_id,
                )
        self._add_runtime_event(
            scan_id,
            f"DNS validation retained {len(validated)} hostname(s) in scope.",
            kind="success",
            stage="validating_dns",
        )
        return validated

    @staticmethod
    def _collect_scan_ips(
        scope: AuthorizedScope,
        validated_hostnames: Sequence[ValidatedHostname],
    ) -> list[str]:
        max_scan_ips = max(1, int(os.getenv("AEGIS_MAX_SCAN_IPS", "8")))

        if scope.scope_type == "domain":
            unique_ips = sorted(
                {
                    ip_address
                    for validated in validated_hostnames
                    for ip_address in validated.ip_addresses
                }
            )
            ipv4_candidates = [
                ip_address
                for ip_address in unique_ips
                if ipaddress.ip_address(ip_address).version == 4
            ]
            preferred = ipv4_candidates if ipv4_candidates else unique_ips
            return preferred[:max_scan_ips]
        if scope.scope_type == "ip" and scope.ip_address is not None:
            return [str(scope.ip_address)]
        if scope.scope_type == "network" and scope.network is not None:
            return [str(ip_address) for ip_address in scope.network.hosts()][:max_scan_ips]
        return []

    async def _scan_ports(
        self,
        ip_addresses: Sequence[str],
        *,
        scan_id: uuid.UUID | None = None,
        full_port_scan_enabled: bool = False,
    ) -> list[PortFinding]:
        findings: list[PortFinding] = []
        if not ip_addresses:
            self._add_runtime_event(
                scan_id,
                "No IP addresses were available for port scanning.",
                kind="info",
                stage="scanning_ports",
            )
            return findings

        stage_message = (
            "Running full TCP scan across all ports (1-65535) and bounded UDP discovery."
            if full_port_scan_enabled
            else "Running bounded TCP/UDP discovery across in-scope addresses."
        )

        self._set_runtime_stage(
            scan_id,
            stage="scanning_ports",
            detail=f"{len(ip_addresses)} address(es)",
            message=stage_message,
        )

        semaphore = asyncio.Semaphore(self.port_scan_concurrency)

        async def _scan_with_limit(ip_address: str) -> list[PortFinding]:
            async with semaphore:
                return await self._scan_host_with_profile(ip_address, full_port_scan_enabled)

        scan_results = await asyncio.gather(
            *(_scan_with_limit(ip_address) for ip_address in ip_addresses),
            return_exceptions=True,
        )
        for ip_address, result in zip(ip_addresses, scan_results, strict=True):
            if isinstance(result, Exception):
                logger.exception("Port scan failed for %s.", ip_address, exc_info=result)
                self._add_runtime_event(
                    scan_id,
                    f"Port scan failed for {ip_address}; continuing with remaining addresses.",
                    kind="error",
                    stage="scanning_ports",
                )
                continue
            findings.extend(result)
        self._add_runtime_event(
            scan_id,
            f"Port scanning completed with {len(findings)} open service finding(s).",
            kind="success",
            stage="scanning_ports",
        )
        return findings

    async def _scan_host_with_profile(
        self,
        ip_address: str,
        full_port_scan_enabled: bool,
    ) -> list[PortFinding]:
        """Call scanner with backward compatibility for older stub signatures."""
        try:
            return await self.port_scanner.scan_host(
                ip_address,
                full_tcp_scan=full_port_scan_enabled,
            )
        except TypeError:
            return await self.port_scanner.scan_host(ip_address)

    async def _probe_tls_targets(
        self,
        *,
        scope: AuthorizedScope,
        validated_hostnames: Sequence[ValidatedHostname],
        port_findings: Sequence[PortFinding],
        scan_id: uuid.UUID | None = None,
    ) -> list[TLSProbeResult]:
        ip_to_hostnames = self._build_ip_hostname_index(scope, validated_hostnames)
        tls_targets: list[TLSScanTarget] = []
        seen_targets: set[tuple[str | None, str, int, str]] = set()

        def _append_tls_target(target: TLSScanTarget) -> None:
            key = (target.hostname, target.ip_address, target.port, target.protocol)
            if key in seen_targets:
                return
            seen_targets.add(key)
            tls_targets.append(target)

        for finding in port_findings:
            if finding.service_type is not ServiceType.TLS:
                continue

            hostnames = self._select_tls_hostnames(
                scope, ip_to_hostnames.get(finding.ip_address, set())
            )
            if hostnames:
                for hostname in hostnames:
                    _append_tls_target(
                        TLSScanTarget(
                            hostname=hostname,
                            ip_address=finding.ip_address,
                            port=finding.port,
                            protocol=finding.protocol,
                        )
                    )
            else:
                _append_tls_target(
                    TLSScanTarget(
                        hostname=None,
                        ip_address=finding.ip_address,
                        port=finding.port,
                        protocol=finding.protocol,
                    )
                )

        self._set_runtime_stage(
            scan_id,
            stage="probing_tls",
            detail=f"{len(tls_targets)} TLS endpoint(s)",
            message="Negotiating TLS handshakes and retrieving certificate chains.",
        )
        semaphore = asyncio.Semaphore(self.tls_probe_concurrency)

        async def _probe_with_limit(target: TLSScanTarget) -> TLSProbeResult:
            async with semaphore:
                return await self.tls_probe.probe(target)

        probe_tasks = [asyncio.create_task(_probe_with_limit(target)) for target in tls_targets]
        done, _pending = await asyncio.wait(probe_tasks)
        tls_results: list[TLSProbeResult] = []
        for task, tls_target in zip(probe_tasks, tls_targets, strict=True):
            if task not in done:
                continue
            if task.cancelled():
                result: TLSProbeResult | Exception = asyncio.TimeoutError(
                    "TLS probe task cancelled due to stage timeout."
                )
            else:
                try:
                    result = task.result()
                except Exception as exc:
                    result = exc

            if isinstance(result, Exception):
                logger.exception(
                    "TLS probing failed for %s:%s.",
                    tls_target.server_name,
                    tls_target.port,
                    exc_info=result,
                )
                self._add_runtime_event(
                    scan_id,
                    f"TLS probing failed for {tls_target.server_name}; continuing with remaining endpoints.",
                    kind="error",
                    stage="probing_tls",
                )
                continue
            tls_results.append(result)
        self._add_runtime_event(
            scan_id,
            f"TLS probing completed with {len(tls_results)} successful handshake result(s).",
            kind="success",
            stage="probing_tls",
        )
        return tls_results

    async def _probe_tls_fallback_without_port_findings(
        self,
        *,
        scope: AuthorizedScope,
        validated_hostnames: Sequence[ValidatedHostname],
        ip_addresses: Sequence[str],
        scan_id: uuid.UUID | None = None,
    ) -> list[TLSProbeResult]:
        """
        Fallback TLS probing path for environments where nmap reports zero open ports.

        This attempts direct TLS handshakes to common HTTPS ports using hostname+SNI.
        """
        common_tls_ports = (443, 8443)
        scan_ipv6 = os.getenv("AEGIS_SCAN_IPV6", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        def _selected_probe_ips(addresses: Sequence[str]) -> tuple[str, ...]:
            if scan_ipv6:
                return tuple(addresses)
            ipv4_addresses = tuple(
                address
                for address in addresses
                if ipaddress.ip_address(address).version == 4
            )
            return ipv4_addresses or tuple(addresses)

        targets: list[TLSScanTarget] = []
        seen: set[tuple[str | None, str, int]] = set()

        for validated in validated_hostnames:
            normalized_hostname = validated.hostname.strip().lower().rstrip(".")
            if not scope.contains(hostname=normalized_hostname):
                continue
            for ip_address in _selected_probe_ips(validated.ip_addresses):
                for port in common_tls_ports:
                    key = (normalized_hostname, ip_address, port)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        TLSScanTarget(
                            hostname=normalized_hostname,
                            ip_address=ip_address,
                            port=port,
                            protocol="tcp",
                        )
                    )

        if not targets and scope.scope_type in {"ip", "network"}:
            for ip_address in _selected_probe_ips(ip_addresses):
                for port in common_tls_ports:
                    key = (None, ip_address, port)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        TLSScanTarget(
                            hostname=None,
                            ip_address=ip_address,
                            port=port,
                            protocol="tcp",
                        )
                    )

        if not targets:
            return []

        self._add_runtime_event(
            scan_id,
            (
                "Port scanning yielded 0 open findings; "
                "attempting direct TLS fallback on common HTTPS ports (443, 8443)."
            ),
            kind="degraded",
            stage="probing_tls",
        )

        semaphore = asyncio.Semaphore(self.tls_probe_concurrency)

        async def _probe_with_limit(target: TLSScanTarget) -> TLSProbeResult:
            async with semaphore:
                return await self.tls_probe.probe(target)

        results = await asyncio.gather(
            *(_probe_with_limit(target) for target in targets),
            return_exceptions=True,
        )

        tls_results: list[TLSProbeResult] = []
        for target, result in zip(targets, results, strict=True):
            if isinstance(result, Exception):
                continue
            if not result.cipher_suite or not result.tls_version:
                continue
            tls_results.append(result)

        if tls_results:
            self._add_runtime_event(
                scan_id,
                (
                    "TLS fallback recovered "
                    f"{len(tls_results)} successful handshake result(s) after empty port-scan output."
                ),
                kind="success",
                stage="probing_tls",
            )

        return tls_results

    @staticmethod
    def _build_ip_hostname_index(
        scope: AuthorizedScope,
        validated_hostnames: Sequence[ValidatedHostname],
    ) -> dict[str, set[str]]:
        ip_to_hostnames: dict[str, set[str]] = {}
        for validated in validated_hostnames:
            hostname = validated.hostname.strip().lower().rstrip(".")
            if not scope.contains(hostname=hostname):
                continue
            for ip_address in validated.ip_addresses:
                if scope.scope_type in {"ip", "network"} and not scope.contains(
                    ip_address=ip_address
                ):
                    continue
                ip_to_hostnames.setdefault(ip_address, set()).add(hostname)
        return ip_to_hostnames

    async def _persist_discovered_assets(
        self,
        *,
        scan_id: uuid.UUID,
        aggregated_assets: Sequence[AggregatedAsset],
        port_findings: Sequence[PortFinding] = (),
        validated_hostnames: Sequence[ValidatedHostname] = (),
    ) -> list[DiscoveredAsset]:
        self._set_runtime_stage(
            scan_id,
            stage="persisting_assets",
            detail=f"{len(aggregated_assets)} asset(s)",
            message="Persisting discovered assets and service identities.",
        )
        async with self.session_factory() as session:
            repository = DiscoveredAssetRepository(session)
            persisted_assets: list[DiscoveredAsset] = []
            for asset in aggregated_assets:
                normalized_asset_hostname = (
                    asset.hostname.strip().lower().rstrip(".") if asset.hostname else None
                )
                open_ports = [
                    {
                        "port": port_finding.port,
                        "protocol": port_finding.protocol,
                        "service_name": port_finding.service_name,
                        "state": port_finding.state,
                    }
                    for port_finding in port_findings
                    if port_finding.ip_address == asset.ip_address
                ]
                persisted_assets.append(
                    await repository.create(
                        scan_id=scan_id,
                        hostname=asset.hostname,
                        ip_address=asset.ip_address,
                        port=asset.port,
                        protocol=asset.protocol,
                        service_type=asset.service_type,
                        server_software=asset.server_software,
                        open_ports=open_ports,
                        asset_metadata=await self._build_asset_metadata(asset),
                        discovery_source=(
                            "dnsx"
                            if normalized_asset_hostname is not None
                            and any(
                                validated_hostname.hostname.strip().lower().rstrip(".")
                                == normalized_asset_hostname
                                for validated_hostname in validated_hostnames
                            )
                            else "nmap"
                        ),
                        is_shadow_it=False,
                    )
                )
            await session.commit()
            return persisted_assets

    async def _build_asset_metadata(self, asset: AggregatedAsset) -> dict[str, Any] | None:
        metadata = dict(asset.metadata) if asset.metadata else {}
        metadata["service_type"] = asset.service_type.value

        network_enrichment = await self._enrich_ip(asset.ip_address)
        if network_enrichment:
            metadata["network_enrichment"] = network_enrichment

        if asset.hostname:
            domain_enrichment = await self._enrich_domain(asset.hostname)
            if domain_enrichment:
                metadata["domain_enrichment"] = domain_enrichment

        return metadata or None

    async def _enrich_ip(self, ip_address: str) -> dict[str, Any]:
        normalized = ip_address.strip()
        if normalized in self._ip_enrichment_cache:
            return self._ip_enrichment_cache[normalized]

        enrichment: dict[str, Any] = {}
        try:
            parsed_ip = ipaddress.ip_address(normalized)
            if isinstance(parsed_ip, ipaddress.IPv4Address):
                enrichment["subnet"] = str(ipaddress.ip_network(f"{normalized}/24", strict=False))
            else:
                enrichment["subnet"] = str(ipaddress.ip_network(f"{normalized}/64", strict=False))
        except ValueError:
            enrichment["subnet"] = None

        reverse_dns = await asyncio.to_thread(self._safe_reverse_dns, normalized)
        if reverse_dns:
            enrichment["reverse_dns"] = reverse_dns

        asn_payload = await asyncio.to_thread(self._lookup_asn_cymru, normalized)
        if asn_payload:
            enrichment.update(asn_payload)

        if not enrichment.get("city") or not enrichment.get("country"):
            geo_payload = await asyncio.to_thread(self._lookup_ip_geolocation, normalized)
            if geo_payload:
                for key, value in geo_payload.items():
                    if value and not enrichment.get(key):
                        enrichment[key] = value

        self._ip_enrichment_cache[normalized] = enrichment
        return enrichment

    async def _enrich_domain(self, hostname: str) -> dict[str, Any]:
        normalized = hostname.strip().lower().rstrip(".")
        if normalized in self._domain_enrichment_cache:
            return self._domain_enrichment_cache[normalized]

        labels = normalized.split(".")
        root_domain = ".".join(labels[-2:]) if len(labels) >= 2 else normalized
        payload = {
            "hostname": normalized,
            "root_domain": root_domain,
            "registrar": None,
            "registration_date": None,
            "expiry_date": None,
            "nameservers": [],
        }
        rdap_enrichment = await asyncio.to_thread(self._lookup_domain_rdap, root_domain)
        if rdap_enrichment:
            payload.update(rdap_enrichment)
        self._domain_enrichment_cache[normalized] = payload
        return payload

    def _lookup_domain_rdap(self, domain: str) -> dict[str, Any] | None:
        endpoints = (
            f"https://rdap.org/domain/{domain}",
            f"https://rdap-bootstrap.arin.net/bootstrap/domain/{domain}",
        )
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "Aegis-RDAP/1.0",
        }

        for url in endpoints:
            try:
                request = Request(url, headers=headers)
                with urlopen(request, timeout=3.5) as response:
                    if response.status >= 400:
                        continue
                    body = response.read().decode("utf-8", errors="ignore")
                rdap = json.loads(body)
            except (TimeoutError, URLError, HTTPError, json.JSONDecodeError):
                continue
            except Exception:
                continue

            parsed = self._parse_rdap_payload(rdap)
            if parsed:
                return parsed

        return None

    def _parse_rdap_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        registration_date: str | None = None
        expiry_date: str | None = None
        registrar: str | None = None
        nameservers: list[str] = []

        for event in payload.get("events", []):
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).strip().lower()
            event_date = self._normalize_rdap_date(event.get("eventDate"))
            if event_date is None:
                continue
            if registration_date is None and action in {"registration", "created"}:
                registration_date = event_date
            if expiry_date is None and action in {"expiration", "expiry", "expired"}:
                expiry_date = event_date

        entities = payload.get("entities", [])
        if isinstance(entities, list):
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                roles = entity.get("roles", [])
                if not isinstance(roles, list):
                    continue
                normalized_roles = {str(role).strip().lower() for role in roles}
                if "registrar" in normalized_roles:
                    registrar = self._extract_rdap_entity_name(entity)
                    if registrar:
                        break

        raw_nameservers = payload.get("nameservers", [])
        if isinstance(raw_nameservers, list):
            for entry in raw_nameservers:
                if not isinstance(entry, dict):
                    continue
                candidate = entry.get("ldhName") or entry.get("unicodeName")
                if isinstance(candidate, str) and candidate.strip():
                    nameservers.append(candidate.strip().lower())

        if not registration_date and not expiry_date and not registrar and not nameservers:
            return {}

        return {
            "registrar": registrar,
            "registration_date": registration_date,
            "expiry_date": expiry_date,
            "nameservers": sorted(set(nameservers)),
        }

    @staticmethod
    def _extract_rdap_entity_name(entity: dict[str, Any]) -> str | None:
        vcard_array = entity.get("vcardArray")
        if (
            not isinstance(vcard_array, list)
            or len(vcard_array) != 2
            or not isinstance(vcard_array[1], list)
        ):
            return None

        for vcard_field in vcard_array[1]:
            if (
                not isinstance(vcard_field, list)
                or len(vcard_field) < 4
                or str(vcard_field[0]).strip().lower() != "fn"
            ):
                continue
            value = vcard_field[3]
            if isinstance(value, str) and value.strip():
                return value.strip()

        return None

    @staticmethod
    def _normalize_rdap_date(value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None

        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(normalized).date().isoformat()
        except ValueError:
            return None

    @staticmethod
    def _safe_reverse_dns(ip_address: str) -> str | None:
        try:
            host, _, _ = socket.gethostbyaddr(ip_address)
            return host.rstrip(".").lower()
        except Exception:
            return None

    @staticmethod
    def _lookup_asn_cymru(ip_address: str) -> dict[str, Any] | None:
        query = f"begin\nverbose\n{ip_address}\nend\n".encode("utf-8")
        try:
            with socket.create_connection(("whois.cymru.com", 43), timeout=2.5) as sock:
                sock.sendall(query)
                response = sock.recv(8192).decode("utf-8", errors="ignore")
        except Exception:
            return None

        lines = [line.strip() for line in response.splitlines() if line.strip()]
        if len(lines) < 2:
            return None

        # Expected pipe-separated format:
        # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
        parts = [part.strip() for part in lines[-1].split("|")]
        if len(parts) < 7:
            return None

        asn = parts[0] if parts[0] and parts[0].isdigit() else None
        as_name = parts[6] or None
        return {
            "asn": f"AS{asn}" if asn else None,
            "netname": as_name,
            "isp": as_name,
            "city": None,
            "country": None,
        }

    @staticmethod
    def _lookup_ip_geolocation(ip_address: str) -> dict[str, Any] | None:
        endpoint = f"https://ipapi.co/{ip_address}/json/"
        request = Request(
            endpoint,
            headers={
                "Accept": "application/json",
                "User-Agent": "Aegis-IP-Enrichment/1.0",
            },
        )
        try:
            with urlopen(request, timeout=2.5) as response:
                if response.status >= 400:
                    return None
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        except (TimeoutError, URLError, HTTPError, json.JSONDecodeError):
            return None
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None

        return {
            "city": payload.get("city") or None,
            "country": payload.get("country_name") or None,
            "asn": payload.get("asn") or None,
            "isp": payload.get("org") or None,
        }

    async def _process_tls_asset(
        self,
        *,
        asset_id: uuid.UUID,
        tls_result: TLSProbeResult,
        scan_id: uuid.UUID | None = None,
    ) -> None:
        async with self.session_factory() as session:
            asset_repository = DiscoveredAssetRepository(session)
            certificate_repository = CertificateChainRepository(session)
            assessment_repository = CryptoAssessmentRepository(session)
            cbom_repository = CbomDocumentRepository(session)
            remediation_repository = RemediationBundleRepository(session)
            certificate_store = ComplianceCertificateRepository(session)
            fingerprint_repo = AssetFingerprintRepository(session)

            asset = await asset_repository.get_by_id(asset_id)
            if asset is None:
                raise ScanNotFoundError(f"Asset {asset_id} does not exist.")
            asset_label = f"{asset.hostname or asset.ip_address}:{asset.port}"
            self._set_runtime_stage(
                scan_id,
                stage="assessing_tls_assets",
                detail=asset_label,
                message=f"Analyzing TLS posture for {asset_label}.",
            )

            tls_result = await self._ensure_certificate_chain(
                asset_label=asset_label,
                tls_result=tls_result,
                scan_id=scan_id,
            )
            extracted_certificates = self.certificate_extractor.extract(tls_result)
            analyzed_certificates = self.certificate_analyzer.analyze(extracted_certificates)
            persisted_certificates = []

            for extracted, analyzed in zip(
                extracted_certificates, analyzed_certificates, strict=True
            ):
                persisted_certificates.append(
                    await certificate_repository.create(
                        asset_id=asset.id,
                        cert_level=extracted.cert_level,
                        subject=extracted.subject,
                        issuer=extracted.issuer,
                        public_key_algorithm=extracted.public_key_algorithm,
                        key_size_bits=extracted.key_size_bits,
                        signature_algorithm=extracted.signature_algorithm,
                        quantum_safe=analyzed.quantum_safe,
                        not_before=extracted.not_before,
                        not_after=extracted.not_after,
                    )
                )

            assessment_inputs = self._build_assessment_inputs(
                tls_result=tls_result,
                extracted_certificates=extracted_certificates,
                analyzed_certificates=analyzed_certificates,
            )
            evaluation = self.rules_engine.evaluate(
                ComplianceInput(
                    kex_algorithm=assessment_inputs.kex_algorithm,
                    auth_algorithm=assessment_inputs.auth_algorithm,
                    enc_algorithm=assessment_inputs.enc_algorithm,
                    risk_score=assessment_inputs.risk_score,
                )
            )
            self._add_runtime_event(
                scan_id,
                f"{asset_label} classified as {evaluation.tier.value}.",
                kind="success",
                stage="assessing_tls_assets",
            )
            assessment = await assessment_repository.create(
                asset_id=asset.id,
                tls_version=assessment_inputs.tls_version,
                cipher_suite=assessment_inputs.cipher_suite,
                kex_algorithm=assessment_inputs.kex_algorithm,
                auth_algorithm=assessment_inputs.auth_algorithm,
                enc_algorithm=assessment_inputs.enc_algorithm,
                mac_algorithm=assessment_inputs.mac_algorithm,
                kex_vulnerability=assessment_inputs.kex_vulnerability,
                sig_vulnerability=assessment_inputs.sig_vulnerability,
                sym_vulnerability=assessment_inputs.sym_vulnerability,
                tls_vulnerability=assessment_inputs.tls_vulnerability,
                risk_score=assessment_inputs.risk_score,
                score_explanation=assessment_inputs.score_explanation,
            )
            try:
                async with session.begin_nested():
                    canonical_key = build_asset_fingerprint_key(asset)
                    if canonical_key is None:
                        raise ValueError(
                            f"Cannot derive canonical fingerprint key for asset {asset.id}."
                        )
                    q_score = round(100 - (assessment_inputs.risk_score or 50))
                    now = datetime.now(UTC)
                    score_snapshot = {
                        "scan_id": str(scan_id),
                        "q_score": q_score,
                        "scanned_at": now.isoformat(),
                    }
                    existing = await fingerprint_repo.get_by_canonical_key(canonical_key)
                    if existing:
                        new_history = list(existing.q_score_history or []) + [score_snapshot]
                        await fingerprint_repo.update(
                            existing.id,
                            last_seen_scan_id=scan_id,
                            last_seen_at=now,
                            appearance_count=existing.appearance_count + 1,
                            q_score_history=new_history,
                            latest_q_score=q_score,
                            latest_compliance_tier=evaluation.tier,
                        )
                    else:
                        try:
                            await fingerprint_repo.create(
                                canonical_key=canonical_key,
                                first_seen_scan_id=scan_id,
                                last_seen_scan_id=scan_id,
                                first_seen_at=now,
                                last_seen_at=now,
                                appearance_count=1,
                                q_score_history=[score_snapshot],
                                latest_q_score=q_score,
                                latest_compliance_tier=evaluation.tier,
                            )
                        except IntegrityError:
                            # Concurrent asset workers may race on first insert for the same canonical key.
                            # Ignore duplicate insert in this transaction; canonical record already exists.
                            pass
            except Exception:
                logger.exception(
                    "Failed to persist asset fingerprint for asset %s.",
                    asset.id,
                )

            cbom_document = await self.cbom_mapper.persist_cbom(
                bundle=AssetCbomBundle(
                    asset=asset,
                    assessment=assessment,
                    certificates=persisted_certificates,
                    compliance=evaluation,
                ),
                cbom_repository=cbom_repository,
            )

            remediation_bundle = None
            if evaluation.tier is not ComplianceTier.FULLY_QUANTUM_SAFE:
                self._set_runtime_stage(
                    scan_id,
                    stage="generating_remediation",
                    detail=asset_label,
                    message=f"Generating remediation guidance for {asset_label}.",
                )
                try:
                    remediation_bundle = await self.rag_orchestrator.generate_and_persist(
                        remediation_input=RemediationInput(
                            asset=asset,
                            assessment=assessment,
                            cbom_document=cbom_document,
                            compliance_tier=evaluation.tier,
                        ),
                        remediation_repository=remediation_repository,
                        certificates=persisted_certificates,
                    )
                    if remediation_bundle is not None:
                        remediation_actions: list[dict[str, Any]] = []
                        if (
                            assessment_inputs.kex_vulnerability is not None
                            and assessment_inputs.kex_vulnerability >= 1.0
                        ):
                            remediation_actions.append(
                                {
                                    "priority": RemediationPriority.P1,
                                    "finding": (
                                        "Quantum-vulnerable key exchange: "
                                        f"{assessment_inputs.kex_algorithm}"
                                    ),
                                    "action": "Replace with X25519MLKEM768 hybrid or pure ML-KEM-768",
                                    "effort": RemediationEffort.HIGH,
                                    "category": "key_exchange",
                                }
                            )
                        if (
                            assessment_inputs.sig_vulnerability is not None
                            and assessment_inputs.sig_vulnerability >= 1.0
                        ):
                            remediation_actions.append(
                                {
                                    "priority": RemediationPriority.P1,
                                    "finding": (
                                        "Quantum-vulnerable signature algorithm: "
                                        f"{assessment_inputs.auth_algorithm}"
                                    ),
                                    "action": "Migrate certificate to ML-DSA-65",
                                    "effort": RemediationEffort.HIGH,
                                    "category": "certificate",
                                }
                            )
                        if (
                            assessment_inputs.tls_vulnerability is not None
                            and assessment_inputs.tls_vulnerability >= 0.4
                            and assessment_inputs.tls_version is not None
                            and "1.3" not in assessment_inputs.tls_version
                        ):
                            remediation_actions.append(
                                {
                                    "priority": RemediationPriority.P2,
                                    "finding": f"Legacy TLS version: {assessment_inputs.tls_version}",
                                    "action": "Enforce TLS 1.3 only",
                                    "effort": RemediationEffort.LOW,
                                    "category": "tls_version",
                                }
                            )
                        if (
                            assessment_inputs.sym_vulnerability is not None
                            and assessment_inputs.sym_vulnerability >= 0.5
                        ):
                            remediation_actions.append(
                                {
                                    "priority": RemediationPriority.P3,
                                    "finding": "Symmetric cipher has reduced post-quantum security",
                                    "action": "Prefer AES-256-GCM or ChaCha20-Poly1305",
                                    "effort": RemediationEffort.LOW,
                                    "category": "cipher_strength",
                                }
                            )
                        for remediation_action in remediation_actions:
                            try:
                                async with session.begin_nested():
                                    session.add(
                                        RemediationAction(
                                            asset_id=asset.id,
                                            remediation_bundle_id=remediation_bundle.id,
                                            priority=remediation_action["priority"].value,
                                            finding=remediation_action["finding"],
                                            action=remediation_action["action"],
                                            effort=remediation_action["effort"].value,
                                            status=RemediationStatus.NOT_STARTED.value,
                                            category=remediation_action["category"],
                                        )
                                    )
                                    await session.flush()
                            except Exception:
                                logger.exception(
                                    "Failed to persist remediation action for asset %s.",
                                    asset.id,
                                )
                        self._add_runtime_event(
                            scan_id,
                            f"Generated remediation artifacts for {asset_label}.",
                            kind="success",
                            stage="generating_remediation",
                        )
                        # Enrich CBOM with HNDL info
                        hndl = remediation_bundle.hndl_timeline
                        if hndl:
                            urgency = hndl.get("urgency")
                            entries = hndl.get("entries", [])
                            break_year = min((e["breakYear"] for e in entries), default=None)

                            updated_json = dict(cbom_document.cbom_json)
                            updated_json["quantumRiskSummary"]["hndlUrgency"] = urgency
                            updated_json["quantumRiskSummary"]["estimatedBreakYear"] = break_year

                            await cbom_repository.update(cbom_document.id, cbom_json=updated_json)
                except Exception:
                    logger.exception(
                        "Remediation generation failed for asset %s (%s:%s).",
                        asset.id,
                        asset.hostname or asset.ip_address,
                        asset.port,
                    )
                    self._add_runtime_event(
                        scan_id,
                        f"Remediation generation failed for {asset_label}; certificate issuance will continue if possible.",
                        kind="error",
                        stage="generating_remediation",
                    )
            else:
                self._add_runtime_event(
                    scan_id,
                    f"{asset_label} is fully quantum safe; remediation was skipped.",
                    kind="info",
                    stage="assessing_tls_assets",
                )

            await session.commit()

            self._set_runtime_stage(
                scan_id,
                stage="issuing_certificates",
                detail=asset_label,
                message=f"Issuing compliance certificate for {asset_label}.",
            )
            certificate_record = await self.certificate_signer.issue_and_persist(
                certificate_request=CertificateRequest(
                    asset=asset,
                    assessment=assessment,
                    remediation_bundle=remediation_bundle,
                ),
                compliance_certificate_repository=certificate_store,
            )
            if certificate_record.signing_algorithm != "ML-DSA-65":
                self._add_degraded_mode(
                    scan_id,
                    f"{asset_label} used {certificate_record.signing_algorithm} certificate signing fallback.",
                )
            self._add_runtime_event(
                scan_id,
                f"Issued {certificate_record.signing_algorithm} compliance certificate for {asset_label}.",
                kind="success",
                stage="issuing_certificates",
            )

            await session.commit()

    async def _ensure_certificate_chain(
        self,
        *,
        asset_label: str,
        tls_result: TLSProbeResult,
        scan_id: uuid.UUID | None = None,
    ) -> TLSProbeResult:
        """Recover a PEM certificate chain when the initial probe returned none."""
        if tls_result.certificate_chain_pem:
            return tls_result

        recovered_chain = await self._recover_certificate_chain_with_showcerts(tls_result)
        if not recovered_chain:
            self._add_degraded_mode(
                scan_id,
                f"No certificate chain could be recovered for {asset_label}; certificate-chain persistence was skipped.",
            )
            return tls_result

        self._add_runtime_event(
            scan_id,
            f"Recovered {len(recovered_chain)} certificate(s) for {asset_label} using showcerts fallback.",
            kind="success",
            stage="assessing_tls_assets",
        )
        return TLSProbeResult(
            hostname=tls_result.hostname,
            ip_address=tls_result.ip_address,
            port=tls_result.port,
            protocol=tls_result.protocol,
            tls_version=tls_result.tls_version,
            cipher_suite=tls_result.cipher_suite,
            certificate_chain_pem=recovered_chain,
            server_software=tls_result.server_software,
            metadata=dict(tls_result.metadata),
        )

    async def _recover_certificate_chain_with_showcerts(
        self,
        tls_result: TLSProbeResult,
    ) -> tuple[str, ...]:
        """Use openssl s_client -showcerts as a fallback chain source."""
        command = [
            "/usr/local/bin/openssl-oqs",
            "s_client",
            "-connect",
            f"{tls_result.ip_address}:{tls_result.port}",
            "-showcerts",
        ]
        if tls_result.hostname:
            command.extend(["-servername", tls_result.hostname])

        env = os.environ.copy()
        env["OPENSSL_CONF"] = "/opt/openssl/ssl/openssl.cnf"

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=b"\n"),
                timeout=self.tls_probe.timeout_seconds,
            )
        except Exception:
            logger.exception(
                "Certificate-chain fallback probe failed for %s:%s.",
                tls_result.hostname or tls_result.ip_address,
                tls_result.port,
            )
            return ()

        output = b"".join((stdout or b"", stderr or b"")).decode("utf-8", errors="ignore")
        pem_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            output,
            flags=re.DOTALL,
        )
        return tuple(f"{block.strip()}\n" for block in pem_blocks)

    def _build_assessment_inputs(
        self,
        *,
        tls_result: TLSProbeResult,
        extracted_certificates: Sequence[Any],
        analyzed_certificates: Sequence[Any],
    ) -> _AssessmentInputs:
        if not tls_result.cipher_suite:
            # HANDSHAKE FAILURE CASE: Return max risk 100.0
            risk = calculate_risk_score(
                kex_vulnerability=1.0,
                sig_vulnerability=1.0,
                sym_vulnerability=1.0,
                tls_vulnerability=1.0,
            )
            score_explanation = generate_score_explanation(
                kex_vulnerability=1.0,
                sig_vulnerability=1.0,
                sym_vulnerability=1.0,
                tls_vulnerability=1.0,
                kex_algorithm="UNKNOWN",
                auth_algorithm="UNKNOWN",
                enc_algorithm="UNKNOWN",
                tls_version="Handshake Failed",
                risk_score=100.0,
                base_risk_score=100.0,
                certificate_penalty=0.0,
            )
            return _AssessmentInputs(
                tls_version="Handshake Failed",
                cipher_suite="BROKEN",
                kex_algorithm="UNKNOWN",
                auth_algorithm="UNKNOWN",
                enc_algorithm="UNKNOWN",
                mac_algorithm="UNKNOWN",
                kex_vulnerability=1.0,
                sig_vulnerability=1.0,
                sym_vulnerability=1.0,
                tls_vulnerability=1.0,
                risk_score=100.0,
                score_explanation=score_explanation,
            )

        tls_version = tls_result.tls_version
        if tls_version and "1.3" in tls_version:
            return self._build_tls13_assessment_inputs(
                tls_result=tls_result,
                extracted_certificates=extracted_certificates,
                analyzed_certificates=analyzed_certificates,
            )

        parsed = parse_tls12_cipher_suite(tls_result.cipher_suite)
        metadata = dict(tls_result.metadata)
        metadata_kex = self._first_non_unknown(
            metadata.get("kex_algorithm"),
            metadata.get("negotiated_group"),
            metadata.get("group_name"),
            metadata.get("key_exchange"),
            metadata.get("curve_name"),
        )
        resolved_kex_algorithm = parsed.kex_algorithm
        if self._is_unknown_token(resolved_kex_algorithm) and metadata_kex is not None:
            resolved_kex_algorithm = canonicalize_algorithm("kex", str(metadata_kex))

        leaf_days_remaining = self._extract_leaf_certificate_days_remaining(extracted_certificates)
        risk = calculate_risk_score(
            kex_vulnerability=self._safe_lookup_vulnerability("kex", resolved_kex_algorithm),
            sig_vulnerability=parsed.sig_vulnerability,
            sym_vulnerability=parsed.sym_vulnerability,
            tls_version=tls_result.tls_version,
            certificate_days_remaining=leaf_days_remaining,
        )
        score_explanation = generate_score_explanation(
            kex_vulnerability=risk.kex_vulnerability,
            sig_vulnerability=parsed.sig_vulnerability,
            sym_vulnerability=parsed.sym_vulnerability,
            tls_vulnerability=risk.tls_vulnerability,
            kex_algorithm=resolved_kex_algorithm,
            auth_algorithm=parsed.auth_algorithm,
            enc_algorithm=parsed.enc_algorithm,
            tls_version=tls_result.tls_version,
            risk_score=risk.score,
            base_risk_score=risk.base_score,
            certificate_penalty=risk.certificate_penalty,
        )
        return _AssessmentInputs(
            tls_version=tls_result.tls_version,
            cipher_suite=tls_result.cipher_suite,
            kex_algorithm=resolved_kex_algorithm,
            auth_algorithm=parsed.auth_algorithm,
            enc_algorithm=parsed.enc_algorithm,
            mac_algorithm=parsed.mac_algorithm,
            kex_vulnerability=risk.kex_vulnerability,
            sig_vulnerability=parsed.sig_vulnerability,
            sym_vulnerability=parsed.sym_vulnerability,
            tls_vulnerability=risk.tls_vulnerability,
            risk_score=risk.score,
            score_explanation=score_explanation,
        )

    def _build_tls13_assessment_inputs(
        self,
        *,
        tls_result: TLSProbeResult,
        extracted_certificates: Sequence[Any],
        analyzed_certificates: Sequence[Any],
    ) -> _AssessmentInputs:
        leaf_certificate = next(
            (
                certificate
                for certificate in analyzed_certificates
                if certificate.cert_level is CertLevel.LEAF
            ),
            analyzed_certificates[0] if analyzed_certificates else None,
        )
        metadata = dict(tls_result.metadata)
        metadata.setdefault("tls_version", tls_result.tls_version)
        if leaf_certificate is not None:
            metadata.setdefault(
                "certificate",
                {
                    "public_key_algorithm": leaf_certificate.public_key_algorithm,
                    "signature_algorithm": leaf_certificate.signature_algorithm,
                },
            )

        try:
            resolved = resolve_tls13_handshake_metadata(metadata)
            kex_algorithm = resolved.kex_algorithm
            auth_algorithm = resolved.auth_algorithm
            if self._is_unknown_token(kex_algorithm) or self._is_unknown_token(auth_algorithm):
                raise HandshakeMetadataResolutionError(
                    "Resolved TLS 1.3 metadata contains unusable UNKNOWN values."
                )
        except HandshakeMetadataResolutionError:
            auth_algorithm = canonicalize_algorithm(
                "sig",
                getattr(leaf_certificate, "public_key_algorithm", None)
                or getattr(leaf_certificate, "signature_algorithm", None),
            )
            group_name = self._first_non_unknown(
                metadata.get("kex_algorithm"),
                metadata.get("negotiated_group"),
                metadata.get("group_name"),
                metadata.get("key_exchange"),
                metadata.get("curve_name"),
                "X25519",
            )
            kex_algorithm = canonicalize_algorithm("kex", str(group_name))

        enc_algorithm, mac_algorithm = self._parse_tls13_cipher_suite(tls_result.cipher_suite or "")
        kex_vulnerability = self._safe_lookup_vulnerability("kex", kex_algorithm)
        sig_vulnerability = self._safe_lookup_vulnerability("sig", auth_algorithm)
        sym_vulnerability = self._safe_lookup_vulnerability("sym", enc_algorithm)
        leaf_days_remaining = self._extract_leaf_certificate_days_remaining(extracted_certificates)
        risk = calculate_risk_score(
            kex_vulnerability=kex_vulnerability,
            sig_vulnerability=sig_vulnerability,
            sym_vulnerability=sym_vulnerability,
            tls_version=tls_result.tls_version,
            certificate_days_remaining=leaf_days_remaining,
        )
        score_explanation = generate_score_explanation(
            kex_vulnerability=kex_vulnerability,
            sig_vulnerability=sig_vulnerability,
            sym_vulnerability=sym_vulnerability,
            tls_vulnerability=risk.tls_vulnerability,
            kex_algorithm=kex_algorithm,
            auth_algorithm=auth_algorithm,
            enc_algorithm=enc_algorithm,
            tls_version=tls_result.tls_version,
            risk_score=risk.score,
            base_risk_score=risk.base_score,
            certificate_penalty=risk.certificate_penalty,
        )
        return _AssessmentInputs(
            tls_version=tls_result.tls_version,
            cipher_suite=tls_result.cipher_suite,
            kex_algorithm=kex_algorithm,
            auth_algorithm=auth_algorithm,
            enc_algorithm=enc_algorithm,
            mac_algorithm=mac_algorithm,
            kex_vulnerability=kex_vulnerability,
            sig_vulnerability=sig_vulnerability,
            sym_vulnerability=sym_vulnerability,
            tls_vulnerability=risk.tls_vulnerability,
            risk_score=risk.score,
            score_explanation=score_explanation,
        )

    @staticmethod
    def _parse_tls13_cipher_suite(cipher_suite: str) -> tuple[str | None, str | None]:
        normalized = cipher_suite.strip().upper()
        if not normalized.startswith("TLS_"):
            return None, None
        tokens = [token for token in normalized[4:].split("_") if token]
        if len(tokens) < 2:
            return None, None
        return "_".join(tokens[:-1]), tokens[-1]

    @staticmethod
    def _safe_lookup_vulnerability(category: str, algorithm: str | None) -> float:
        if algorithm is None:
            return 1.0
        try:
            return lookup_vulnerability(category, algorithm)
        except KeyError:
            return 1.0

    @staticmethod
    def _extract_leaf_certificate_days_remaining(
        extracted_certificates: Sequence[Any],
    ) -> int | None:
        if not extracted_certificates:
            return None

        leaf = next(
            (
                cert
                for cert in extracted_certificates
                if getattr(cert, "cert_level", None) is CertLevel.LEAF
            ),
            extracted_certificates[0],
        )
        not_after = getattr(leaf, "not_after", None)
        if not_after is None:
            return None

        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=UTC)

        delta = not_after - datetime.now(UTC)
        return int(delta.total_seconds() // 86400)

    @staticmethod
    def _is_unknown_token(value: str | None) -> bool:
        if value is None:
            return True
        normalized = str(value).strip().upper()
        return normalized in {"", "UNKNOWN", "N/A", "NONE", "NULL"}

    @classmethod
    def _first_non_unknown(cls, *candidates: object) -> str | None:
        for candidate in candidates:
            if candidate is None:
                continue
            as_text = str(candidate).strip()
            if cls._is_unknown_token(as_text):
                continue
            return as_text
        return None


