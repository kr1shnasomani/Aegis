"""
ScanReadService — read-only query helpers for scan status and compiled results.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.core.database import async_session_factory
from backend.models.crypto_assessment import CryptoAssessment
from backend.models.discovered_asset import DiscoveredAsset
from backend.models.certificate_chain import CertificateChain
from backend.models.dns_record import DNSRecord
from backend.models.enums import ScanStatus, ServiceType, ComplianceTier, CertLevel
from backend.models.scan_job import ScanJob
from backend.models.scan_event import ScanEvent
from backend.models.remediation_action import RemediationAction
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
from .exceptions import ScanNotFoundError
from .models import ScanRuntimeStore, ETA_STAGE_WEIGHTS_SECONDS, ETA_STAGE_ORDER
from .serializers import (
    select_latest,
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
    _normalize_hostname,
    extract_subject_cn,
    build_asset_fingerprint_key,
)

class ScanReadService:
    """Read-side helpers for scan status, compiled results, and artifact retrieval."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        runtime_store: ScanRuntimeStore | None = None,
    ) -> None:
        self.session_factory = session_factory or async_session_factory
        self.runtime_store = runtime_store

    async def get_scan_status(self, *, scan_id: uuid.UUID) -> dict[str, Any]:
        bundle = await self._load_scan_bundle(scan_id=scan_id)
        payload = {
            "scan_id": bundle["scan"].id,
            "target": bundle["scan"].target,
            "status": bundle["scan"].status,
            "created_at": bundle["scan"].created_at,
            "completed_at": bundle["scan"].completed_at,
            "progress": bundle["progress"],
            "summary": bundle["summary"],
        }
        payload.update(self._build_runtime_payload(bundle))
        return payload

    async def get_scan_results(self, *, scan_id: uuid.UUID) -> dict[str, Any]:
        bundle = await self._load_scan_bundle(scan_id=scan_id)
        assets_payload = []
        for asset in bundle["assets"]:
            assets_payload.append(
                {
                    "asset_id": asset.id,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "port": asset.port,
                    "protocol": asset.protocol,
                    "service_type": asset.service_type,
                    "server_software": asset.server_software,
                    "open_ports": asset.open_ports,
                    "asset_metadata": asset.asset_metadata,
                    "is_shadow_it": asset.is_shadow_it,
                    "discovery_source": asset.discovery_source,
                    "assessment": serialize_assessment(bundle["assessments"].get(asset.id)),
                    "cbom": serialize_cbom(bundle["cboms"].get(asset.id)),
                    "remediation": serialize_remediation(bundle["remediations"].get(asset.id)),
                    "certificate": serialize_asset_certificate(
                        bundle["leaf_certificates"].get(asset.id)
                    ),
                    "compliance_certificate": serialize_certificate(
                        bundle["certificates"].get(asset.id),
                        include_pem=False,
                    ),
                    "leaf_certificate": serialize_leaf_certificate(
                        bundle["leaf_certificates"].get(asset.id)
                    ),
                    "remediation_actions": [
                        serialize_remediation_action(action)
                        for action in bundle["remediation_actions"].get(asset.id, [])
                    ],
                    "asset_fingerprint": serialize_asset_fingerprint(
                        bundle["asset_fingerprints"].get(asset.id)
                    ),
                }
            )

        payload = {
            "scan_id": bundle["scan"].id,
            "target": bundle["scan"].target,
            "status": bundle["scan"].status,
            "created_at": bundle["scan"].created_at,
            "completed_at": bundle["scan"].completed_at,
            "progress": bundle["progress"],
            "summary": bundle["summary"],
            "dns_records": [serialize_dns_record(record) for record in bundle["dns_records"]],
            "assets": assets_payload,
        }
        payload.update(self._build_runtime_payload(bundle))
        return payload

    async def get_mission_control_overview(
        self,
        *,
        recent_limit: int = 10,
        priority_limit: int = 5,
    ) -> dict[str, Any]:
        async with self.session_factory() as session:
            scan_repository = ScanJobRepository(session)
            scans = list(await scan_repository.get_recent(limit=recent_limit))

        bundles = [await self._load_scan_bundle(scan_id=scan.id) for scan in scans]
        recent_scans = [self._serialize_recent_scan(bundle) for bundle in bundles]
        priority_findings = self._build_priority_findings(
            bundles=bundles,
            priority_limit=priority_limit,
        )

        completed_scans = sum(
            1 for bundle in bundles if bundle["scan"].status is ScanStatus.COMPLETED
        )
        running_scans = sum(
            1
            for bundle in bundles
            if bundle["scan"].status in {ScanStatus.PENDING, ScanStatus.RUNNING}
        )
        failed_scans = sum(1 for bundle in bundles if bundle["scan"].status is ScanStatus.FAILED)
        degraded_counts = [len(bundle["runtime"]["degraded_modes"]) for bundle in bundles]

        return {
            "portfolio_summary": {
                "completed_scans": completed_scans,
                "running_scans": running_scans,
                "failed_scans": failed_scans,
                "vulnerable_assets": sum(
                    bundle["summary"]["vulnerable_assets"] for bundle in bundles
                ),
                "transitioning_assets": sum(
                    bundle["summary"]["transitioning_assets"] for bundle in bundles
                ),
                "compliant_assets": sum(
                    bundle["summary"]["fully_quantum_safe_assets"] for bundle in bundles
                ),
                "certificates_issued": sum(
                    bundle["progress"]["certificates_created"] for bundle in bundles
                ),
                "remediation_bundles_generated": sum(
                    bundle["progress"]["remediations_created"] for bundle in bundles
                ),
                "degraded_scan_count": sum(1 for count in degraded_counts if count > 0),
            },
            "recent_scans": recent_scans,
            "priority_findings": priority_findings,
            "system_health": {
                "backend_status": "reachable",
                "degraded_runtime_notice_count": sum(degraded_counts),
            },
        }

    async def get_scan_history(
        self,
        *,
        limit: int | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        async with self.session_factory() as session:
            scan_repository = ScanJobRepository(session)
            scans = list(await scan_repository.get_recent(limit=limit, target=target))

        bundles = [await self._load_scan_bundle(scan_id=scan.id) for scan in scans]
        return {
            "items": [self._serialize_recent_scan(bundle) for bundle in bundles],
        }

    async def get_recent_activity(
        self,
        *,
        limit: int = 25,
    ) -> dict[str, Any]:
        async with self.session_factory() as session:
            rows = (
                await session.execute(
                    select(ScanEvent, ScanJob)
                    .join(ScanJob, ScanEvent.scan_id == ScanJob.id)
                    .order_by(ScanEvent.timestamp.desc(), ScanEvent.id.desc())
                    .limit(limit)
                )
            ).all()

        items: list[dict[str, Any]] = []
        for event, scan in rows:
            message = event.message
            lowered = message.lower()
            route = None
            if "cbom" in lowered:
                route = "/dashboard/cbom"
            elif "certificate" in lowered:
                route = "/dashboard/discovery?tab=ssl"
            elif "remediation" in lowered or "vulnerable" in lowered:
                route = "/dashboard/remediation/action-plan"
            elif "discovered" in lowered or "dns" in lowered:
                route = "/dashboard/discovery"

            items.append(
                {
                    "timestamp": event.timestamp,
                    "kind": event.kind,
                    "message": message,
                    "stage": event.stage,
                    "scan_id": scan.id,
                    "target": scan.target,
                    "status": scan.status,
                    "route": route,
                }
            )

        return {"items": items}

    async def get_network_graph(
        self,
        *,
        scan_id: uuid.UUID | None = None,
        limit: int = 150,
    ) -> dict[str, list[Any]]:
        async with self.session_factory() as session:
            if scan_id is not None:
                scan_row = (
                    await session.execute(select(ScanJob).where(ScanJob.id == scan_id))
                ).scalar_one_or_none()
                if scan_row is None:
                    raise ScanNotFoundError(f"Scan {scan_id} does not exist.")
                selected_scan_id = scan_row.id
            else:
                selected_scan_id = (
                    await session.execute(
                        select(ScanJob.id)
                        .where(ScanJob.status == ScanStatus.COMPLETED)
                        .order_by(
                            ScanJob.completed_at.desc().nullslast(),
                            ScanJob.created_at.desc(),
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()

            if selected_scan_id is None:
                return {"nodes": [], "edges": []}

            assets = (
                (
                    await session.execute(
                        select(DiscoveredAsset)
                        .where(DiscoveredAsset.scan_id == selected_scan_id)
                        .order_by(DiscoveredAsset.hostname.asc(), DiscoveredAsset.port.asc())
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )
            if not assets:
                return {"nodes": [], "edges": []}

            asset_ids = [asset.id for asset in assets]
            assessments = (
                (
                    await session.execute(
                        select(CryptoAssessment).where(CryptoAssessment.asset_id.in_(asset_ids))
                    )
                )
                .scalars()
                .all()
            )
            assessments_by_asset_id = {
                assessment.asset_id: assessment for assessment in assessments
            }

        status_rank = {
            "critical": 4,
            "unknown": 3,
            "vulnerable": 2,
            "transitioning": 1,
            "elite-pqc": 0,
        }

        def combine_status(current: str | None, incoming: str) -> str:
            if current is None:
                return incoming
            return incoming if status_rank[incoming] > status_rank[current] else current

        def map_asset_status(assessment: CryptoAssessment | None) -> str:
            if assessment is None:
                return "unknown"
            if assessment.compliance_tier is ComplianceTier.FULLY_QUANTUM_SAFE:
                return "elite-pqc"
            if assessment.compliance_tier is ComplianceTier.PQC_TRANSITIONING:
                return "transitioning"
            risk_score = assessment.risk_score or 0.0
            if risk_score >= 70:
                return "critical"
            if risk_score >= 40:
                return "vulnerable"
            return "transitioning"

        domain_to_ips: dict[str, list[str]] = {}
        ip_to_ports: dict[str, list[tuple[str, str]]] = {}
        domain_statuses: dict[str, str] = {}
        ip_statuses: dict[str, str] = {}
        port_statuses: dict[str, str] = {}

        for asset in assets:
            domain = (asset.hostname or asset.ip_address or "unknown").strip().lower()
            ip = (asset.ip_address or domain).strip().lower()
            port = str(asset.port)
            port_id = f"{ip}:{port}"
            status = map_asset_status(assessments_by_asset_id.get(asset.id))

            domain_to_ips.setdefault(domain, [])
            if ip not in domain_to_ips[domain]:
                domain_to_ips[domain].append(ip)

            ip_to_ports.setdefault(ip, [])
            port_tuple = (port_id, port)
            if port_tuple not in ip_to_ports[ip]:
                ip_to_ports[ip].append(port_tuple)

            domain_statuses[domain] = combine_status(domain_statuses.get(domain), status)
            ip_statuses[ip] = combine_status(ip_statuses.get(ip), status)
            port_statuses[port_id] = combine_status(port_statuses.get(port_id), status)

        nodes: list[dict[str, Any]] = []
        edges: list[list[str]] = []
        seen_edges: set[tuple[str, str]] = set()

        domain_positions: dict[str, float] = {}
        ip_positions: dict[str, float] = {}
        port_positions: dict[str, tuple[float, str]] = {}

        sorted_domains = sorted(domain_to_ips.keys())
        domain_y_step = 320 / max(len(sorted_domains), 1)
        for domain_index, domain in enumerate(sorted_domains):
            domain_positions[domain] = 20 + domain_y_step * (domain_index + 0.5)

        sorted_ips = sorted(ip_to_ports.keys())
        ip_y_step = 320 / max(len(sorted_ips), 1)
        for ip_index, ip in enumerate(sorted_ips):
            ip_positions[ip] = 20 + ip_y_step * (ip_index + 0.5)

        for ip in sorted_ips:
            ip_y = ip_positions[ip]
            ports = sorted(ip_to_ports.get(ip, []), key=lambda item: int(item[1]))
            for port_index, (port_id, port_label) in enumerate(ports):
                if port_id not in port_positions:
                    port_y = max(16.0, min(344.0, ip_y - 12 + (port_index * 12)))
                    port_positions[port_id] = (port_y, port_label)

        for domain in sorted_domains:
            nodes.append(
                {
                    "id": domain,
                    "label": domain,
                    "status": domain_statuses.get(domain, "unknown"),
                    "x": 120,
                    "y": round(domain_positions[domain], 2),
                    "r": 18,
                }
            )

        for ip in sorted_ips:
            nodes.append(
                {
                    "id": ip,
                    "label": ip,
                    "status": ip_statuses.get(ip, "unknown"),
                    "x": 320,
                    "y": round(ip_positions[ip], 2),
                    "r": 14,
                }
            )

        for port_id, (port_y, port_label) in sorted(port_positions.items()):
            nodes.append(
                {
                    "id": port_id,
                    "label": port_label,
                    "status": port_statuses.get(port_id, "unknown"),
                    "x": 500,
                    "y": round(port_y, 2),
                    "r": 9,
                }
            )

        for domain in sorted_domains:
            for ip in sorted(domain_to_ips[domain]):
                edge = (domain, ip)
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    edges.append([domain, ip])

        for ip in sorted_ips:
            for port_id, _port_label in sorted(
                ip_to_ports.get(ip, []), key=lambda item: int(item[1])
            ):
                edge = (ip, port_id)
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    edges.append([ip, port_id])

        return {"nodes": nodes, "edges": edges}

    async def get_latest_cbom(self, *, asset_id: uuid.UUID) -> dict[str, Any]:
        async with self.session_factory() as session:
            repository = CbomDocumentRepository(session)
            cbom = select_latest_cbom(await repository.get_by_asset_id(asset_id))
            if cbom is None:
                raise ScanNotFoundError(f"No CBOM found for asset {asset_id}.")
            return serialize_cbom(cbom)

    async def get_latest_certificate(self, *, asset_id: uuid.UUID) -> dict[str, Any]:
        async with self.session_factory() as session:
            repository = ComplianceCertificateRepository(session)
            certificate = select_latest_certificate(await repository.get_by_asset_id(asset_id))
            if certificate is None:
                raise ScanNotFoundError(f"No certificate found for asset {asset_id}.")
            return serialize_certificate(certificate, include_pem=True)

    async def get_latest_remediation(self, *, asset_id: uuid.UUID) -> dict[str, Any]:
        async with self.session_factory() as session:
            repository = RemediationBundleRepository(session)
            remediation = select_latest_remediation(await repository.get_by_asset_id(asset_id))
            if remediation is None:
                raise ScanNotFoundError(f"No remediation found for asset {asset_id}.")
            return serialize_remediation(remediation)

    async def _load_scan_bundle(self, *, scan_id: uuid.UUID) -> dict[str, Any]:
        async with self.session_factory() as session:
            return await self._load_scan_bundle_from_session(session=session, scan_id=scan_id)

    async def _load_scan_bundle_from_session(
        self,
        *,
        session: AsyncSession,
        scan_id: uuid.UUID,
    ) -> dict[str, Any]:
        scan_repository = ScanJobRepository(session)
        asset_repository = DiscoveredAssetRepository(session)
        assessment_repository = CryptoAssessmentRepository(session)
        cbom_repository = CbomDocumentRepository(session)
        remediation_repository = RemediationBundleRepository(session)
        certificate_repository = ComplianceCertificateRepository(session)
        fingerprint_repository = AssetFingerprintRepository(session)
        dns_record_repository = DNSRecordRepository(session)
        scan_event_repository = ScanEventRepository(session)

        scan = await scan_repository.get_by_id(scan_id)
        if scan is None:
            raise ScanNotFoundError(f"Scan {scan_id} does not exist.")

        assets = list(await asset_repository.get_by_scan_id(scan_id))
        dns_records = list(await dns_record_repository.get_by_scan_id(scan_id))
        scan_events = list(await scan_event_repository.get_by_scan_id(scan_id))
        assessments: dict[uuid.UUID, CryptoAssessment] = {}
        cboms: dict[uuid.UUID, Any] = {}
        remediations: dict[uuid.UUID, Any] = {}
        certificates: dict[uuid.UUID, Any] = {}
        leaf_certificates: dict[uuid.UUID, CertificateChain] = {}
        remediation_actions: dict[uuid.UUID, list[RemediationAction]] = {}
        asset_fingerprints: dict[uuid.UUID, AssetFingerprint] = {}

        asset_ids = [asset.id for asset in assets]
        if asset_ids:
            canonical_keys_by_asset_id = {
                asset.id: canonical_key
                for asset in assets
                for canonical_key in [build_asset_fingerprint_key(asset)]
                if canonical_key is not None
            }
            if canonical_keys_by_asset_id:
                fingerprint_rows = await fingerprint_repository.get_by_canonical_keys(
                    tuple(canonical_keys_by_asset_id.values())
                )
                fingerprints_by_key = {
                    fingerprint.canonical_key: fingerprint for fingerprint in fingerprint_rows
                }
                asset_fingerprints = {
                    asset_id: fingerprints_by_key[canonical_key]
                    for asset_id, canonical_key in canonical_keys_by_asset_id.items()
                    if canonical_key in fingerprints_by_key
                }

            leaf_certificate_rows = (
                (
                    await session.execute(
                        select(CertificateChain).where(
                            CertificateChain.asset_id.in_(asset_ids),
                            CertificateChain.cert_level == CertLevel.LEAF,
                        )
                    )
                )
                .scalars()
                .all()
            )
            for certificate_chain in leaf_certificate_rows:
                leaf_certificates[certificate_chain.asset_id] = certificate_chain

            remediation_action_rows = (
                (
                    await session.execute(
                        select(RemediationAction).where(RemediationAction.asset_id.in_(asset_ids))
                    )
                )
                .scalars()
                .all()
            )
            for remediation_action in remediation_action_rows:
                remediation_actions.setdefault(remediation_action.asset_id, []).append(
                    remediation_action
                )

        for asset in assets:
            assessment_rows = await assessment_repository.get_by_asset_id(asset.id)
            if assessment_rows:
                assessments[asset.id] = select_latest(
                    assessment_rows,
                    timestamp_getter=lambda record: None,
                )

            cbom = select_latest_cbom(await cbom_repository.get_by_asset_id(asset.id))
            if cbom is not None:
                cboms[asset.id] = cbom

            remediation = select_latest_remediation(
                await remediation_repository.get_by_asset_id(asset.id)
            )
            if remediation is not None:
                remediations[asset.id] = remediation

            certificate = select_latest_certificate(
                await certificate_repository.get_by_asset_id(asset.id)
            )
            if certificate is not None:
                certificates[asset.id] = certificate

        tier_counts = {
            ComplianceTier.FULLY_QUANTUM_SAFE: 0,
            ComplianceTier.PQC_TRANSITIONING: 0,
            ComplianceTier.QUANTUM_VULNERABLE: 0,
        }
        critical_assets = 0
        unknown_assets = 0
        q_scores = []
        risk_scores = []
        for asset in assets:
            assessment = assessments.get(asset.id)
            if assessment is None:
                unknown_assets += 1
                continue

            if assessment.compliance_tier in tier_counts:
                tier_counts[assessment.compliance_tier] += 1
            else:
                unknown_assets += 1

            if assessment.risk_score is not None:
                risk_scores.append(assessment.risk_score)
                q_scores.append(max(0.0, min(100.0, 100.0 - assessment.risk_score)))
                if assessment.risk_score > 70:
                    critical_assets += 1
        tls_assets = sum(1 for asset in assets if asset.service_type is ServiceType.TLS)

        bundle = {
            "scan": scan,
            "assets": assets,
            "dns_records": dns_records,
            "scan_events": scan_events,
            "assessments": assessments,
            "cboms": cboms,
            "remediations": remediations,
            "certificates": certificates,
            "leaf_certificates": leaf_certificates,
            "remediation_actions": remediation_actions,
            "asset_fingerprints": asset_fingerprints,
            "progress": {
                "assets_discovered": len(assets),
                "assessments_created": len(assessments),
                "cboms_created": len(cboms),
                "remediations_created": len(remediations),
                "certificates_created": len(certificates),
            },
            "summary": {
                "total_assets": len(assets),
                "tls_assets": tls_assets,
                "non_tls_assets": len(assets) - tls_assets,
                "fully_quantum_safe_assets": tier_counts[ComplianceTier.FULLY_QUANTUM_SAFE],
                "transitioning_assets": tier_counts[ComplianceTier.PQC_TRANSITIONING],
                "vulnerable_assets": tier_counts[ComplianceTier.QUANTUM_VULNERABLE],
                "critical_assets": critical_assets,
                "unknown_assets": unknown_assets,
                "average_q_score": round(sum(q_scores) / len(q_scores), 1) if q_scores else None,
                "highest_risk_score": max(risk_scores) if risk_scores else None,
            },
        }
        bundle["runtime"] = self._build_runtime_payload(bundle)
        return bundle

    def _serialize_recent_scan(self, bundle: dict[str, Any]) -> dict[str, Any]:
        return {
            "scan_id": bundle["scan"].id,
            "target": bundle["scan"].target,
            "status": bundle["scan"].status,
            "created_at": bundle["scan"].created_at,
            "completed_at": bundle["scan"].completed_at,
            "summary": {
                "total_assets": bundle["summary"]["total_assets"],
                "tls_assets": bundle["summary"]["tls_assets"],
                "non_tls_assets": bundle["summary"]["non_tls_assets"],
                "vulnerable_assets": bundle["summary"]["vulnerable_assets"],
                "transitioning_assets": bundle["summary"]["transitioning_assets"],
                "fully_quantum_safe_assets": bundle["summary"]["fully_quantum_safe_assets"],
                "critical_assets": bundle["summary"]["critical_assets"],
                "unknown_assets": bundle["summary"]["unknown_assets"],
                "average_q_score": bundle["summary"]["average_q_score"],
                "highest_risk_score": bundle["summary"]["highest_risk_score"],
            },
            "progress": bundle["progress"],
            "scan_profile": bundle["scan"].scan_profile,
            "initiated_by": bundle["scan"].initiated_by,
            "degraded_mode_count": len(bundle["runtime"]["degraded_modes"]),
        }

    def _build_priority_findings(
        self,
        *,
        bundles: Sequence[dict[str, Any]],
        priority_limit: int,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for bundle in bundles:
            if bundle["scan"].status is not ScanStatus.COMPLETED:
                continue

            for asset in bundle["assets"]:
                assessment = bundle["assessments"].get(asset.id)
                findings.append(
                    {
                        "scan_id": bundle["scan"].id,
                        "asset_id": asset.id,
                        "target": bundle["scan"].target,
                        "asset_label": asset.hostname or asset.ip_address or str(asset.id),
                        "port": asset.port,
                        "service_type": asset.service_type,
                        "tier": getattr(assessment, "compliance_tier", None),
                        "risk_score": getattr(assessment, "risk_score", None),
                    }
                )

        tier_rank = {
            ComplianceTier.QUANTUM_VULNERABLE: 0,
            ComplianceTier.PQC_TRANSITIONING: 1,
            ComplianceTier.FULLY_QUANTUM_SAFE: 2,
            None: 3,
        }
        findings.sort(
            key=lambda finding: (
                tier_rank.get(finding["tier"], 3),
                -(
                    finding["risk_score"]
                    if isinstance(finding["risk_score"], (float, int))
                    else -1.0
                ),
                str(finding["scan_id"]),
                str(finding["asset_id"]),
            )
        )
        return findings[:priority_limit]

    @staticmethod
    def _estimate_profile_multiplier(scan_profile: str | None) -> float:
        if not scan_profile:
            return 1.0

        flags = ScanReadService._profile_option_flags(scan_profile)
        multiplier = 1.0

        if flags["quick"]:
            multiplier *= 0.6
        elif flags["deep"]:
            multiplier *= 1.9
        elif flags["pqc_focus"]:
            multiplier *= 1.25

        if flags["full_port_scan"]:
            multiplier *= 2.2
        if flags["bounded_port_scan"]:
            multiplier *= 0.85

        if flags["full_enumeration"]:
            multiplier *= 1.7
        if flags["no_enumeration"]:
            multiplier *= 0.8

        return max(multiplier, 0.35)

    @staticmethod
    def _profile_option_flags(scan_profile: str | None) -> dict[str, bool]:
        normalized = (scan_profile or "").lower()
        return {
            "quick": "quick" in normalized,
            "deep": "deep" in normalized,
            "pqc_focus": "pqc focus" in normalized,
            "standard": "standard" in normalized,
            "full_port_scan": "full port scan" in normalized or "deep" in normalized,
            "bounded_port_scan": "bounded port scan" in normalized,
            "full_enumeration": "full enumeration" in normalized or "deep" in normalized or "standard" in normalized,
            "no_enumeration": "no enumeration" in normalized or "pqc focus" in normalized,
        }

    def _build_eta_payload(
        self,
        *,
        status: ScanStatus,
        stage: str | None,
        stage_detail: str | None,
        stage_started_at: datetime | None,
        elapsed_seconds: float | None,
        scan_profile: str | None,
        progress: dict[str, Any],
    ) -> dict[str, Any]:
        if elapsed_seconds is None:
            return {
                "estimated_total_seconds": None,
                "estimated_remaining_seconds": None,
                "estimated_remaining_lower_seconds": None,
                "estimated_remaining_upper_seconds": None,
                "eta_confidence": None,
            }

        if status in {ScanStatus.COMPLETED, ScanStatus.FAILED}:
            return {
                "estimated_total_seconds": elapsed_seconds,
                "estimated_remaining_seconds": 0.0,
                "estimated_remaining_lower_seconds": 0.0,
                "estimated_remaining_upper_seconds": 0.0,
                "eta_confidence": "final",
            }

        multiplier = ScanReadService._estimate_profile_multiplier(scan_profile)
        expected_by_stage = {
            key: value * multiplier for key, value in ETA_STAGE_WEIGHTS_SECONDS.items()
        }
        total_expected = sum(
            expected_by_stage.get(stage_name, 0.0) for stage_name in ETA_STAGE_ORDER
        )

        current_stage = stage or "queued"
        completed_weight = 0.0
        for stage_name in ETA_STAGE_ORDER:
            if stage_name == current_stage:
                break
            completed_weight += expected_by_stage.get(stage_name, 0.0)

        current_stage_expected = expected_by_stage.get(current_stage, expected_by_stage["queued"])

        # Streaming stages don't have stable denominator early on; hide ETA until
        # enough runtime signal is available to avoid misleading ranges.
        if current_stage in {"enumerating_domains", "scanning_ports", "probing_tls"}:
            if (stage_detail is None or stage_detail.strip().lower() == "streaming") and elapsed_seconds < 120:
                return {
                    "estimated_total_seconds": None,
                    "estimated_remaining_seconds": None,
                    "estimated_remaining_lower_seconds": None,
                    "estimated_remaining_upper_seconds": None,
                    "eta_confidence": "low",
                }

        if current_stage == "probing_tls" and stage_detail:
            match = re.search(r"(\d+)\s+TLS endpoint", stage_detail)
            if match:
                endpoint_count = max(1, int(match.group(1)))
                tls_probe_concurrency = max(
                    1,
                    int(os.getenv("AEGIS_TLS_PROBE_CONCURRENCY", "50")),
                )
                # Empirical per-endpoint budget with concurrency sharing and retries.
                estimated_tls = (endpoint_count / tls_probe_concurrency) * 3.5
                current_stage_expected = max(current_stage_expected, estimated_tls)

        stage_elapsed_seconds = 0.0
        if stage_started_at is not None:
            stage_elapsed_seconds = max((datetime.now(UTC) - stage_started_at).total_seconds(), 0.0)

        assets_discovered = progress.get("assets_discovered")
        if isinstance(assets_discovered, (int, float)) and assets_discovered > 0:
            scale = min(float(assets_discovered), 2000.0)
            total_expected *= 1.0 + (scale / 2000.0) * 2.5

        # Track overrun in the active stage and increase remaining estimate accordingly.
        stage_overrun_ratio = 1.0
        if current_stage_expected > 0 and stage_elapsed_seconds > 0:
            stage_overrun_ratio = max(1.0, stage_elapsed_seconds / current_stage_expected)

        nominal_current_remaining = max(current_stage_expected - stage_elapsed_seconds, 0.0)
        if stage_overrun_ratio > 1.0:
            nominal_current_remaining = max(
                nominal_current_remaining,
                min(stage_elapsed_seconds * 0.45, 20 * 60.0),
            )

        trailing_stage_weights = 0.0
        seen_current = False
        for stage_name in ETA_STAGE_ORDER:
            if stage_name == current_stage:
                seen_current = True
                continue
            if seen_current:
                trailing_stage_weights += expected_by_stage.get(stage_name, 0.0)

        if stage_overrun_ratio > 1.0:
            trailing_stage_weights *= min(stage_overrun_ratio, 3.0)

        estimated_remaining_seconds = max(nominal_current_remaining + trailing_stage_weights, 0.0)
        estimated_total_seconds = max(elapsed_seconds + estimated_remaining_seconds, total_expected)

        # Keep ETA honest during non-terminal running states.
        if estimated_remaining_seconds < 60.0:
            estimated_remaining_seconds = min(max(estimated_remaining_seconds, 60.0), 5 * 60.0)
            estimated_total_seconds = max(
                estimated_total_seconds, elapsed_seconds + estimated_remaining_seconds
            )

        lower = max(estimated_remaining_seconds * 0.7, 0.0)
        upper = estimated_remaining_seconds * 1.6

        confidence = "medium"
        if current_stage in {"queued", "preparing_scan", "enumerating_domains"}:
            confidence = "low"
        elif current_stage in {"persisting_assets", "completed", "failed"}:
            confidence = "high"
        if stage_overrun_ratio >= 1.5:
            confidence = "low"

        lower = min(lower, estimated_remaining_seconds)
        upper = max(upper, estimated_remaining_seconds)

        return {
            "estimated_total_seconds": estimated_total_seconds,
            "estimated_remaining_seconds": estimated_remaining_seconds,
            "estimated_remaining_lower_seconds": lower,
            "estimated_remaining_upper_seconds": upper,
            "eta_confidence": confidence,
        }

    def _build_runtime_payload(self, bundle: dict[str, Any]) -> dict[str, Any]:
        runtime_snapshot = None
        if self.runtime_store is not None:
            runtime_snapshot = self.runtime_store.get_snapshot(bundle["scan"].id)

        completed_at = bundle["scan"].completed_at
        end_time = completed_at or datetime.now(UTC)
        created_at = bundle["scan"].created_at
        elapsed_seconds = None
        if created_at is not None:
            elapsed_seconds = max((end_time - created_at).total_seconds(), 0.0)

        stage = runtime_snapshot.stage if runtime_snapshot is not None else None
        if stage is None:
            stage = (
                "queued"
                if bundle["scan"].status is ScanStatus.PENDING
                else bundle["scan"].status.value
            )

        persisted_events = [
            serialize_persisted_scan_event(event)
            for event in sorted(
                bundle.get("scan_events", []),
                key=lambda event: (
                    getattr(event, "timestamp", None) or datetime.min.replace(tzinfo=UTC),
                    str(getattr(event, "id", "")),
                ),
            )
        ]
        runtime_events = (
            [serialize_runtime_event(event) for event in runtime_snapshot.events]
            if runtime_snapshot is not None
            else persisted_events
        )
        degraded_modes = (
            list(runtime_snapshot.degraded_modes)
            if runtime_snapshot is not None
            else [event["message"] for event in persisted_events if event["kind"] == "degraded"]
        )

        eta_payload = self._build_eta_payload(
            status=bundle["scan"].status,
            stage=stage,
            stage_detail=runtime_snapshot.stage_detail if runtime_snapshot is not None else None,
            stage_started_at=runtime_snapshot.stage_started_at
            if runtime_snapshot is not None
            else None,
            elapsed_seconds=elapsed_seconds,
            scan_profile=bundle["scan"].scan_profile,
            progress=bundle["progress"],
        )

        return {
            "stage": stage,
            "stage_detail": runtime_snapshot.stage_detail if runtime_snapshot is not None else None,
            "stage_started_at": runtime_snapshot.stage_started_at
            if runtime_snapshot is not None
            else None,
            "elapsed_seconds": elapsed_seconds,
            **eta_payload,
            "events": runtime_events,
            "degraded_modes": degraded_modes,
        }


