"""
Serializer and selector helpers for orchestrator read models.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any, Callable, Sequence

from backend.models.certificate_chain import CertificateChain
from backend.models.crypto_assessment import CryptoAssessment
from backend.models.discovered_asset import DiscoveredAsset
from backend.models.dns_record import DNSRecord
from backend.models.enums import ScanStatus, ServiceType
from backend.models.remediation_action import RemediationAction
from backend.models.scan_event import ScanEvent

from .models import ScanRuntimeEvent


def select_latest_cbom(records: Sequence[Any]) -> Any | None:
    """Return the latest CBOM using created_at desc then id desc."""
    return select_latest(
        records,
        timestamp_getter=lambda record: getattr(record, "created_at", None),
    )


def select_latest_certificate(records: Sequence[Any]) -> Any | None:
    """Return the latest certificate using valid_from desc then id desc."""
    return select_latest(
        records,
        timestamp_getter=lambda record: getattr(record, "valid_from", None),
    )


def select_latest_remediation(records: Sequence[Any]) -> Any | None:
    """Return the latest remediation using created_at desc then id desc."""
    return select_latest(
        records,
        timestamp_getter=lambda record: getattr(record, "created_at", None),
    )


def select_latest(
    records: Sequence[Any],
    *,
    timestamp_getter: Callable[[Any], datetime | None],
) -> Any | None:
    """Return the deterministic latest record using timestamp then id."""
    if not records:
        return None
    minimum = datetime.min.replace(tzinfo=UTC)
    return max(
        records,
        key=lambda record: (
            timestamp_getter(record) or minimum,
            str(getattr(record, "id", "")),
        ),
    )


def serialize_assessment(assessment: CryptoAssessment | None) -> dict[str, Any] | None:
    if assessment is None:
        return None
    return {
        "id": assessment.id,
        "tls_version": assessment.tls_version,
        "cipher_suite": assessment.cipher_suite,
        "kex_algorithm": assessment.kex_algorithm,
        "auth_algorithm": assessment.auth_algorithm,
        "enc_algorithm": assessment.enc_algorithm,
        "mac_algorithm": assessment.mac_algorithm,
        "risk_score": assessment.risk_score,
        "score_explanation": assessment.score_explanation,
        "compliance_tier": assessment.compliance_tier,
        "kex_vulnerability": assessment.kex_vulnerability,
        "sig_vulnerability": assessment.sig_vulnerability,
        "sym_vulnerability": assessment.sym_vulnerability,
        "tls_vulnerability": assessment.tls_vulnerability,
    }


def serialize_cbom(cbom_document: Any | None) -> dict[str, Any] | None:
    if cbom_document is None:
        return None
    return {
        "id": cbom_document.id,
        "serial_number": cbom_document.serial_number,
        "created_at": cbom_document.created_at,
        "cbom_json": cbom_document.cbom_json,
    }


def serialize_remediation(remediation_bundle: Any | None) -> dict[str, Any] | None:
    if remediation_bundle is None:
        return None
    return {
        "id": remediation_bundle.id,
        "created_at": remediation_bundle.created_at,
        "hndl_timeline": remediation_bundle.hndl_timeline,
        "patch_config": remediation_bundle.patch_config,
        "migration_roadmap": remediation_bundle.migration_roadmap,
        "source_citations": remediation_bundle.source_citations,
    }


def serialize_certificate(
    certificate: Any | None,
    *,
    include_pem: bool,
) -> dict[str, Any] | None:
    if certificate is None:
        return None
    payload = {
        "id": certificate.id,
        "tier": certificate.tier,
        "signing_algorithm": certificate.signing_algorithm,
        "valid_from": certificate.valid_from,
        "valid_until": certificate.valid_until,
        "extensions_json": certificate.extensions_json,
        "remediation_bundle_id": certificate.remediation_bundle_id,
    }
    if include_pem:
        payload["certificate_pem"] = certificate.certificate_pem
    return payload


def serialize_leaf_certificate(certificate_chain: CertificateChain | None) -> dict[str, Any] | None:
    if certificate_chain is None:
        return None
    now = datetime.now(UTC)
    not_after = certificate_chain.not_after
    return {
        "subject_cn": extract_subject_cn(certificate_chain.subject),
        "issuer": certificate_chain.issuer,
        "public_key_algorithm": certificate_chain.public_key_algorithm,
        "key_size_bits": certificate_chain.key_size_bits,
        "signature_algorithm": certificate_chain.signature_algorithm,
        "quantum_safe": certificate_chain.quantum_safe,
        "not_before": certificate_chain.not_before,
        "not_after": not_after,
        "days_remaining": (not_after - now).days if not_after is not None else None,
    }


def serialize_asset_certificate(
    certificate_chain: CertificateChain | None,
) -> dict[str, Any] | None:
    """Build frontend-facing TLS certificate summary from the leaf certificate row."""
    if certificate_chain is None:
        return None

    summary = serialize_leaf_certificate(certificate_chain)
    if summary is None:
        return None

    public_key_algorithm = (summary.get("public_key_algorithm") or "").upper()
    if "ML-DSA" in public_key_algorithm:
        key_type = "ML-DSA"
    elif "SLH-DSA" in public_key_algorithm:
        key_type = "SLH-DSA"
    elif "ECDSA" in public_key_algorithm or "EC" in public_key_algorithm:
        key_type = "ECDSA"
    else:
        key_type = "RSA"

    subject_cn = summary.get("subject_cn") or "unknown"
    issuer = summary.get("issuer") or "Unknown"

    return {
        "subject_cn": subject_cn,
        "subject_alt_names": [subject_cn] if subject_cn != "unknown" else [],
        "issuer": issuer,
        "certificate_authority": issuer,
        "signature_algorithm": summary.get("signature_algorithm") or "unknown",
        "key_type": key_type,
        "key_size": summary.get("key_size_bits") or 0,
        "valid_from": summary.get("not_before"),
        "valid_until": summary.get("not_after"),
        "days_remaining": summary.get("days_remaining"),
        "sha256_fingerprint": "",
    }


def serialize_asset_fingerprint_history_entry(
    entry: Any,
) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None

    scan_id = entry.get("scan_id")
    parsed_scan_id: uuid.UUID | None = None
    if isinstance(scan_id, uuid.UUID):
        parsed_scan_id = scan_id
    elif isinstance(scan_id, str):
        try:
            parsed_scan_id = uuid.UUID(scan_id)
        except ValueError:
            parsed_scan_id = None

    q_score = entry.get("q_score")
    parsed_q_score: int | None = None
    if isinstance(q_score, bool):
        parsed_q_score = None
    elif isinstance(q_score, (int, float)):
        parsed_q_score = int(round(q_score))
    elif isinstance(q_score, str):
        try:
            parsed_q_score = int(round(float(q_score)))
        except ValueError:
            parsed_q_score = None

    scanned_at = entry.get("scanned_at")
    parsed_scanned_at: datetime | None = None
    if isinstance(scanned_at, datetime):
        parsed_scanned_at = scanned_at
    elif isinstance(scanned_at, str):
        normalized_scanned_at = scanned_at.replace("Z", "+00:00")
        try:
            parsed_scanned_at = datetime.fromisoformat(normalized_scanned_at)
        except ValueError:
            parsed_scanned_at = None
    if parsed_scanned_at is not None and parsed_scanned_at.tzinfo is None:
        parsed_scanned_at = parsed_scanned_at.replace(tzinfo=UTC)

    if parsed_scan_id is None and parsed_q_score is None and parsed_scanned_at is None:
        return None

    return {
        "scan_id": parsed_scan_id,
        "q_score": parsed_q_score,
        "scanned_at": parsed_scanned_at,
    }


def serialize_asset_fingerprint(
    fingerprint: AssetFingerprint | None,
) -> dict[str, Any] | None:
    if fingerprint is None:
        return None

    history_entries = []
    for entry in fingerprint.q_score_history or []:
        serialized_entry = serialize_asset_fingerprint_history_entry(entry)
        if serialized_entry is not None:
            history_entries.append(serialized_entry)

    minimum = datetime.min.replace(tzinfo=UTC)
    history_entries.sort(
        key=lambda entry: (
            entry["scanned_at"] or minimum,
            str(entry["scan_id"] or ""),
        )
    )

    return {
        "canonical_key": fingerprint.canonical_key,
        "appearance_count": fingerprint.appearance_count,
        "latest_q_score": fingerprint.latest_q_score,
        "latest_compliance_tier": fingerprint.latest_compliance_tier,
        "first_seen_at": fingerprint.first_seen_at,
        "last_seen_at": fingerprint.last_seen_at,
        "first_seen_scan_id": fingerprint.first_seen_scan_id,
        "last_seen_scan_id": fingerprint.last_seen_scan_id,
        "q_score_history": history_entries,
    }


def serialize_remediation_action(remediation_action: RemediationAction) -> dict[str, Any]:
    return {
        "priority": remediation_action.priority.value,
        "finding": remediation_action.finding,
        "action": remediation_action.action,
        "effort": remediation_action.effort.value,
        "status": remediation_action.status.value,
        "category": remediation_action.category,
        "nist_reference": remediation_action.nist_reference,
    }


def serialize_dns_record(dns_record: DNSRecord) -> dict[str, Any]:
    return {
        "hostname": dns_record.hostname,
        "resolved_ips": list(dns_record.resolved_ips or []),
        "cnames": list(dns_record.cnames or []),
        "discovery_source": dns_record.discovery_source,
        "is_in_scope": dns_record.is_in_scope,
        "discovered_at": dns_record.discovered_at,
    }


def serialize_runtime_event(event: ScanRuntimeEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "kind": event.kind,
        "message": event.message,
        "stage": event.stage,
    }


def serialize_persisted_scan_event(event: ScanEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "kind": event.kind,
        "message": event.message,
        "stage": event.stage,
    }


def _artifact_key_from_tls_result(
    tls_result: TLSProbeResult,
) -> tuple[str | None, str, int, str, str]:
    return (
        _normalize_hostname(tls_result.hostname),
        tls_result.ip_address,
        tls_result.port,
        tls_result.protocol.lower(),
        ServiceType.TLS.value,
    )


def _artifact_key_from_asset(asset: DiscoveredAsset) -> tuple[str | None, str, int, str, str]:
    return (
        _normalize_hostname(asset.hostname),
        asset.ip_address or "",
        asset.port,
        asset.protocol.lower(),
        asset.service_type.value if asset.service_type else "",
    )


def build_asset_fingerprint_key(asset: DiscoveredAsset) -> str | None:
    asset_label = _normalize_hostname(asset.hostname) or (asset.ip_address or "").strip()
    if not asset_label:
        return None
    return f"{asset_label}:{asset.port}/{asset.protocol.lower()}"


def _normalize_hostname(hostname: str | None) -> str | None:
    if hostname is None:
        return None
    normalized = hostname.strip().lower().rstrip(".")
    return normalized or None


def extract_subject_cn(subject: str | None) -> str | None:
    if not subject:
        return None
    match = re.search(r"(?:^|,)CN=([^,]+)", subject)
    if match is None:
        return None
    return match.group(1).strip() or None
