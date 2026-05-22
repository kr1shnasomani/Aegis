"""
AssessmentMixin — TLS cryptographic analysis, risk scoring, and artifact generation.

These methods are mixed into PipelineOrchestrator via inheritance.
They cover:
  - _process_tls_asset (full 318-line pipeline per asset)
  - _ensure_certificate_chain / _recover_certificate_chain_with_showcerts
  - _build_assessment_inputs
  - _compute_risk_score / _compute_compliance_tier
  - _persist_crypto_assessment / _persist_cbom / _persist_compliance_cert
  - _generate_remediation_actions
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import os
import uuid
import re
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Sequence

from sqlalchemy.exc import IntegrityError

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
from backend.cert import CertificateRequest
from backend.compliance import ComplianceInput, RulesEngine
from backend.discovery import CertificateExtractor, TLSProbeResult
from backend.models.asset_fingerprint import AssetFingerprint
from backend.models.certificate_chain import CertificateChain
from backend.models.crypto_assessment import CryptoAssessment
from backend.models.discovered_asset import DiscoveredAsset
from backend.models.enums import CertLevel, ComplianceTier, ServiceType
from backend.models.remediation_action import (
    RemediationAction,
    RemediationEffort,
    RemediationPriority,
    RemediationStatus,
)
from backend.intelligence import RagOrchestrator, RemediationInput
from backend.repositories import (
    AssetFingerprintRepository,
    CbomDocumentRepository,
    CertificateChainRepository,
    ComplianceCertificateRepository,
    CryptoAssessmentRepository,
    DiscoveredAssetRepository,
    RemediationBundleRepository,
    ScanJobRepository,
)
from .models import _AssessmentInputs
from .serializers import (
    _artifact_key_from_asset,
    build_asset_fingerprint_key,
    extract_subject_cn,
    select_latest_cbom,
    select_latest_certificate,
    serialize_assessment,
    serialize_leaf_certificate,
)

logger = logging.getLogger(__name__)


class AssessmentMixin:
    """TLS assessment and artifact generation — mixed into PipelineOrchestrator."""

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


