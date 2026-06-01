"""
Phase 7 X.509 compliance certificate signer.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from backend.compliance import ComplianceInput, RulesEngine
from backend.core.config import Settings, get_settings
from backend.models.enums import ComplianceTier

if TYPE_CHECKING:
    from backend.repositories.compliance_cert_repo import ComplianceCertificateRepository
    from backend.models.discovered_asset import DiscoveredAsset
    from backend.models.remediation_bundle import RemediationBundle

from .asn1 import _OID_MAP, _encode_utf8_asn1
from .exceptions import (
    CertificateIssuanceError,
    ComplianceTierMismatchError,
    OQSConfigError,
    OQSSubprocessError,
    OQSUnavailableError,
)
from .models import CertificateRequest, IssuedCertificate, _CertificateIdentity, _OqsCapability

logger = logging.getLogger(__name__)

_VALIDITY_DAYS = {
    ComplianceTier.FULLY_QUANTUM_SAFE: 90,
    ComplianceTier.PQC_TRANSITIONING: 30,
    ComplianceTier.QUANTUM_VULNERABLE: 7,
}
_PQC_STATUS = {
    ComplianceTier.FULLY_QUANTUM_SAFE: "READY",
    ComplianceTier.PQC_TRANSITIONING: "HYBRID",
    ComplianceTier.QUANTUM_VULNERABLE: "VULNERABLE",
}
_MAX_BROKEN_ALGORITHMS_LENGTH = 192
_OPENSSL_TIMEOUT_SECONDS = 20.0


class CertificateSigner:
    """Issue and persist Aegis X.509 compliance certificates."""

    _oqs_capability_cache: _OqsCapability | None = None
    _issuer_lock: Lock = Lock()

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        rules_engine: RulesEngine | None = None,
        runtime_dir: str | Path | None = None,
        openssl_binary: str = "openssl",
    ) -> None:
        self.settings = settings or get_settings()
        self.rules_engine = rules_engine or RulesEngine()
        self.openssl_binary = openssl_binary
        self.runtime_dir = Path(runtime_dir or self.settings.CERT_RUNTIME_DIR)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

    async def issue_and_persist(
        self,
        *,
        certificate_request: CertificateRequest,
        compliance_certificate_repository: "ComplianceCertificateRepository",
    ):
        """Issue and persist one compliance certificate."""
        issued = self.issue(certificate_request=certificate_request)
        evaluation = self._evaluate_request(certificate_request)

        return await compliance_certificate_repository.create(
            asset_id=certificate_request.asset.id,
            tier=evaluation.tier,
            certificate_pem=issued.certificate_pem,
            signing_algorithm=issued.signing_algorithm,
            valid_from=issued.valid_from,
            valid_until=issued.valid_until,
            extensions_json=issued.extensions_json,
            remediation_bundle_id=certificate_request.remediation_bundle.id
            if certificate_request.remediation_bundle
            else None,
        )

    def issue(
        self,
        *,
        certificate_request: CertificateRequest,
    ) -> IssuedCertificate:
        """Issue one compliance certificate without persisting it."""
        evaluation = self._evaluate_request(certificate_request)
        identity = self._build_identity(certificate_request.asset)
        valid_from, valid_until = self._compute_validity_window(evaluation.tier)
        serial_number = self._generate_serial_number()
        extension_payload = self._build_extension_payload(
            evaluation=evaluation,
            remediation_bundle=certificate_request.remediation_bundle,
        )

        oqs_capability = self._detect_oqs_capability()
        if oqs_capability.available:
            try:
                return self._issue_with_oqs(
                    identity=identity,
                    extension_payload=extension_payload,
                    valid_from=valid_from,
                    valid_until=valid_until,
                    serial_number=serial_number,
                )
            except OQSUnavailableError as error:
                logger.warning("Falling back to ECDSA because OQS is unavailable: %s", error)
            except OQSConfigError as error:
                logger.warning("Falling back to ECDSA because OQS config is invalid: %s", error)
            except OQSSubprocessError as error:
                logger.warning("Falling back to ECDSA because OQS subprocess failed: %s", error)
        else:
            logger.info(
                "OQS capability unavailable, using ECDSA fallback: %s", oqs_capability.reason
            )

        return self._issue_with_ecdsa(
            identity=identity,
            extension_payload=extension_payload,
            valid_from=valid_from,
            valid_until=valid_until,
            serial_number=serial_number,
        )

    def _evaluate_request(self, certificate_request: CertificateRequest):
        evaluation = self.rules_engine.evaluate(
            ComplianceInput(
                kex_algorithm=certificate_request.assessment.kex_algorithm,
                auth_algorithm=certificate_request.assessment.auth_algorithm,
                enc_algorithm=certificate_request.assessment.enc_algorithm,
                risk_score=certificate_request.assessment.risk_score,
            )
        )
        stored_tier = certificate_request.assessment.compliance_tier
        if stored_tier is not None and stored_tier is not evaluation.tier:
            raise ComplianceTierMismatchError(
                f"Stored compliance tier {stored_tier.value} does not match recomputed "
                f"{evaluation.tier.value}."
            )
        if (
            evaluation.tier is ComplianceTier.QUANTUM_VULNERABLE
            and certificate_request.remediation_bundle is None
        ):
            raise CertificateIssuanceError(
                "Tier 3 certificate issuance requires a remediation bundle."
            )
        return evaluation

    @staticmethod
    def _build_identity(asset: DiscoveredAsset) -> _CertificateIdentity:
        if asset.hostname:
            return _CertificateIdentity(
                common_name=asset.hostname,
                san_value=asset.hostname,
                san_is_ip=False,
            )
        if asset.ip_address:
            parsed = ipaddress.ip_address(asset.ip_address)
            return _CertificateIdentity(
                common_name=asset.ip_address,
                san_value=str(parsed),
                san_is_ip=True,
            )
        raise CertificateIssuanceError("Asset is missing both hostname and ip_address.")

    @staticmethod
    def _compute_validity_window(tier: ComplianceTier) -> tuple[datetime, datetime]:
        valid_from = datetime.now(UTC).replace(microsecond=0)
        valid_until = valid_from + timedelta(days=_VALIDITY_DAYS[tier])
        if valid_until <= valid_from:
            raise CertificateIssuanceError("Certificate validity window is invalid.")
        return valid_from, valid_until

    @staticmethod
    def _generate_serial_number() -> int:
        serial_number = int.from_bytes(secrets.token_bytes(16), byteorder="big")
        return serial_number or 1

    @staticmethod
    def _format_openssl_ca_serial(serial_number: int) -> str:
        rendered = f"{serial_number:X}"
        if len(rendered) % 2 == 1:
            rendered = f"0{rendered}"
        return rendered

    def _build_extension_payload(
        self,
        *,
        evaluation,
        remediation_bundle: RemediationBundle | None,
    ) -> dict[str, Any]:
        broken_algorithms = list(evaluation.broken_algorithms)
        hybrid_algorithms = list(evaluation.hybrid_algorithms)
        bounded_broken = self._bounded_csv(broken_algorithms, _MAX_BROKEN_ALGORITHMS_LENGTH)
        oid_payloads = {
            "pqc_status": _PQC_STATUS[evaluation.tier],
            "fips_compliant": "203+204"
            if evaluation.tier is ComplianceTier.FULLY_QUANTUM_SAFE
            else "",
            "broken_algorithms": bounded_broken,
            "remediation_bundle_id": str(remediation_bundle.id) if remediation_bundle else "",
        }
        return {
            "pqc_status": oid_payloads["pqc_status"],
            "fips_compliant": oid_payloads["fips_compliant"] or None,
            "broken_algorithms": broken_algorithms,
            "hybrid_algorithms": hybrid_algorithms,
            "remediation_bundle_id": oid_payloads["remediation_bundle_id"] or None,
            "oid_map": dict(_OID_MAP),
            "oid_payloads": oid_payloads,
        }

    @staticmethod
    def _bounded_csv(values: list[str], max_length: int) -> str:
        if not values:
            return ""
        joined = ",".join(values)
        if len(joined) <= max_length:
            return joined
        parts: list[str] = []
        current_length = 0
        for value in values:
            separator = 1 if parts else 0
            if current_length + separator + len(value) > max_length - 4:
                break
            parts.append(value)
            current_length += separator + len(value)
        if not parts:
            return joined[: max_length - 3] + "..."
        return ",".join(parts) + ",..."

    def _issue_with_ecdsa(
        self,
        *,
        identity: _CertificateIdentity,
        extension_payload: dict[str, Any],
        valid_from: datetime,
        valid_until: datetime,
        serial_number: int,
    ) -> IssuedCertificate:
        issuer_key, issuer_cert = self._ensure_ecdsa_issuer()
        asset_key = ec.generate_private_key(ec.SECP384R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(self._build_subject_name(identity))
            .issuer_name(issuer_cert.subject)
            .public_key(asset_key.public_key())
            .serial_number(serial_number)
            .not_valid_before(valid_from)
            .not_valid_after(valid_until)
        )
        certificate = self._apply_standard_extensions(certificate, identity=identity)
        certificate = self._apply_custom_extensions(
            certificate=certificate,
            extension_payload=extension_payload,
        )
        signed = certificate.sign(private_key=issuer_key, algorithm=hashes.SHA384())
        pem = signed.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return IssuedCertificate(
            certificate_pem=pem,
            signing_algorithm="ECDSA",
            valid_from=valid_from,
            valid_until=valid_until,
            extensions_json=extension_payload,
        )

    def _ensure_ecdsa_issuer(self) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        key_path = self.runtime_dir / "issuer_ecdsa_key.pem"
        cert_path = self.runtime_dir / "issuer_ecdsa_cert.pem"
        with self._issuer_lock:
            if key_path.exists() and cert_path.exists():
                issuer_key = serialization.load_pem_private_key(
                    key_path.read_bytes(),
                    password=None,
                )
                issuer_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                return issuer_key, issuer_cert

            issuer_key = ec.generate_private_key(ec.SECP384R1())
            now = datetime.now(UTC)
            issuer_subject = self._build_issuer_subject()
            issuer_cert = (
                x509.CertificateBuilder()
                .subject_name(issuer_subject)
                .issuer_name(issuer_subject)
                .public_key(issuer_key.public_key())
                .serial_number(self._generate_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),
                    critical=False,
                )
                .sign(private_key=issuer_key, algorithm=hashes.SHA384())
            )
            key_path.write_bytes(
                issuer_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            cert_path.write_bytes(issuer_cert.public_bytes(serialization.Encoding.PEM))
            return issuer_key, issuer_cert

    def _issue_with_oqs(
        self,
        *,
        identity: _CertificateIdentity,
        extension_payload: dict[str, Any],
        valid_from: datetime,
        valid_until: datetime,
        serial_number: int,
    ) -> IssuedCertificate:
        self._ensure_oqs_issuer()
        with tempfile.TemporaryDirectory(prefix="aegis-oqs-", dir=self.runtime_dir) as temp_dir:
            temp_path = Path(temp_dir)
            leaf_key = temp_path / "leaf.key"
            leaf_csr = temp_path / "leaf.csr"
            leaf_cert = temp_path / "leaf.crt"
            leaf_config = temp_path / "leaf.cnf"
            ca_db = temp_path / "ca"
            ca_db.mkdir(parents=True, exist_ok=True)
            (ca_db / "index.txt").write_text("", encoding="utf-8")
            (ca_db / "serial").write_text(
                f"{self._format_openssl_ca_serial(serial_number)}\n",
                encoding="utf-8",
            )

            leaf_config.write_text(
                self._render_leaf_openssl_config(
                    identity=identity,
                    extension_payload=extension_payload,
                    ca_db=ca_db,
                ),
                encoding="utf-8",
            )

            self._run_openssl(
                [
                    "req",
                    "-new",
                    "-newkey",
                    "ml-dsa-65",
                    "-keyout",
                    str(leaf_key),
                    "-out",
                    str(leaf_csr),
                    "-config",
                    str(leaf_config),
                    "-subj",
                    self._subject_string(identity),
                    "-nodes",
                ]
            )
            self._run_openssl(
                [
                    "ca",
                    "-batch",
                    "-config",
                    str(leaf_config),
                    "-in",
                    str(leaf_csr),
                    "-out",
                    str(leaf_cert),
                    "-extensions",
                    "v3_leaf",
                    "-startdate",
                    valid_from.strftime("%Y%m%d%H%M%SZ"),
                    "-enddate",
                    valid_until.strftime("%Y%m%d%H%M%SZ"),
                ]
            )
            certificate = x509.load_pem_x509_certificate(leaf_cert.read_bytes())
            pem = leaf_cert.read_text(encoding="utf-8")
            return IssuedCertificate(
                certificate_pem=pem,
                signing_algorithm="ML-DSA-65",
                valid_from=certificate.not_valid_before_utc,
                valid_until=certificate.not_valid_after_utc,
                extensions_json=extension_payload,
            )

    def _ensure_oqs_issuer(self) -> None:
        key_path = self.runtime_dir / "issuer_mldsa_key.pem"
        cert_path = self.runtime_dir / "issuer_mldsa_cert.pem"
        with self._issuer_lock:
            if key_path.exists() and cert_path.exists():
                return

            with tempfile.TemporaryDirectory(
                prefix="aegis-oqs-issuer-", dir=self.runtime_dir
            ) as temp_dir:
                temp_path = Path(temp_dir)
                issuer_config = temp_path / "issuer.cnf"
                issuer_config.write_text(self._render_issuer_openssl_config(), encoding="utf-8")
                self._run_openssl(
                    [
                        "req",
                        "-x509",
                        "-new",
                        "-newkey",
                        "ml-dsa-65",
                        "-keyout",
                        str(key_path),
                        "-out",
                        str(cert_path),
                        "-config",
                        str(issuer_config),
                        "-extensions",
                        "v3_ca",
                        "-days",
                        "3650",
                        "-subj",
                        self._issuer_subject_string(),
                        "-nodes",
                    ]
                )

    def _run_openssl(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if shutil.which(self.openssl_binary) is None:
            raise OQSUnavailableError(f"OpenSSL binary '{self.openssl_binary}' was not found.")
        command = [self.openssl_binary, *args]
        try:
            return subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=_OPENSSL_TIMEOUT_SECONDS,
                env=self._openssl_environment(),
            )
        except subprocess.TimeoutExpired as error:
            raise OQSSubprocessError(
                f"OQS OpenSSL command timed out: {' '.join(command)}"
            ) from error
        except subprocess.CalledProcessError as error:
            stderr = (error.stderr or "").strip()
            if "provider" in stderr.lower() or "unknown option" in stderr.lower():
                raise OQSUnavailableError(stderr or "OQS provider is unavailable.") from error
            if "config" in stderr.lower():
                raise OQSConfigError(stderr or "Generated OpenSSL config is invalid.") from error
            raise OQSSubprocessError(
                stderr or f"OQS command failed: {' '.join(command)}"
            ) from error

    def _detect_oqs_capability(self) -> _OqsCapability:
        if CertificateSigner._oqs_capability_cache is not None:
            return CertificateSigner._oqs_capability_cache
        if shutil.which(self.openssl_binary) is None:
            capability = _OqsCapability(False, "OpenSSL binary not found.")
            CertificateSigner._oqs_capability_cache = capability
            return capability

        commands = [
            ["list", "-signature-algorithms", "-provider", "oqsprovider", "-provider", "default"],
            ["list", "-signature-algorithms"],
        ]
        for args in commands:
            try:
                result = subprocess.run(
                    [self.openssl_binary, *args],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=_OPENSSL_TIMEOUT_SECONDS,
                    env=self._openssl_environment(),
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                continue
            combined_output = " ".join([result.stdout, result.stderr]).upper()
            if "ML-DSA" in combined_output or "DILITHIUM" in combined_output:
                capability = _OqsCapability(True, "ML-DSA signature algorithms detected.")
                CertificateSigner._oqs_capability_cache = capability
                return capability

        capability = _OqsCapability(False, "ML-DSA signature algorithms were not detected.")
        CertificateSigner._oqs_capability_cache = capability
        return capability

    def _openssl_environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        modules_dir = self.runtime_dir / "openssl-modules"
        if modules_dir.exists():
            environment.setdefault("OPENSSL_MODULES", str(modules_dir))
        elif Path("/usr/local/lib/ossl-modules").exists():
            environment.setdefault("OPENSSL_MODULES", "/usr/local/lib/ossl-modules")
        return environment

    def _render_issuer_openssl_config(self) -> str:
        issuer_subject = self._build_issuer_subject()
        return "\n".join(
            [
                "[ req ]",
                "distinguished_name = dn",
                "x509_extensions = v3_ca",
                "prompt = no",
                "",
                "[ dn ]",
                f"CN = {issuer_subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}",
                f"O = {issuer_subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value}",
                f"OU = {issuer_subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value}",
                "",
                "[ v3_ca ]",
                "basicConstraints = critical,CA:true",
                "keyUsage = critical,keyCertSign,cRLSign,digitalSignature",
                "subjectKeyIdentifier = hash",
                "authorityKeyIdentifier = keyid:always,issuer",
            ]
        )

    def _render_leaf_openssl_config(
        self,
        *,
        identity: _CertificateIdentity,
        extension_payload: dict[str, Any],
        ca_db: Path,
    ) -> str:
        san_name = "IP.1" if identity.san_is_ip else "DNS.1"
        lines = [
            "[ ca ]",
            "default_ca = CA_default",
            "",
            "[ CA_default ]",
            f"database = {ca_db / 'index.txt'}",
            f"serial = {ca_db / 'serial'}",
            f"new_certs_dir = {ca_db}",
            "default_md = sha384",
            f"private_key = {self.runtime_dir / 'issuer_mldsa_key.pem'}",
            f"certificate = {self.runtime_dir / 'issuer_mldsa_cert.pem'}",
            "policy = policy_any",
            "copy_extensions = none",
            "unique_subject = no",
            "",
            "[ policy_any ]",
            "commonName = supplied",
            "",
            "[ req ]",
            "distinguished_name = dn",
            "req_extensions = req_ext",
            "prompt = no",
            "",
            "[ dn ]",
            f"CN = {identity.common_name}",
            "",
            "[ req_ext ]",
            "subjectAltName = @alt_names",
            "",
            "[ alt_names ]",
            f"{san_name} = {identity.san_value}",
            "",
            "[ v3_leaf ]",
            "basicConstraints = critical,CA:false",
            "keyUsage = critical,digitalSignature,keyEncipherment",
            "extendedKeyUsage = serverAuth",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid,issuer",
            "subjectAltName = @alt_names",
        ]
        for key, oid in _OID_MAP.items():
            payload = extension_payload["oid_payloads"].get(key, "")
            if payload:
                lines.append(f"{oid} = ASN1:UTF8String:{payload}")
        return "\n".join(lines)

    def _apply_standard_extensions(
        self,
        certificate: x509.CertificateBuilder,
        *,
        identity: _CertificateIdentity,
    ) -> x509.CertificateBuilder:
        san = (
            x509.IPAddress(ipaddress.ip_address(identity.san_value))
            if identity.san_is_ip
            else x509.DNSName(identity.san_value)
        )
        return (
            certificate.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([san]),
                critical=False,
            )
        )

    def _apply_custom_extensions(
        self,
        *,
        certificate: x509.CertificateBuilder,
        extension_payload: dict[str, Any],
    ) -> x509.CertificateBuilder:
        builder = certificate
        for key, oid in _OID_MAP.items():
            payload = extension_payload["oid_payloads"].get(key, "")
            if not payload:
                continue
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(oid),
                    _encode_utf8_asn1(payload),
                ),
                critical=False,
            )
        return builder

    def _build_subject_name(self, identity: _CertificateIdentity) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity.common_name)])

    def _build_issuer_subject(self) -> x509.Name:
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, self.settings.CERT_ISSUER_COMMON_NAME),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, self.settings.CERT_ISSUER_ORGANIZATION
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, self.settings.CERT_ISSUER_ORG_UNIT
                ),
            ]
        )

    def _subject_string(self, identity: _CertificateIdentity) -> str:
        return f"/CN={identity.common_name}"

    def _issuer_subject_string(self) -> str:
        return (
            f"/CN={self.settings.CERT_ISSUER_COMMON_NAME}"
            f"/O={self.settings.CERT_ISSUER_ORGANIZATION}"
            f"/OU={self.settings.CERT_ISSUER_ORG_UNIT}"
        )


__all__ = ["CertificateSigner"]
