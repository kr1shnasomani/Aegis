"""
Certificate data models (request/response shapes and internal identity types).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.models.crypto_assessment import CryptoAssessment
    from backend.models.discovered_asset import DiscoveredAsset
    from backend.models.remediation_bundle import RemediationBundle


@dataclass(frozen=True, slots=True)
class CertificateRequest:
    """Input bundle required to issue one compliance certificate."""

    asset: DiscoveredAsset
    assessment: CryptoAssessment
    remediation_bundle: RemediationBundle | None = None


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    """Issued certificate metadata returned by the signer."""

    certificate_pem: str
    signing_algorithm: str
    valid_from: datetime
    valid_until: datetime
    extensions_json: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _CertificateIdentity:
    common_name: str
    san_value: str
    san_is_ip: bool


@dataclass(frozen=True, slots=True)
class _OqsCapability:
    available: bool
    reason: str
