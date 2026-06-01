"""
Certificate issuance exceptions.
"""

from __future__ import annotations


class CertificateIssuanceError(RuntimeError):
    """Raised when certificate issuance cannot complete."""


class ComplianceTierMismatchError(CertificateIssuanceError):
    """Raised when stored and recomputed tiers disagree."""


class OQSUnavailableError(CertificateIssuanceError):
    """Raised when the OQS OpenSSL toolchain is unavailable."""


class OQSSubprocessError(CertificateIssuanceError):
    """Raised when an OQS subprocess invocation fails."""


class OQSConfigError(CertificateIssuanceError):
    """Raised when generated OQS configuration is invalid."""
