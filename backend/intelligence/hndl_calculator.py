"""
Deterministic HNDL break-year calculation for Phase 6.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from backend.analysis.constants import canonicalize_algorithm
from backend.models.certificate_chain import CertificateChain
from backend.models.crypto_assessment import CryptoAssessment

from .types import HndlTimelineEntry, HndlTimelineResult


QUBIT_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "RSA-2048": {
        "logical_qubits": 4000,
        "growth_rate": 400.0,
        "source": {
            "title": "Quantum Threat Reference",
            "section": "RSA-2048 logical qubit estimate",
            "path": "corpus/nist/roadmaps.txt",
        },
    },
    "ECDH-P256": {
        "logical_qubits": 2330,
        "growth_rate": 400.0,
        "source": {
            "title": "Quantum Threat Reference",
            "section": "ECDH-P256 logical qubit estimate",
            "path": "corpus/nist/roadmaps.txt",
        },
    },
    "RSA-4096": {
        "logical_qubits": 8000,
        "growth_rate": 400.0,
        "source": {
            "title": "Quantum Threat Reference",
            "section": "RSA-4096 logical qubit estimate",
            "path": "corpus/nist/roadmaps.txt",
        },
    },
}


class HndlCalculationError(RuntimeError):
    """Raised when HNDL computation cannot be completed safely."""


class HndlCalculator:
    """Deterministic HNDL calculator with bounded outputs."""

    _MIN_GROWTH_RATE = 1.0
    _MAX_BREAK_YEAR = 2100

    def __init__(
        self,
        *,
        current_year: int | None = None,
        qubit_requirements: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.current_year = current_year or datetime.now(UTC).year
        self.qubit_requirements = {
            key: dict(value) for key, value in (qubit_requirements or QUBIT_REQUIREMENTS).items()
        }

    def calculate(
        self,
        *,
        assessment: CryptoAssessment,
        cbom_document: Mapping[str, Any] | Any | None = None,
        certificates: Sequence[CertificateChain] = (),
    ) -> HndlTimelineResult:
        """Calculate deterministic break-year projections for classical algorithms."""
        targets = self._resolve_targets(
            assessment=assessment,
            cbom_document=cbom_document,
            certificates=certificates,
        )
        entries = tuple(self._build_entry(target) for target in targets)
        most_urgent = min(entries, key=lambda entry: entry.break_year, default=None)
        urgency = self._classify_urgency(most_urgent.break_year if most_urgent else None)
        citations = tuple(entry.source for entry in entries)
        return HndlTimelineResult(
            entries=entries,
            most_urgent_algorithm=most_urgent.algorithm if most_urgent else None,
            urgency=urgency,
            citations=citations,
        )

    def _resolve_targets(
        self,
        *,
        assessment: CryptoAssessment,
        cbom_document: Mapping[str, Any] | Any | None,
        certificates: Sequence[CertificateChain],
    ) -> tuple[str, ...]:
        targets: list[str] = []
        normalized_kex = canonicalize_algorithm("kex", assessment.kex_algorithm)
        normalized_sig = canonicalize_algorithm("sig", assessment.auth_algorithm)
        key_size = self._resolve_rsa_key_size(
            cbom_document=cbom_document,
            certificates=certificates,
        )

        if normalized_kex in {"ECDHE", "ECDH", "X25519", "X25519_MLKEM768"}:
            targets.append("ECDH-P256")
        if normalized_kex == "RSA":
            targets.append(self._rsa_algorithm_from_key_size(key_size))
        if normalized_sig == "RSA":
            targets.append(self._rsa_algorithm_from_key_size(key_size))

        return tuple(dict.fromkeys(targets))

    def _build_entry(self, algorithm: str) -> HndlTimelineEntry:
        if algorithm not in self.qubit_requirements:
            raise HndlCalculationError(f"Unsupported HNDL algorithm target: {algorithm}")

        requirement = self.qubit_requirements[algorithm]
        growth_rate = max(
            float(requirement.get("growth_rate", self._MIN_GROWTH_RATE)),
            self._MIN_GROWTH_RATE,
        )
        break_year = min(
            self._MAX_BREAK_YEAR,
            round(self.current_year + (int(requirement["logical_qubits"]) / growth_rate)),
        )
        return HndlTimelineEntry(
            algorithm=algorithm,
            logical_qubits=int(requirement["logical_qubits"]),
            projected_growth_rate=growth_rate,
            break_year=break_year,
            source=dict(requirement.get("source", {})),
        )

    @classmethod
    def _classify_urgency(cls, earliest_break_year: int | None) -> str:
        if earliest_break_year is None:
            return "LOW"
        if earliest_break_year <= 2030:
            return "CRITICAL"
        if earliest_break_year <= 2035:
            return "HIGH"
        if earliest_break_year <= 2045:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _rsa_algorithm_from_key_size(key_size_bits: int | None) -> str:
        return "RSA-4096" if key_size_bits and key_size_bits >= 4096 else "RSA-2048"

    @staticmethod
    def _resolve_rsa_key_size(
        *,
        cbom_document: Mapping[str, Any] | Any | None,
        certificates: Sequence[CertificateChain],
    ) -> int | None:
        for certificate in certificates:
            if certificate.key_size_bits:
                return certificate.key_size_bits

        if cbom_document is None:
            return None

        payload: Mapping[str, Any] | None
        if hasattr(cbom_document, "cbom_json"):
            payload = getattr(cbom_document, "cbom_json")
        elif isinstance(cbom_document, Mapping):
            payload = cbom_document
        else:
            payload = None

        if not payload:
            return None

        try:
            return payload["components"][0]["cryptoProperties"]["certificateProperties"][
                "subjectPublicKeySize"
            ]
        except (KeyError, IndexError, TypeError):
            return None
