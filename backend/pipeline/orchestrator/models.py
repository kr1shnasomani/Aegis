"""
Pipeline runtime models, state containers, and constants.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from backend.models.enums import ScanStatus
from backend.discovery.types import AggregatedAsset, PortFinding, ValidatedHostname, TLSProbeResult


MAX_SCAN_RUNTIME_EVENTS = 60
RUNTIME_EVENT_DEDUP_WINDOW_SECONDS = 90
ETA_STAGE_WEIGHTS_SECONDS: dict[str, float] = {
    "queued": 1.0,
    "preparing_scan": 2.0,
    "enumerating_domains": 8.0,
    "validating_dns": 5.0,
    "scanning_ports": 12.0,
    "probing_tls": 18.0,
    "persisting_assets": 6.0,
    "completed": 0.0,
    "failed": 0.0,
}
ETA_STAGE_ORDER: tuple[str, ...] = (
    "queued",
    "preparing_scan",
    "enumerating_domains",
    "validating_dns",
    "scanning_ports",
    "probing_tls",
    "persisting_assets",
    "completed",
)
COMMON_ENUMERATION_PREFIXES: tuple[str, ...] = (
    "www",
    "api",
    "auth",
    "login",
    "sso",
    "portal",
    "secure",
    "vpn",
    "mail",
    "smtp",
    "imap",
    "pop",
    "m",
    "mobile",
    "cdn",
    "static",
    "assets",
    "img",
    "media",
    "status",
    "support",
    "admin",
    "dev",
    "test",
    "staging",
    "beta",
)


@dataclass(frozen=True, slots=True)
class _DiscoveryExecution:
    aggregated_assets: tuple[AggregatedAsset, ...]
    port_findings: tuple[PortFinding, ...]
    validated_hostnames: tuple[ValidatedHostname, ...]
    tls_results_by_key: dict[tuple[str | None, str, int, str, str], TLSProbeResult]


@dataclass(frozen=True, slots=True)
class _AssessmentInputs:
    tls_version: str | None
    cipher_suite: str | None
    kex_algorithm: str | None
    auth_algorithm: str | None
    enc_algorithm: str | None
    mac_algorithm: str | None
    kex_vulnerability: float | None
    sig_vulnerability: float | None
    sym_vulnerability: float | None
    tls_vulnerability: float | None
    risk_score: float | None
    score_explanation: dict[str, Any] | None


@dataclass(slots=True)
class ScanRuntimeEvent:
    timestamp: datetime
    kind: str
    message: str
    stage: str | None = None


@dataclass(slots=True)
class ScanRuntimeState:
    scan_id: uuid.UUID
    target: str
    created_at: datetime | None = None
    stage: str | None = None
    stage_detail: str | None = None
    stage_started_at: datetime | None = None
    degraded_modes: list[str] = field(default_factory=list)
    events: list[ScanRuntimeEvent] = field(default_factory=list)


class ScanRuntimeStore:
    """In-process telemetry for active and recently completed scans."""

    def __init__(self) -> None:
        self._states: dict[uuid.UUID, ScanRuntimeState] = {}

    def register_scan(
        self,
        *,
        scan_id: uuid.UUID,
        target: str,
        created_at: datetime | None = None,
    ) -> None:
        state = self._states.get(scan_id)
        is_new_state = state is None
        if state is None:
            state = ScanRuntimeState(scan_id=scan_id, target=target, created_at=created_at)
            self._states[scan_id] = state
        else:
            state.target = target
            state.created_at = created_at or state.created_at
        state.stage = "queued"
        state.stage_detail = target
        state.stage_started_at = datetime.now(UTC)

        if is_new_state or not state.events:
            self.add_event(
                scan_id,
                "Scan accepted and queued for execution.",
                kind="queued",
                stage="queued",
            )

    def set_stage(
        self,
        scan_id: uuid.UUID,
        *,
        stage: str,
        detail: str | None = None,
        message: str | None = None,
    ) -> None:
        state = self._states.get(scan_id)
        if state is None:
            return
        state.stage = stage
        state.stage_detail = detail
        state.stage_started_at = datetime.now(UTC)
        if message:
            self.add_event(scan_id, message, kind="stage", stage=stage)

    def add_event(
        self,
        scan_id: uuid.UUID,
        message: str,
        *,
        kind: str = "info",
        stage: str | None = None,
    ) -> None:
        state = self._states.get(scan_id)
        if state is None:
            return
        now = datetime.now(UTC)
        if state.events:
            latest = state.events[-1]
            if (
                latest.kind == kind
                and latest.stage == (stage or state.stage)
                and latest.message == message
                and (now - latest.timestamp).total_seconds() <= RUNTIME_EVENT_DEDUP_WINDOW_SECONDS
            ):
                return
        state.events.append(
            ScanRuntimeEvent(
                timestamp=now,
                kind=kind,
                message=message,
                stage=stage or state.stage,
            )
        )
        if len(state.events) > MAX_SCAN_RUNTIME_EVENTS:
            del state.events[:-MAX_SCAN_RUNTIME_EVENTS]

    def add_degraded_mode(self, scan_id: uuid.UUID, message: str) -> None:
        state = self._states.get(scan_id)
        if state is None:
            return
        if message not in state.degraded_modes:
            state.degraded_modes.append(message)
        self.add_event(scan_id, message, kind="degraded")

    def mark_terminal(
        self,
        scan_id: uuid.UUID,
        *,
        status: ScanStatus,
        message: str,
    ) -> None:
        self.set_stage(scan_id, stage=status.value, message=message)

    def get_snapshot(self, scan_id: uuid.UUID) -> ScanRuntimeState | None:
        return self._states.get(scan_id)

    def remove_scan(self, scan_id: uuid.UUID) -> None:
        self._states.pop(scan_id, None)

