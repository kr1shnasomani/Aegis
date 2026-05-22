"""
DiscoveryMixin — DNS enumeration, port scanning, and TLS probing phases.

These methods are mixed into PipelineOrchestrator via inheritance.
They cover:
  - _run_discovery / _run_discovery_streaming
  - _resolve_hostnames
  - _scan_ports / _scan_host_with_profile
  - _probe_tls_targets / _probe_tls_fallback_without_port_findings
  - _build_ip_hostname_index
  - Profile/scope helper statics
"""

from __future__ import annotations

import asyncio
import logging
import os
import ipaddress
import socket
import uuid
from collections import defaultdict
from typing import Sequence, TYPE_CHECKING

from backend.discovery import (
    AuthorizedScope,
    PortFinding,
    TLSProbeResult,
    TLSScanTarget,
    ValidatedHostname,
    URLProbeTarget,
    aggregate_assets,
)
from backend.discovery.dns_enumerator import DNSEnumerationError
from backend.models.enums import ServiceType
from backend.repositories import DNSRecordRepository

from .models import _DiscoveryExecution, COMMON_ENUMERATION_PREFIXES
from .serializers import _artifact_key_from_tls_result

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class DiscoveryMixin:
    """Discovery phase helpers — mixed into PipelineOrchestrator."""

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
        if not probe_tasks:
            return []
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

