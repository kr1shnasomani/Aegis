"""
PersistenceMixin — asset persistence and external enrichment helpers.

These methods are mixed into PipelineOrchestrator via inheritance.
They cover:
  - _persist_discovered_assets
  - _build_asset_metadata
  - _enrich_ip / _enrich_domain
  - _lookup_domain_rdap / _parse_rdap_payload / _extract_rdap_entity_name
  - _normalize_rdap_date
  - _safe_reverse_dns
  - _lookup_asn_cymru / _lookup_ip_geolocation
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import uuid
from datetime import datetime
from typing import Any, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from backend.discovery import AggregatedAsset, PortFinding, ValidatedHostname
from backend.models.discovered_asset import DiscoveredAsset
from backend.repositories import (
    DiscoveredAssetRepository,
)

logger = logging.getLogger(__name__)


class PersistenceMixin:
    """Asset persistence and enrichment helpers — mixed into PipelineOrchestrator."""

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

