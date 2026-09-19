"""
MAILTRACE AI — RDAP Client.

Queries RDAP (Registration Data Access Protocol) for domain and IP registration,
network assignment, and registrar data. Operates with configurable timeouts,
in-memory caching, structured parsing, and mockable transport.
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Callable

import httpx

from intelligence.cache import InMemoryTtlCache
from intelligence.rdap.models import RdapQueryType, RdapResult, RdapStatus

_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


class RdapClient:
    """
    Client for querying RDAP services for domains and IP addresses.

    Attributes:
        base_url: Base URL for RDAP service (default: https://rdap.org).
        timeout: Query timeout in seconds.
        cache: Optional InMemoryTtlCache for caching lookups.
        mock_fetch_func: Optional callback for offline testing.
            Signature: (url: str) -> tuple[int, dict[str, Any] | str]
    """

    def __init__(
        self,
        base_url: str = "https://rdap.org",
        timeout: float = 3.0,
        cache: InMemoryTtlCache[RdapResult] | None = None,
        mock_fetch_func: Callable[[str], tuple[int, dict[str, Any] | str]] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache = cache or InMemoryTtlCache[RdapResult](ttl_seconds=3600)
        self.mock_fetch_func = mock_fetch_func

    def lookup_domain(self, domain: str) -> RdapResult:
        """
        Query RDAP for domain registration information.

        Args:
            domain: Domain name to query.

        Returns:
            ``RdapResult`` containing structured registration details.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain or not _DOMAIN_REGEX.match(clean_domain):
            return RdapResult(
                query=domain,
                query_type="domain",
                status="MALFORMED",
                error=f"Malformed or invalid domain name: {domain!r}",
                evidence={"reason": "regex_validation_failed"},
            )

        cache_key = f"domain:{clean_domain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        url = f"{self.base_url}/domain/{clean_domain}"
        result = self._query_rdap(url, query=clean_domain, query_type="domain")
        self.cache.set(cache_key, result)
        return result

    def lookup_ip(self, ip_str: str) -> RdapResult:
        """
        Query RDAP for IP address network and assignment information.

        Args:
            ip_str: IPv4 or IPv6 address string.

        Returns:
            ``RdapResult`` containing network/CIDR and entity details.
        """
        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return RdapResult(
                query=ip_str,
                query_type="ip",
                status="MALFORMED",
                error=f"Invalid IP address format: {ip_str!r}",
                evidence={"reason": "invalid_ip_format"},
            )

        # Do not query public RDAP for private/reserved IPs
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return RdapResult(
                query=clean_ip,
                query_type="ip",
                status="OK",
                organization="Private / Reserved Network",
                network_cidr=str(ipaddress.ip_network(f"{clean_ip}/32" if ip_obj.version == 4 else f"{clean_ip}/128")),
                source="rfc1918_filter",
                evidence={"is_private": True, "ip_version": ip_obj.version},
            )

        cache_key = f"ip:{clean_ip}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        url = f"{self.base_url}/ip/{clean_ip}"
        result = self._query_rdap(url, query=clean_ip, query_type="ip")
        self.cache.set(cache_key, result)
        return result

    def _query_rdap(
        self,
        url: str,
        query: str,
        query_type: RdapQueryType,
    ) -> RdapResult:
        """Execute the HTTP query or invoke mock handler."""
        start_time = time.monotonic()
        try:
            if self.mock_fetch_func is not None:
                status_code, body = self.mock_fetch_func(url)
                duration_ms = round((time.monotonic() - start_time) * 1000, 2)
                if isinstance(body, str):
                    import json
                    try:
                        data = json.loads(body)
                    except Exception as parse_err:
                        return RdapResult(
                            query=query,
                            query_type=query_type,
                            status="MALFORMED",
                            error=f"Malformed JSON response: {parse_err}",
                            evidence={"duration_ms": duration_ms, "url": url},
                        )
                else:
                    data = body
            else:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    resp = client.get(
                        url,
                        headers={"Accept": "application/rdap+json, application/json"},
                    )
                    status_code = resp.status_code
                    duration_ms = round((time.monotonic() - start_time) * 1000, 2)
                    if status_code == 404:
                        return RdapResult(
                            query=query,
                            query_type=query_type,
                            status="NOT_FOUND",
                            error="RDAP record not found (HTTP 404)",
                            evidence={"status_code": 404, "duration_ms": duration_ms, "url": url},
                        )
                    if status_code != 200:
                        return RdapResult(
                            query=query,
                            query_type=query_type,
                            status="ERROR",
                            error=f"RDAP query failed with HTTP {status_code}",
                            evidence={"status_code": status_code, "duration_ms": duration_ms, "url": url},
                        )
                    try:
                        data = resp.json()
                    except Exception as json_err:
                        return RdapResult(
                            query=query,
                            query_type=query_type,
                            status="MALFORMED",
                            error=f"Failed to parse JSON response: {json_err}",
                            evidence={"status_code": status_code, "duration_ms": duration_ms, "url": url},
                        )

            if status_code == 404:
                return RdapResult(
                    query=query,
                    query_type=query_type,
                    status="NOT_FOUND",
                    error="RDAP record not found (HTTP 404)",
                    evidence={"status_code": 404, "duration_ms": duration_ms, "url": url},
                )
            if status_code != 200:
                return RdapResult(
                    query=query,
                    query_type=query_type,
                    status="ERROR",
                    error=f"RDAP query failed with HTTP {status_code}",
                    evidence={"status_code": status_code, "duration_ms": duration_ms, "url": url},
                )

            return self._parse_rdap_response(data, query=query, query_type=query_type, duration_ms=duration_ms, url=url)

        except (httpx.TimeoutException, TimeoutError):
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            return RdapResult(
                query=query,
                query_type=query_type,
                status="TIMEOUT",
                error=f"RDAP query timed out after {self.timeout}s",
                evidence={"duration_ms": duration_ms, "url": url},
            )
        except Exception as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            return RdapResult(
                query=query,
                query_type=query_type,
                status="ERROR",
                error=f"RDAP query error: {type(exc).__name__}: {exc}",
                evidence={"duration_ms": duration_ms, "url": url},
            )

    def _parse_rdap_response(
        self,
        data: dict[str, Any],
        query: str,
        query_type: RdapQueryType,
        duration_ms: float,
        url: str,
    ) -> RdapResult:
        """Extract structured fields from RDAP JSON schema."""
        if not isinstance(data, dict):
            return RdapResult(
                query=query,
                query_type=query_type,
                status="MALFORMED",
                error="RDAP response is not a JSON object",
                evidence={"duration_ms": duration_ms, "url": url},
            )

        registrar = None
        organization = None
        country = data.get("country")
        reg_date = None
        exp_date = None
        last_changed = None
        nameservers: list[str] = []
        network_cidr = None
        asn = None

        # Extract dates from events
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction", "").lower()
            date = event.get("eventDate")
            if action in ("registration", "transfer") and not reg_date:
                reg_date = date
            elif action == "expiration" and not exp_date:
                exp_date = date
            elif action in ("last changed", "last update", "last modified") and not last_changed:
                last_changed = date

        # Extract entities (registrar, organization, registrant)
        for entity in data.get("entities", []):
            if not isinstance(entity, dict):
                continue
            roles = [r.lower() for r in entity.get("roles", [])]
            entity_name = self._extract_vcard_fn_or_org(entity)
            if "registrar" in roles and not registrar:
                registrar = entity_name or entity.get("handle")
            if any(r in roles for r in ("registrant", "technical", "administrative")) and not organization:
                organization = entity_name

        # Extract nameservers
        for ns in data.get("nameservers", []):
            if isinstance(ns, dict):
                ns_name = ns.get("ldhName") or ns.get("handle")
                if ns_name and ns_name not in nameservers:
                    nameservers.append(ns_name)

        # Extract CIDR / network info for IP
        if query_type == "ip":
            # Check cidr0_cidrs
            cidrs = data.get("cidr0_cidrs", [])
            if cidrs and isinstance(cidrs, list) and isinstance(cidrs[0], dict):
                v4_prefix = cidrs[0].get("v4prefix")
                v6_prefix = cidrs[0].get("v6prefix")
                length = cidrs[0].get("length")
                prefix = v4_prefix or v6_prefix
                if prefix is not None and length is not None:
                    network_cidr = f"{prefix}/{length}"

            if not network_cidr:
                start_addr = data.get("startAddress")
                end_addr = data.get("endAddress")
                if start_addr and end_addr:
                    network_cidr = f"{start_addr} - {end_addr}"

            # Look for ASN in autnums or remarks
            autnums = data.get("autnums", [])
            if autnums and isinstance(autnums, list):
                asn = str(autnums[0])

        return RdapResult(
            query=query,
            query_type=query_type,
            status="OK",
            registrar=registrar,
            organization=organization,
            country=country,
            registration_date=reg_date,
            expiration_date=exp_date,
            last_changed_date=last_changed,
            nameservers=nameservers,
            network_cidr=network_cidr,
            asn=asn,
            source=self.base_url,
            raw_data={
                "handle": data.get("handle"),
                "ldhName": data.get("ldhName"),
                "status": data.get("status"),
            },
            evidence={
                "duration_ms": duration_ms,
                "url": url,
            },
        )

    @staticmethod
    def _extract_vcard_fn_or_org(entity: dict[str, Any]) -> str | None:
        """Extract fn or org string from vcardArray if present."""
        vcard = entity.get("vcardArray")
        if not vcard or not isinstance(vcard, list) or len(vcard) < 2:
            return None
        properties = vcard[1]
        if not isinstance(properties, list):
            return None

        fn_val = None
        org_val = None
        for item in properties:
            if isinstance(item, list) and len(item) >= 4:
                prop_name = str(item[0]).lower()
                val = item[3]
                if prop_name == "fn" and isinstance(val, str):
                    fn_val = val.strip()
                elif prop_name == "org" and isinstance(val, str):
                    org_val = val.strip()

        return org_val or fn_val
