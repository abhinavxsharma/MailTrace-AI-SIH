"""
MAILTRACE AI — DNS Intelligence Resolver.

Performs robust, time-bounded DNS queries for threat intelligence enrichment.
Handles NXDOMAIN, timeouts, SERVFAIL, missing records, and malformed domains.
Operates strictly in memory with TTL caching and mockable resolution.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

from intelligence.cache import InMemoryTtlCache
from intelligence.dns.models import DnsIntelligenceResult, DnsRecordResult

# Common DNS record types supported for intelligence enrichment
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

# Basic domain syntax regex per RFC 1035
_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


class DnsIntelligenceResolver:
    """
    DNS resolver for threat intelligence enrichment.

    Attributes:
        timeout: Query timeout in seconds (default 3.0).
        nameservers: Optional list of custom DNS server IPs.
        cache: Optional InMemoryTtlCache instance.
    """

    def __init__(
        self,
        timeout: float = 3.0,
        nameservers: list[str] | None = None,
        cache: InMemoryTtlCache[DnsRecordResult] | None = None,
        mock_query_func: Callable[[str, str], list[str]] | None = None,
    ):
        self.timeout = timeout
        self.nameservers = nameservers
        self.cache = cache or InMemoryTtlCache[DnsRecordResult](ttl_seconds=300)
        self.mock_query_func = mock_query_func

    def resolve_record(self, domain: str, record_type: str) -> DnsRecordResult:
        """
        Resolve a specific DNS record type for a domain.

        Args:
            domain: Domain name string.
            record_type: Record type (A, AAAA, MX, NS, TXT, CNAME).

        Returns:
            ``DnsRecordResult`` with status and resolved values.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        rec_type = record_type.strip().upper()

        if rec_type not in DEFAULT_RECORD_TYPES:
            return DnsRecordResult(
                domain=domain,
                record_type=rec_type,
                status="MALFORMED",
                error=f"Unsupported or malformed record type: {rec_type!r}",
                evidence={"raw_domain": domain},
            )

        # Check domain syntax
        if not clean_domain or not _DOMAIN_REGEX.match(clean_domain):
            return DnsRecordResult(
                domain=domain,
                record_type=rec_type,
                status="MALFORMED",
                error=f"Malformed or invalid domain name: {domain!r}",
                evidence={"raw_domain": domain},
            )

        # Check cache
        cache_key = f"{rec_type}:{clean_domain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        # Use mock query function if injected (for unit tests)
        if self.mock_query_func:
            start_t = time.perf_counter()
            try:
                values = self.mock_query_func(clean_domain, rec_type)
                latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
                status = "NOERROR" if values else "NO_RECORDS"
                res = DnsRecordResult(
                    domain=clean_domain,
                    record_type=rec_type,
                    values=values,
                    resolver="mock",
                    status=status,
                    evidence={"latency_ms": latency_ms},
                )
                self.cache.set(cache_key, res)
                return res
            except Exception as exc:
                exc_name = type(exc).__name__
                if "NXDOMAIN" in exc_name:
                    status = "NXDOMAIN"
                elif "Timeout" in exc_name:
                    status = "TIMEOUT"
                elif "NoNameservers" in exc_name or "SERVFAIL" in exc_name:
                    status = "SERVFAIL"
                elif "NoAnswer" in exc_name:
                    status = "NO_RECORDS"
                else:
                    status = "ERROR"
                return DnsRecordResult(
                    domain=clean_domain,
                    record_type=rec_type,
                    status=status,
                    error=str(exc) or exc_name,
                    resolver="mock",
                )

        # Real DNS resolution via dnspython
        start_t = time.perf_counter()
        try:
            import dns.exception
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            resolver.timeout = self.timeout
            if self.nameservers:
                resolver.nameservers = self.nameservers

            answers = resolver.resolve(clean_domain, rec_type)
            values: list[str] = []

            for rdata in answers:
                if rec_type == "TXT":
                    val = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
                elif rec_type == "MX":
                    val = f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
                elif rec_type in ("NS", "CNAME"):
                    val = str(rdata.target).rstrip(".")
                else:
                    val = str(rdata).strip()
                values.append(val)

            latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
            result = DnsRecordResult(
                domain=clean_domain,
                record_type=rec_type,
                values=values,
                resolver=",".join(resolver.nameservers) if self.nameservers else "system",
                status="NOERROR" if values else "NO_RECORDS",
                evidence={"latency_ms": latency_ms},
            )

        except dns.resolver.NXDOMAIN:
            result = DnsRecordResult(
                domain=clean_domain,
                record_type=rec_type,
                status="NXDOMAIN",
                error=f"Domain does not exist: {clean_domain}",
            )
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            result = DnsRecordResult(
                domain=clean_domain,
                record_type=rec_type,
                status="NO_RECORDS",
                error=f"No {rec_type} records found for {clean_domain}",
            )
        except (dns.resolver.Timeout, dns.exception.Timeout):
            result = DnsRecordResult(
                domain=clean_domain,
                record_type=rec_type,
                status="TIMEOUT",
                error=f"DNS query timed out after {self.timeout}s",
            )
        except Exception as exc:  # noqa: BLE001
            result = DnsRecordResult(
                domain=clean_domain,
                record_type=rec_type,
                status="ERROR",
                error=f"DNS resolution error: {exc}",
            )

        self.cache.set(cache_key, result)
        return result

    def resolve_domain(
        self,
        domain: str,
        record_types: list[str] | None = None,
    ) -> DnsIntelligenceResult:
        """
        Query standard DNS records for a domain and aggregate results.

        Args:
            domain: Domain name string.
            record_types: Optional list of record types to query.

        Returns:
            ``DnsIntelligenceResult`` containing all resolved records.
        """
        types_to_query = record_types or DEFAULT_RECORD_TYPES
        records: dict[str, DnsRecordResult] = {}

        for r_type in types_to_query:
            records[r_type] = self.resolve_record(domain, r_type)

        a_records = records.get("A", DnsRecordResult(domain=domain, record_type="A", status="NO_RECORDS")).values
        aaaa_records = records.get("AAAA", DnsRecordResult(domain=domain, record_type="AAAA", status="NO_RECORDS")).values
        mx_records = records.get("MX", DnsRecordResult(domain=domain, record_type="MX", status="NO_RECORDS")).values
        ns_records = records.get("NS", DnsRecordResult(domain=domain, record_type="NS", status="NO_RECORDS")).values
        txt_records = records.get("TXT", DnsRecordResult(domain=domain, record_type="TXT", status="NO_RECORDS")).values
        cname_records = records.get("CNAME", DnsRecordResult(domain=domain, record_type="CNAME", status="NO_RECORDS")).values

        # Overall domain status
        statuses = [r.status for r in records.values()]
        if all(s == "NXDOMAIN" for s in statuses):
            overall_status = "NXDOMAIN"
        elif any(s == "TIMEOUT" for s in statuses):
            overall_status = "TIMEOUT"
        elif any(s == "MALFORMED" for s in statuses):
            overall_status = "MALFORMED"
        elif any(s == "NOERROR" for s in statuses):
            overall_status = "NOERROR"
        else:
            overall_status = "NO_RECORDS"

        return DnsIntelligenceResult(
            domain=domain.strip().lower().rstrip("."),
            records=records,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            cname_records=cname_records,
            status=overall_status,
            evidence={"queried_types": types_to_query},
        )
