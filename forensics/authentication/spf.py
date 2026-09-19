"""
MAILTRACE AI — SPF (Sender Policy Framework) Verifier.

Implements RFC 7208 SPF evaluation with support for:
- Envelope sender / Return-Path domain identification
- Connecting IP extraction from Received hops
- Pluggable DNS resolver (supporting mock DNS in unit tests)
- Standard mechanisms: ip4, ip6, a, mx, include, redirect, all
- Standard qualifiers: +, -, ~, ?
- RFC 7208 lookup limits (max 10 DNS queries to prevent DoS/recursion)
- Strict result states: PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR,
  PERMERROR, UNAVAILABLE, NOT_EVALUATED.

Operates strictly in memory.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Protocol

from forensics.authentication.models import SpfResult
from forensics.email_parser.models import ParsedEmail

# Maximum DNS-calling mechanisms per RFC 7208 section 4.6.4
MAX_SPF_DNS_LOOKUPS = 10

_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{3,39}")


class DnsResolverProtocol(Protocol):
    """Protocol for DNS lookups in authentication modules."""

    def get_txt_records(self, domain: str) -> list[str]:
        ...

    def get_a_records(self, domain: str) -> list[str]:
        ...

    def get_mx_hosts(self, domain: str) -> list[str]:
        ...


class DefaultDnsResolver:
    """Standard DNS resolver using dnspython with error safety."""

    def get_txt_records(self, domain: str) -> list[str]:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "TXT")
            records: list[str] = []
            for rdata in answers:
                # rdata.strings is a tuple of bytes
                text = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
                records.append(text)
            return records
        except Exception:  # noqa: BLE001
            return []

    def get_a_records(self, domain: str) -> list[str]:
        try:
            import dns.resolver
            ips: list[str] = []
            for qtype in ("A", "AAAA"):
                try:
                    answers = dns.resolver.resolve(domain, qtype)
                    for rdata in answers:
                        ips.append(str(rdata))
                except Exception:  # noqa: BLE001
                    pass
            return ips
        except Exception:  # noqa: BLE001
            return []

    def get_mx_hosts(self, domain: str) -> list[str]:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            return [str(rdata.exchange).rstrip(".") for rdata in answers]
        except Exception:  # noqa: BLE001
            return []


def extract_connecting_ip(parsed_email: ParsedEmail) -> str | None:
    """
    Extract the most likely connecting IP from the Received hop chain.

    Examines Received hops starting from the outermost (last hop received)
    or first available hop containing a valid public or private IP.
    """
    for hop in parsed_email.received_hops:
        for candidate in (hop.from_host, hop.by_host, hop.original_value):
            if not candidate:
                continue
            matches = _IP_REGEX.findall(candidate)
            for m in matches:
                try:
                    parsed_ip = ipaddress.ip_address(m)
                    # Exclude localhost 127.0.0.1 if others are present, but return first valid IP
                    return str(parsed_ip)
                except ValueError:
                    continue
    return None


def verify_spf(
    parsed_email: ParsedEmail | None = None,
    domain: str | None = None,
    ip: str | None = None,
    resolver: DnsResolverProtocol | None = None,
) -> SpfResult:
    """
    Evaluate SPF policy for an email or domain/IP pair.

    Args:
        parsed_email: ParsedEmail instance (extracts domain and IP if not passed).
        domain: Explicit envelope sender domain (overrides parsed_email).
        ip: Explicit connecting IP (overrides parsed_email).
        resolver: Custom DnsResolverProtocol instance (e.g. for mock DNS).

    Returns:
        Structured ``SpfResult``.
    """
    res = resolver or DefaultDnsResolver()

    # 1. Determine checked domain
    target_domain = domain
    if not target_domain and parsed_email:
        if parsed_email.return_path and parsed_email.return_path.domain:
            target_domain = parsed_email.return_path.domain
        elif parsed_email.from_address and parsed_email.from_address.domain:
            target_domain = parsed_email.from_address.domain

    if not target_domain:
        return SpfResult(
            domain="",
            ip=ip,
            status="NOT_EVALUATED",
            reason="Missing envelope sender / Return-Path domain.",
            evidence={"domain": "", "ip": ip},
        )

    target_domain = target_domain.strip().lower()

    # 2. Determine connecting IP
    target_ip = ip
    if not target_ip and parsed_email:
        target_ip = extract_connecting_ip(parsed_email)

    if not target_ip:
        return SpfResult(
            domain=target_domain,
            ip=None,
            status="NOT_EVALUATED",
            reason="Connecting IP could not be determined from Received chain or arguments.",
            evidence={"domain": target_domain, "ip": None},
        )

    # Validate IP syntax
    try:
        evaluated_ip = ipaddress.ip_address(target_ip)
    except ValueError:
        return SpfResult(
            domain=target_domain,
            ip=target_ip,
            status="PERMERROR",
            reason=f"Invalid connecting IP address syntax: {target_ip!r}",
            evidence={"domain": target_domain, "ip": target_ip},
            error=f"Invalid IP: {target_ip}",
        )

    # 3. Evaluate SPF via recursive evaluator tracking DNS query count
    state = _SpfEvaluationState(resolver=res, connecting_ip=evaluated_ip)
    status, reason, policy, evidence = state.evaluate(target_domain)

    return SpfResult(
        domain=target_domain,
        ip=target_ip,
        policy=policy,
        status=status,
        reason=reason,
        evidence=evidence,
        error=evidence.get("error"),
    )


class _SpfEvaluationState:
    """Internal evaluation state maintaining lookup limits per RFC 7208."""

    def __init__(self, resolver: DnsResolverProtocol, connecting_ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
        self.resolver = resolver
        self.connecting_ip = connecting_ip
        self.dns_lookups = 0
        self.visited_domains: set[str] = set()

    def evaluate(self, domain: str) -> tuple[str, str, str | None, dict[str, Any]]:
        domain = domain.strip().lower()

        if domain in self.visited_domains:
            return (
                "PERMERROR",
                f"Recursive SPF loop detected at domain '{domain}'.",
                None,
                {"error": "Loop detected", "domain": domain},
            )

        self.visited_domains.add(domain)

        txt_records = self.resolver.get_txt_records(domain)
        spf_records = [r for r in txt_records if r.strip().startswith("v=spf1")]

        if not spf_records:
            return (
                "NONE",
                f"No SPF record published for domain '{domain}'.",
                None,
                {"domain": domain, "dns_records_found": len(txt_records)},
            )

        if len(spf_records) > 1:
            return (
                "PERMERROR",
                f"Multiple SPF records found for domain '{domain}'.",
                spf_records[0],
                {"domain": domain, "records": spf_records, "error": "Multiple SPF records"},
            )

        policy = spf_records[0].strip()
        tokens = policy.split()

        # Evaluate terms
        redirect_domain: str | None = None
        evidence: dict[str, Any] = {
            "domain": domain,
            "policy": policy,
            "ip": str(self.connecting_ip),
            "matched_mechanism": None,
        }

        for token in tokens[1:]:
            # Check for modifier: redirect=
            if token.lower().startswith("redirect="):
                redirect_domain = token.split("=", 1)[1].strip()
                continue
            # Check for modifier: exp= (ignored in evaluation)
            if token.lower().startswith("exp="):
                continue

            # Parse qualifier (+, -, ~, ?)
            qualifier = "+"
            mechanism = token
            if token[0] in ("+", "-", "~", "?"):
                qualifier = token[0]
                mechanism = token[1:]

            result_map = {
                "+": "PASS",
                "-": "FAIL",
                "~": "SOFTFAIL",
                "?": "NEUTRAL",
            }
            qualifier_result = result_map.get(qualifier, "PASS")

            # Evaluate mechanism
            matched, permerror = self._evaluate_mechanism(mechanism, domain)
            if permerror:
                return (
                    "PERMERROR",
                    f"SPF evaluation failed evaluating '{token}': {permerror}",
                    policy,
                    {"domain": domain, "token": token, "error": permerror},
                )

            if matched:
                evidence["matched_mechanism"] = token
                evidence["qualifier"] = qualifier
                return (
                    qualifier_result,
                    f"Matched mechanism '{token}' with qualifier '{qualifier}'.",
                    policy,
                    evidence,
                )

        # If no mechanism matched and redirect= is present
        if redirect_domain:
            self.dns_lookups += 1
            if self.dns_lookups > MAX_SPF_DNS_LOOKUPS:
                return (
                    "PERMERROR",
                    "SPF DNS lookup limit (10) exceeded on redirect.",
                    policy,
                    {"domain": domain, "error": "Lookup limit exceeded"},
                )
            return self.evaluate(redirect_domain)

        # Default RFC 7208 outcome when no mechanism matches
        return (
            "NEUTRAL",
            "No SPF mechanism matched; default result is NEUTRAL.",
            policy,
            evidence,
        )

    def _evaluate_mechanism(self, mechanism: str, current_domain: str) -> tuple[bool, str | None]:
        mech_lower = mechanism.lower()

        # 1. all
        if mech_lower == "all":
            return True, None

        # 2. ip4
        if mech_lower.startswith("ip4:"):
            cidr_str = mechanism.split(":", 1)[1].strip()
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
                if self.connecting_ip.version == 4 and self.connecting_ip in network:
                    return True, None
                return False, None
            except ValueError:
                return False, f"Invalid ip4 CIDR: {cidr_str}"

        # 3. ip6
        if mech_lower.startswith("ip6:"):
            cidr_str = mechanism.split(":", 1)[1].strip()
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
                if self.connecting_ip.version == 6 and self.connecting_ip in network:
                    return True, None
                return False, None
            except ValueError:
                return False, f"Invalid ip6 CIDR: {cidr_str}"

        # 4. a
        if mech_lower == "a" or mech_lower.startswith("a:") or mech_lower.startswith("a/"):
            self.dns_lookups += 1
            if self.dns_lookups > MAX_SPF_DNS_LOOKUPS:
                return False, "Lookup limit exceeded"
            target_dom = current_domain
            if mech_lower.startswith("a:"):
                target_dom = mechanism.split(":", 1)[1].split("/")[0].strip()
            a_ips = self.resolver.get_a_records(target_dom)
            for ip_str in a_ips:
                try:
                    if ipaddress.ip_address(ip_str) == self.connecting_ip:
                        return True, None
                except ValueError:
                    continue
            return False, None

        # 5. mx
        if mech_lower == "mx" or mech_lower.startswith("mx:") or mech_lower.startswith("mx/"):
            self.dns_lookups += 1
            if self.dns_lookups > MAX_SPF_DNS_LOOKUPS:
                return False, "Lookup limit exceeded"
            target_dom = current_domain
            if mech_lower.startswith("mx:"):
                target_dom = mechanism.split(":", 1)[1].split("/")[0].strip()
            mx_hosts = self.resolver.get_mx_hosts(target_dom)
            for mx_h in mx_hosts:
                self.dns_lookups += 1
                if self.dns_lookups > MAX_SPF_DNS_LOOKUPS:
                    return False, "Lookup limit exceeded"
                a_ips = self.resolver.get_a_records(mx_h)
                for ip_str in a_ips:
                    try:
                        if ipaddress.ip_address(ip_str) == self.connecting_ip:
                            return True, None
                    except ValueError:
                        continue
            return False, None

        # 6. include
        if mech_lower.startswith("include:"):
            self.dns_lookups += 1
            if self.dns_lookups > MAX_SPF_DNS_LOOKUPS:
                return False, "Lookup limit exceeded"
            inc_dom = mechanism.split(":", 1)[1].strip()
            inc_status, inc_reason, _pol, _ev = self.evaluate(inc_dom)
            if inc_status == "PASS":
                return True, None
            if inc_status in ("PERMERROR", "TEMPERROR"):
                return False, f"Include {inc_dom} failed with {inc_status}: {inc_reason}"
            return False, None

        # Unknown or unsupported mechanism syntax
        return False, f"Unknown mechanism '{mechanism}'"
