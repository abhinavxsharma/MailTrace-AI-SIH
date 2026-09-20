"""
MAILTRACE AI — Correlation Engine and Graph Builder.

Constructs typed entity graphs for emails and correlates multiple emails
using deterministic, explainable rules. Operates strictly in memory with
full evidence preservation.
"""

from __future__ import annotations

import re
from typing import Any

from graph.correlation.models import (
    AnalyzedEmailContext,
    CorrelationMatch,
    EmailGraph,
    GraphEntity,
    GraphRelationship,
)

import ipaddress

_SUBJECT_PREFIX_REGEX = re.compile(r"^(?:re|fwd|fw):\s*", re.IGNORECASE)

_RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_rfc1918_or_loopback(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if IP is loopback, link-local, or within RFC 1918 private space."""
    if ip_obj.is_loopback:
        return True
    return any(ip_obj in net for net in _RFC1918_NETWORKS)


class CorrelationEngine:
    """
    Deterministic correlation engine and graph builder.
    """

    def build_email_graph(self, context: AnalyzedEmailContext) -> EmailGraph:
        """
        Build an entity-relationship graph for an analyzed email.

        Args:
            context: AnalyzedEmailContext containing parsed email and forensic results.

        Returns:
            ``EmailGraph`` with deduplicated nodes and edges.
        """
        parsed = context.parsed_email
        email_id = parsed.message_id or parsed.message_id_header or "unknown_email"
        email_entity_id = f"email:{email_id}"

        entities: dict[str, GraphEntity] = {}
        relationships: list[GraphRelationship] = []
        rel_set: set[tuple[str, str, str]] = set()

        def _add_entity(ent_id: str, ent_type: str, display: str, evidence: dict[str, Any] | None = None) -> None:
            if ent_id not in entities:
                entities[ent_id] = GraphEntity(
                    id=ent_id,
                    type=ent_type,
                    display_value=display,
                    evidence=evidence or {},
                )

        def _add_rel(src: str, tgt: str, rel_type: str, evidence: dict[str, Any] | None = None) -> None:
            key = (src, tgt, rel_type)
            if key not in rel_set:
                rel_set.add(key)
                relationships.append(
                    GraphRelationship(
                        source_id=src,
                        target_id=tgt,
                        relationship_type=rel_type,
                        evidence=evidence or {},
                    )
                )

        # 1. Primary Email Entity
        _add_entity(
            email_entity_id,
            "email",
            parsed.subject or email_id,
            {"subject": parsed.subject, "date": str(parsed.date) if parsed.date else None},
        )

        # 2. From / Sender Addresses and Domains
        if parsed.from_address and parsed.from_address.email:
            addr_id = f"address:{parsed.from_address.email}"
            _add_entity(addr_id, "address", parsed.from_address.email, {"role": "from"})
            _add_rel(email_entity_id, addr_id, "EMAIL_SENT_BY_ADDRESS", {"source": "header:From"})

            if parsed.from_address.domain:
                dom_id = f"domain:{parsed.from_address.domain}"
                _add_entity(dom_id, "domain", parsed.from_address.domain, {"origin": "from_domain"})
                _add_rel(email_entity_id, dom_id, "EMAIL_USES_DOMAIN", {"source": "header:From"})

        if parsed.sender_address and parsed.sender_address.email:
            addr_id = f"address:{parsed.sender_address.email}"
            _add_entity(addr_id, "address", parsed.sender_address.email, {"role": "sender"})
            _add_rel(email_entity_id, addr_id, "EMAIL_SENT_BY_ADDRESS", {"source": "header:Sender"})

        # 3. Reply-To Addresses and Domains
        for r_addr in parsed.reply_to_addresses:
            if r_addr.email:
                addr_id = f"address:{r_addr.email}"
                _add_entity(addr_id, "address", r_addr.email, {"role": "reply-to"})
                _add_rel(email_entity_id, addr_id, "EMAIL_REPLIES_TO", {"source": "header:Reply-To"})
                if r_addr.domain:
                    dom_id = f"domain:{r_addr.domain}"
                    _add_entity(dom_id, "domain", r_addr.domain, {"origin": "reply_to_domain"})
                    _add_rel(email_entity_id, dom_id, "EMAIL_USES_DOMAIN", {"source": "header:Reply-To"})

        # 4. Target Addresses (To, Cc, Bcc)
        all_targets = parsed.to_addresses + parsed.cc_addresses + parsed.bcc_addresses
        for t_addr in all_targets:
            if t_addr.email:
                addr_id = f"address:{t_addr.email}"
                _add_entity(addr_id, "address", t_addr.email, {"role": "target"})
                _add_rel(email_entity_id, addr_id, "EMAIL_TARGETS_ADDRESS", {"source": "recipient"})

        # 5. Message-ID & In-Reply-To / References
        if parsed.message_id_header:
            mid_id = f"message_id:{parsed.message_id_header.strip('<>')}"
            _add_entity(mid_id, "message_id", parsed.message_id_header, {"source": "header:Message-ID"})

        if parsed.in_reply_to:
            ref_mid = f"message_id:{parsed.in_reply_to.strip('<>')}"
            _add_entity(ref_mid, "message_id", parsed.in_reply_to, {"source": "header:In-Reply-To"})
            _add_rel(email_entity_id, ref_mid, "EMAIL_REFERENCES", {"source": "header:In-Reply-To"})

        for ref in parsed.references:
            ref_id = f"message_id:{ref.strip('<>')}"
            _add_entity(ref_id, "message_id", ref, {"source": "header:References"})
            _add_rel(email_entity_id, ref_id, "EMAIL_REFERENCES", {"source": "header:References"})

        # 6. Body URLs and Host Domains
        for u in parsed.extracted_urls:
            url_id = f"url:{u.original_url}"
            _add_entity(url_id, "url", u.original_url, {"scheme": u.scheme, "path": u.path})
            _add_rel(email_entity_id, url_id, "EMAIL_CONTAINS_URL", {"source": "body:URL"})

            if u.host:
                host_clean = u.host.strip("[]").lower()
                dom_id = f"domain:{host_clean}"
                _add_entity(dom_id, "domain", host_clean, {"source": "url_host"})
                _add_rel(url_id, dom_id, "URL_HOSTS_DOMAIN", {"url": u.original_url})

        # 7. Received Hops / IPs
        for idx, hop in enumerate(parsed.received_hops):
            # Extract candidates from hop
            for raw_val in (hop.from_host, hop.by_host, hop.original_value):
                if not raw_val:
                    continue
                import ipaddress
                matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{3,39}", raw_val)
                for m in matches:
                    clean_m = m.strip("[]")
                    try:
                        ip_obj = ipaddress.ip_address(clean_m)
                        ip_id = f"ip:{clean_m}"
                        _add_entity(
                            ip_id,
                            "ip",
                            clean_m,
                            {"hop_index": idx, "is_private": ip_obj.is_private},
                        )
                        _add_rel(
                            email_entity_id,
                            ip_id,
                            "EMAIL_RECEIVED_FROM_IP",
                            {"hop_index": idx, "raw_host": raw_val},
                        )
                    except ValueError:
                        pass

        # 8. Authentication Results (DKIM / SPF)
        if context.auth_result:
            auth = context.auth_result
            if auth.dkim:
                dkim_dom = getattr(auth.dkim, "primary_domain", None) or getattr(auth.dkim, "domain", None)
                if dkim_dom:
                    dkim_id = f"dkim_domain:{dkim_dom.lower()}"
                    _add_entity(dkim_id, "dkim_domain", dkim_dom.lower(), {"status": auth.dkim.status})
                    _add_rel(email_entity_id, dkim_id, "EMAIL_HAS_DKIM_DOMAIN", {"status": auth.dkim.status})

            if auth.spf and auth.spf.domain:
                spf_id = f"spf_domain:{auth.spf.domain.lower()}"
                _add_entity(spf_id, "spf_domain", auth.spf.domain.lower(), {"status": auth.spf.status})
                _add_rel(email_entity_id, spf_id, "EMAIL_HAS_SPF_DOMAIN", {"status": auth.spf.status})

        # 9. Threat Intelligence (DNS / RDAP)
        if context.intel_result:
            intel = context.intel_result
            for dom_key, dns_info in intel.dns.items():
                dom_id = f"domain:{dom_key.lower()}"
                a_recs = dns_info.get("a_records", [])
                for ip_str in a_recs:
                    ip_id = f"ip:{ip_str}"
                    _add_entity(ip_id, "ip", ip_str, {"source": "dns_a_record"})
                    _add_rel(dom_id, ip_id, "DOMAIN_RESOLVES_TO_IP", {"domain": dom_key})

            for q_key, rdap_info in intel.rdap.items():
                cidr = rdap_info.get("network_cidr")
                if cidr:
                    net_id = f"rdap_network:{cidr}"
                    _add_entity(net_id, "rdap_network", cidr, {"source": "rdap"})
                    if rdap_info.get("query_type") == "domain":
                        _add_rel(f"domain:{q_key.lower()}", net_id, "DOMAIN_REGISTERED_TO_NETWORK", {"rdap_query": q_key})

        # 10. NLP Extracted Entities (Structured Indicators)
        parsed_body = getattr(parsed, "body_text", None) or getattr(parsed, "body", "") or ""
        if parsed_body or parsed.subject:
            try:
                from backend.app.services.intelligence.nlp_entities import extract_entities
                s_name = parsed.from_address.display_name if parsed.from_address else None
                s_email = parsed.from_address.email if parsed.from_address else None
                extracted = extract_entities(
                    subject=parsed.subject or "",
                    body=parsed_body,
                    sender_name=s_name,
                    sender_email=s_email,
                )
                for ent in extracted:
                    if ent.type in ("AMOUNT", "PAYMENT_INSTRUCTION", "ACCOUNT_IDENTIFIER", "CRYPTO_WALLET", "ORGANIZATION", "ROLE", "SERVICE_PLATFORM"):
                        norm = ent.normalized_value or ent.value
                        ent_id = f"{ent.type.lower()}:{norm}"
                        _add_entity(ent_id, ent.type.lower(), ent.value, {"context": ent.context, "type": ent.type})
                        _add_rel(email_entity_id, ent_id, f"EMAIL_REFERENCES_{ent.type}", {"source": "nlp_extraction"})
            except Exception as exc:
                logger.debug("NLP entity graph extraction skipped: %s", exc)

        return EmailGraph(
            entities=list(entities.values()),
            relationships=relationships,
            evidence={
                "email_id": email_id,
                "total_entities": len(entities),
                "total_relationships": len(relationships),
            },
        )

    def correlate_pair(
        self,
        ctx1: AnalyzedEmailContext,
        ctx2: AnalyzedEmailContext,
    ) -> list[CorrelationMatch]:
        """
        Correlate two emails based on deterministic, explainable rules.

        Args:
            ctx1: First email context.
            ctx2: Second email context.

        Returns:
            List of ``CorrelationMatch`` objects.
        """
        matches: list[CorrelationMatch] = []
        p1 = ctx1.parsed_email
        p2 = ctx2.parsed_email
        id1 = p1.message_id or p1.message_id_header or "email_1"
        id2 = p2.message_id or p2.message_id_header or "email_2"

        if id1 == id2:
            return matches

        def _add_match(reason: str, indicator: str, evidence: dict[str, Any]) -> None:
            matches.append(
                CorrelationMatch(
                    email_id_1=id1,
                    email_id_2=id2,
                    reason=reason,
                    shared_indicator=indicator,
                    evidence={"email_ids": [id1, id2], **evidence},
                )
            )

        # Rule 1: Shared Sender Address
        if p1.from_address and p2.from_address:
            if p1.from_address.email and p1.from_address.email.lower() == p2.from_address.email.lower():
                _add_match(
                    "shared_sender",
                    p1.from_address.email.lower(),
                    {"from_1": p1.from_address.email, "from_2": p2.from_address.email},
                )

        # Rule 2: Shared Sender Domain
        if p1.from_address and p2.from_address:
            if p1.from_address.domain and p1.from_address.domain.lower() == p2.from_address.domain.lower():
                # Avoid duplicate match if sender email already matched
                if not (p1.from_address.email and p1.from_address.email.lower() == p2.from_address.email.lower()):
                    _add_match(
                        "shared_domain",
                        p1.from_address.domain.lower(),
                        {"domain_1": p1.from_address.domain, "domain_2": p2.from_address.domain},
                    )

        # Rule 3: Shared Reply-To Address
        r1_emails = {r.email.lower() for r in p1.reply_to_addresses if r.email}
        r2_emails = {r.email.lower() for r in p2.reply_to_addresses if r.email}
        common_replies = r1_emails & r2_emails
        for rep in common_replies:
            _add_match("shared_reply_to", rep, {"reply_to": rep})

        # Rule 4: Shared Return-Path Domain
        if p1.return_path and p2.return_path:
            if p1.return_path.domain and p1.return_path.domain.lower() == p2.return_path.domain.lower():
                _add_match(
                    "shared_return_path",
                    p1.return_path.domain.lower(),
                    {"return_path_1": p1.return_path.domain, "return_path_2": p2.return_path.domain},
                )

        # Rule 5: Shared Exact URL
        u1_urls = {u.original_url.strip() for u in p1.extracted_urls if u.original_url}
        u2_urls = {u.original_url.strip() for u in p2.extracted_urls if u.original_url}
        common_urls = u1_urls & u2_urls
        for url_val in common_urls:
            _add_match("shared_url", url_val, {"url": url_val})

        # Rule 6: Shared URL Domain (if exact URL did not already match)
        u1_hosts = {u.host.strip("[]").lower() for u in p1.extracted_urls if u.host}
        u2_hosts = {u.host.strip("[]").lower() for u in p2.extracted_urls if u.host}
        common_hosts = u1_hosts & u2_hosts
        for host_val in common_hosts:
            # Check if this host is already covered by a shared exact URL
            if not any(host_val in cu for cu in common_urls):
                _add_match("shared_url_domain", host_val, {"domain": host_val})

        # Rule 7: Shared Received Infrastructure IP
        def _extract_ips(hops: list[Any]) -> set[str]:
            ips: set[str] = set()
            import ipaddress
            for hop in hops:
                for raw in (hop.from_host, hop.by_host, hop.original_value):
                    if not raw:
                        continue
                    found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{3,39}", raw)
                    for f in found:
                        try:
                            ip_obj = ipaddress.ip_address(f.strip("[]"))
                            # Exclude RFC1918/loopback from cross-email correlation to prevent false clustering
                            if not _is_rfc1918_or_loopback(ip_obj):
                                ips.add(str(ip_obj))
                        except ValueError:
                            pass
            return ips

        ips1 = _extract_ips(p1.received_hops)
        ips2 = _extract_ips(p2.received_hops)
        common_ips = ips1 & ips2
        for ip_val in common_ips:
            _add_match("shared_ip", ip_val, {"ip": ip_val})

        # Rule 8: Shared DKIM Domain
        if ctx1.auth_result and ctx2.auth_result:
            a1 = ctx1.auth_result
            a2 = ctx2.auth_result
            if a1.dkim and a2.dkim:
                d1 = getattr(a1.dkim, "primary_domain", None) or getattr(a1.dkim, "domain", None)
                d2 = getattr(a2.dkim, "primary_domain", None) or getattr(a2.dkim, "domain", None)
                if d1 and d2 and d1.lower() == d2.lower():
                    _add_match(
                        "shared_dkim_domain",
                        d1.lower(),
                        {"dkim_domain": d1.lower()},
                    )

            # Rule 9: Shared SPF Domain
            if a1.spf and a2.spf and a1.spf.domain and a2.spf.domain:
                if a1.spf.domain.lower() == a2.spf.domain.lower():
                    _add_match(
                        "shared_spf_domain",
                        a1.spf.domain.lower(),
                        {"spf_domain": a1.spf.domain.lower()},
                    )

        # Rule 10: Shared Subject Pattern
        s1 = _clean_subject(p1.subject)
        s2 = _clean_subject(p2.subject)
        if s1 and s2 and s1 == s2 and len(s1) >= 5:
            _add_match(
                "shared_subject_pattern",
                s1,
                {"subject_1": p1.subject, "subject_2": p2.subject, "normalized_pattern": s1},
            )

        # Rule 11: Shared Financial Routing or Crypto Wallet
        b1 = getattr(p1, "body_text", None) or getattr(p1, "body", "") or ""
        b2 = getattr(p2, "body_text", None) or getattr(p2, "body", "") or ""
        if (b1 or p1.subject) and (b2 or p2.subject):
            try:
                from backend.app.services.intelligence.nlp_entities import extract_entities
                e1 = extract_entities(p1.subject or "", b1)
                e2 = extract_entities(p2.subject or "", b2)
                targets = {"ACCOUNT_IDENTIFIER", "CRYPTO_WALLET"}
                vals1 = {ent.normalized_value or ent.value for ent in e1 if ent.type in targets}
                vals2 = {ent.normalized_value or ent.value for ent in e2 if ent.type in targets}
                common_entities = vals1 & vals2
                for cent in common_entities:
                    _add_match("shared_financial_entity", cent, {"entity": cent})
            except Exception:
                pass

        return matches

    def correlate_batch(
        self,
        contexts: list[AnalyzedEmailContext],
    ) -> list[CorrelationMatch]:
        """
        Correlate all pairs in a batch of analyzed emails.

        Args:
            contexts: List of AnalyzedEmailContext objects.

        Returns:
            Deduplicated list of all CorrelationMatch objects found.
        """
        all_matches: list[CorrelationMatch] = []
        for i in range(len(contexts)):
            for j in range(i + 1, len(contexts)):
                matches = self.correlate_pair(contexts[i], contexts[j])
                all_matches.extend(matches)
        return all_matches


def _clean_subject(subj: str | None) -> str:
    """Normalize subject line by removing Re:/Fwd: prefixes and trimming."""
    if not subj:
        return ""
    cur = subj.strip()
    while True:
        new_cur = _SUBJECT_PREFIX_REGEX.sub("", cur).strip()
        if new_cur == cur:
            break
        cur = new_cur
    return cur.lower()
