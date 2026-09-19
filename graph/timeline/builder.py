"""
MAILTRACE AI — Timeline Intelligence Builder.

Constructs chronologically sorted, normalized timelines of email events:
- Email Date header
- Received hops transit timestamps
- Authentication evaluations (SPF, DKIM, DMARC)
- Threat intelligence observations (RDAP registration, domain creation)
- Correlation events across related emails

Handles missing, unparseable, and invalid timestamps safely without crashing.
Operates strictly in memory.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from graph.campaign.models import CampaignCluster
from graph.correlation.models import AnalyzedEmailContext, CorrelationMatch
from graph.timeline.models import EmailTimeline, TimelineEvent


class TimelineBuilder:
    """
    Constructs normalized, chronologically sorted timelines from email analysis contexts.
    """

    def build_email_timeline(
        self,
        context: AnalyzedEmailContext,
        correlation_matches: list[CorrelationMatch] | None = None,
    ) -> EmailTimeline:
        """
        Build a chronologically ordered timeline for an individual email.

        Args:
            context: AnalyzedEmailContext containing parsed email and forensic results.
            correlation_matches: Optional list of correlation matches involving this email.

        Returns:
            ``EmailTimeline`` with sorted events and earliest/latest bounds.
        """
        parsed = context.parsed_email
        email_id = parsed.message_id or parsed.message_id_header or "unknown_email"
        events: list[TimelineEvent] = []

        # 1. Email Date Header
        if parsed.date:
            events.append(
                TimelineEvent(
                    timestamp=self._normalize_datetime(parsed.date),
                    event_type="EMAIL_DATE",
                    entity_id=f"email:{email_id}",
                    description=f"Email message originated with Date: {parsed.date.isoformat()}",
                    evidence={"raw_date": str(parsed.date), "subject": parsed.subject},
                )
            )
        else:
            events.append(
                TimelineEvent(
                    timestamp=None,
                    event_type="EMAIL_DATE",
                    entity_id=f"email:{email_id}",
                    description="Email message missing valid Date header",
                    evidence={"raw_date": None},
                )
            )

        # 2. Received Hops (MTA transit progression)
        for idx, hop in enumerate(parsed.received_hops):
            hop_time_str = self._normalize_datetime(hop.timestamp) if hop.timestamp else None
            desc = f"MTA hop [{idx}]: received by {hop.by_host or 'unknown'} from {hop.from_host or 'unknown'}"
            events.append(
                TimelineEvent(
                    timestamp=hop_time_str,
                    event_type="RECEIVED_HOP",
                    entity_id=f"email:{email_id}",
                    description=desc,
                    evidence={
                        "hop_index": idx,
                        "from_host": hop.from_host,
                        "by_host": hop.by_host,
                        "raw_timestamp": str(hop.timestamp) if hop.timestamp else None,
                    },
                )
            )

        # 3. Authentication Evaluations
        if context.auth_result:
            auth = context.auth_result
            if auth.spf:
                events.append(
                    TimelineEvent(
                        timestamp=None,
                        event_type="AUTH_SPF",
                        entity_id=f"email:{email_id}",
                        description=f"SPF verification evaluated with status: {auth.spf.status}",
                        evidence={"spf_status": auth.spf.status, "domain": auth.spf.domain},
                    )
                )
            if auth.dkim:
                dkim_dom = getattr(auth.dkim, "primary_domain", None) or getattr(auth.dkim, "domain", None)
                events.append(
                    TimelineEvent(
                        timestamp=None,
                        event_type="AUTH_DKIM",
                        entity_id=f"email:{email_id}",
                        description=f"DKIM verification evaluated with status: {auth.dkim.status}",
                        evidence={"dkim_status": auth.dkim.status, "domain": dkim_dom},
                    )
                )
            if auth.dmarc:
                events.append(
                    TimelineEvent(
                        timestamp=None,
                        event_type="AUTH_DMARC",
                        entity_id=f"email:{email_id}",
                        description=f"DMARC evaluation completed with status: {auth.dmarc.status}",
                        evidence={"dmarc_status": auth.dmarc.status, "policy": auth.dmarc.policy},
                    )
                )

        # 4. Intelligence Observations (RDAP creation/registration dates)
        if context.intel_result:
            for q_key, rdap_info in context.intel_result.rdap.items():
                reg_date = rdap_info.get("registration_date")
                if reg_date:
                    norm_reg = self._parse_iso_string(reg_date)
                    events.append(
                        TimelineEvent(
                            timestamp=norm_reg,
                            event_type="INTELLIGENCE_RDAP",
                            entity_id=f"domain:{q_key}",
                            description=f"RDAP domain registration for {q_key}: {reg_date}",
                            evidence={"query": q_key, "raw_date": reg_date, "registrar": rdap_info.get("registrar")},
                        )
                    )

        # 5. Correlation Matches
        if correlation_matches:
            for m in correlation_matches:
                if m.email_id_1 == email_id or m.email_id_2 == email_id:
                    other_id = m.email_id_2 if m.email_id_1 == email_id else m.email_id_1
                    events.append(
                        TimelineEvent(
                            timestamp=None,
                            event_type="CORRELATION_EVENT",
                            entity_id=f"email:{email_id}",
                            description=f"Correlated with email {other_id} via rule {m.reason} ({m.shared_indicator})",
                            evidence={"other_email_id": other_id, "reason": m.reason, "indicator": m.shared_indicator},
                        )
                    )

        # Chronological Sort
        events.sort(key=self._sort_key)

        # Determine earliest and latest timestamps
        valid_timestamps = [e.timestamp for e in events if e.timestamp]
        earliest = valid_timestamps[0] if valid_timestamps else None
        latest = valid_timestamps[-1] if valid_timestamps else None

        return EmailTimeline(
            email_id=email_id,
            events=events,
            earliest_timestamp=earliest,
            latest_timestamp=latest,
            evidence={
                "total_events": len(events),
                "events_with_timestamp": len(valid_timestamps),
            },
        )

    def build_campaign_timeline(
        self,
        campaign: CampaignCluster,
        contexts: list[AnalyzedEmailContext],
    ) -> list[TimelineEvent]:
        """
        Build a combined, chronologically sorted timeline across all emails in a campaign cluster.

        Args:
            campaign: CampaignCluster to build timeline for.
            contexts: List of all available AnalyzedEmailContext objects.

        Returns:
            Chronologically sorted list of ``TimelineEvent`` objects.
        """
        ctx_map = {
            (c.parsed_email.message_id or c.parsed_email.message_id_header or ""): c
            for c in contexts
        }

        all_events: list[TimelineEvent] = []

        for email_id in campaign.member_email_ids:
            ctx = ctx_map.get(email_id)
            if ctx:
                email_timeline = self.build_email_timeline(ctx)
                all_events.extend(email_timeline.events)

        # Add campaign cluster formation milestone
        all_events.append(
            TimelineEvent(
                timestamp=None,
                event_type="CAMPAIGN_CLUSTER",
                entity_id=campaign.campaign_id,
                description=f"Campaign cluster formed linking {len(campaign.member_email_ids)} emails",
                evidence={
                    "campaign_id": campaign.campaign_id,
                    "strength": campaign.strength,
                    "reasons": campaign.correlation_reasons,
                },
            )
        )

        all_events.sort(key=self._sort_key)
        return all_events

    @staticmethod
    def _normalize_datetime(dt: datetime | None) -> str | None:
        """Convert datetime object to ISO 8601 UTC string safely."""
        if not dt:
            return None
        try:
            return dt.isoformat()
        except Exception:
            return None

    @staticmethod
    def _parse_iso_string(date_str: str | None) -> str | None:
        """Validate and return normalized ISO string or None."""
        if not date_str or not isinstance(date_str, str):
            return None
        # Quick validation
        clean = date_str.strip()
        try:
            # Check if parseable
            datetime.fromisoformat(clean.replace("Z", "+00:00"))
            return clean
        except Exception:
            return clean if len(clean) >= 10 else None

    @staticmethod
    def _sort_key(event: TimelineEvent) -> tuple[int, str, str]:
        """
        Deterministic sort key:
        1. Events with valid timestamp come first (0), events without timestamp at end (1).
        2. ISO timestamp string for chronological ordering.
        3. Event type as tie-breaker.
        """
        if event.timestamp is not None:
            return (0, event.timestamp, event.event_type)
        return (1, "", event.event_type)
