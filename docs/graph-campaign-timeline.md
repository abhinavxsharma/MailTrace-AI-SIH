# MAILTRACE AI — Graph, Campaign, and Timeline Intelligence (Chunk 6/7)

## Overview

Chunk 6 implements the **Graph, Campaign, and Timeline Intelligence** engine in `graph/`. It aggregates the structured artifacts produced across the previous forensic and intelligence chunks:

```
Forensic Evidence (Chunk 2)
        +
Authentication Results (Chunk 3)
        +
ML Phishing Classification (Chunk 4)
        +
Threat Intelligence (Chunk 5)
        ↓
Graph Entities & Relationships (graph/correlation/)
        ↓
Deterministic Correlation (graph/correlation/engine.py)
        ↓
Campaign Clustering (graph/campaign/clustering.py)
        ↓
Chronological Timeline (graph/timeline/builder.py)
```

---

## Architectural Boundaries

> [!IMPORTANT]
> **Correlation and Provenance Only — Not a Final Risk Score**:
> This chunk constructs entity graphs, establishes explainable links between emails, groups related messages into campaigns, and reconstructs chronological timelines.
> It does **not**:
> - Compute a 0–100 overall risk score (reserved for Chunk 7 Risk Fusion).
> - Use opaque ML clustering models or black-box embeddings.
> - Depend on external graph databases (Neo4j, Memgraph, etc.).
> - Persist graph nodes, raw MIME, or emails to local disk or relational databases.
> - Expose frontend interfaces or API endpoints.

---

## 1. Graph Entity Model

Entities represent the primary nodes in the intelligence graph:

| Entity Type | Identifier Format | Description |
|:---|:---|:---|
| `email` | `email:<message_id>` | The primary email message node (displaying subject or message ID). |
| `address` | `address:<email_address>` | Sender, recipient, or reply-to mailbox address. |
| `domain` | `domain:<domain_name>` | Header domain, sender domain, or URL host domain. |
| `ip` | `ip:<ip_address>` | Infrastructure IP observed in Received hops or resolved via DNS. |
| `url` | `url:<original_url>` | URL extracted from HTML or plain-text body. |
| `message_id` | `message_id:<id>` | RFC 5322 Message-ID, In-Reply-To, or References message ID. |
| `dkim_domain` | `dkim_domain:<domain>` | Cryptographically verified DKIM signing domain (Chunk 3). |
| `spf_domain` | `spf_domain:<domain>` | Envelope domain evaluated for SPF authorization (Chunk 3). |
| `rdap_network` | `rdap_network:<cidr>` | Autonomous system or CIDR network block (Chunk 5). |
| `campaign` | `campaign:<campaign_id>` | Cluster grouping correlated email attacks. |

Every entity contains `id`, `type`, `display_value`, and `evidence`.

---

## 2. Relationships

Directed edges connect graph entities, preserving complete source evidence:

- `EMAIL_SENT_BY_ADDRESS`: Links email to From or Sender address.
- `EMAIL_TARGETS_ADDRESS`: Links email to recipient addresses (To, Cc, Bcc).
- `EMAIL_REPLIES_TO`: Links email to Reply-To address.
- `EMAIL_REFERENCES`: Links email to referenced Message-IDs (In-Reply-To/References).
- `EMAIL_USES_DOMAIN`: Links email to From, Sender, or Reply-To domains.
- `EMAIL_CONTAINS_URL`: Links email to URLs found in the body.
- `URL_HOSTS_DOMAIN`: Links URL to its extracted host domain.
- `DOMAIN_RESOLVES_TO_IP`: Links domain to resolved A/AAAA IP records.
- `EMAIL_RECEIVED_FROM_IP`: Links email to external MTA transit IPs in Received headers.
- `DOMAIN_REGISTERED_TO_NETWORK`: Links domain to RDAP CIDR network allocations.
- `EMAIL_HAS_DKIM_DOMAIN`: Links email to verified DKIM signing domains.
- `EMAIL_HAS_SPF_DOMAIN`: Links email to verified SPF domains.
- `EMAIL_PART_OF_CAMPAIGN`: Links email to its associated campaign cluster.

---

## 3. Deterministic Correlation Rules

To prevent unsubstantiated claims that two emails belong to the same campaign, correlation is strictly rule-based:

1. `shared_sender`: Exact match on From email address.
2. `shared_domain`: Exact match on From domain (when email address differs).
3. `shared_reply_to`: Exact match on Reply-To email address.
4. `shared_return_path`: Exact match on Return-Path domain.
5. `shared_url`: Exact match on body URL.
6. `shared_url_domain`: Exact match on host domain across body URLs.
7. `shared_ip`: Exact match on external Received transit IP (RFC 1918 private IPs are filtered out to avoid false clustering).
8. `shared_dkim_domain`: Exact match on authenticated DKIM signing domain.
9. `shared_spf_domain`: Exact match on authenticated SPF domain.
10. `shared_subject_pattern`: Exact match on normalized subject lines (ignoring `Re:`, `Fwd:`, and whitespace).

Every `CorrelationMatch` records `email_id_1`, `email_id_2`, `reason`, `shared_indicator`, and supporting evidence.

---

## 4. Deterministic Campaign Clustering

`CampaignClusterer` (`graph/campaign/clustering.py`) groups emails using graph connected components over pairwise correlation matches:
- **Grouping**: Any set of 2 or more emails linked by one or more correlation rules forms a `CampaignCluster`.
- **Deterministic IDs**: `campaign_id` is computed as `camp_<sha256(members|indicators|reasons)[:12]>`, guaranteeing identical IDs across runs with identical inputs.
- **Explainable Strength**: Calculated deterministically from the forensic specificity of the matching rules (e.g. shared exact URL and sender carry higher weight than shared subject pattern).
- **Evidence Preservation**: Clusters preserve the complete list of member email IDs, shared indicators, correlation reasons, and pairwise matches.

---

## 5. Timeline Construction

`TimelineBuilder` (`graph/timeline/builder.py`) builds normalized, chronologically ordered timelines:
- **Email Origin**: Extracted from RFC 5322 `Date` header.
- **Transit Progression**: Extracted from ordered `Received` hops.
- **Authentication**: Evaluated status for SPF, DKIM, and DMARC.
- **Threat Intelligence**: Domain registration timestamps from RDAP.
- **Correlation Events**: Links to related emails in the same campaign.

### Missing & Invalid Date Handling
- Events with missing or unparseable timestamps do not cause errors; their `timestamp` is set to `None`.
- Sorting uses a deterministic key: events with valid ISO 8601 timestamps are sorted ascending; events without timestamps are placed at the end.

---

## 6. Privacy & In-Memory Guarantees

- **No Disk Storage**: Graphs, campaigns, and timelines are held exclusively in memory.
- **No Raw MIME or Bodies**: Entities store only normalized identifiers (domains, IPs, URLs, addresses) and metadata.
- **No `tempfile` Usage**: Verified by unit test sentinels.
- **100% Offline Testing**: All test suites run locally with zero network dependencies.

---

## 7. Next Stage: Risk Fusion Boundary (Chunk 7)

Chunk 6 provides structured graph relationships, campaign clusters, and timelines.
In **Chunk 7 (Final Risk Fusion)**, the signals from:
1. Forensic Headers (Chunk 2)
2. Email Authentication (Chunk 3)
3. DistilBERT Phishing Inference (Chunk 4)
4. Threat Intelligence & Infrastructure (Chunk 5)
5. Campaign & Correlation Graph (Chunk 6)

will be synthesized into the final explainable 0–100 composite risk score.
