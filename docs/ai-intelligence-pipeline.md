# MAILTRACE AI — Unified Intelligence Pipeline & Integration (Chunk 7/7)

## Overview

Chunk 7 provides the final **Intelligence Integration & Orchestration Layer** (`backend/app/services/intelligence/`). It creates a clean, decoupled service interface that coordinates all forensic, authentication, machine learning, threat intelligence, and graph correlation engines built across Chunks 1–6:

```
Gmail Connector (Chunk 1)
        ↓
NormalizedEmail
        ↓
┌────────────────────────────────────────────────────────┐
│             IntelligencePipeline.analyze()             │
├────────────────────────────────────────────────────────┤
│  1. Email Parser (Chunk 2)                             │
│  2. Header Forensics (Chunk 2)                         │
│  3. SPF / DKIM / DMARC Authentication (Chunk 3)        │
│  4. DistilBERT Phishing Inference (Chunk 4)            │
│  5. Indicator Extraction & Enrichment (Chunk 5)        │
│     - DNS (A, AAAA, MX, NS, TXT, CNAME)               │
│     - RDAP (Domain/IP registration & network)          │
│     - GeoIP (MaxMind local / RFC 1918 filter)          │
│     - Threat Reputation (Provider abstraction / DNSBL) │
│  6. Entity-Relationship Graph Construction (Chunk 6)   │
│  7. Cross-Email Correlation (Chunk 6)                  │
│  8. Campaign Clustering (Chunk 6)                      │
│  9. Chronological Timeline Reconstruction (Chunk 6)    │
└────────────────────────────────────────────────────────┘
        ↓
IntelligenceAnalysisResult
        ↓
Handoff to Backend / Risk Fusion (Chunk 7 Boundary)
```

---

## Architectural & Ownership Boundaries

> [!IMPORTANT]
> **Backend Integration Contract — Not a Route or Database Model**:
> This package is an internal service integration layer designed to be consumed by Abhinav's main backend application.
> It does **not**:
> - Define FastAPI routes or HTTP endpoints.
> - Create database schemas, migrations, or ORM models.
> - Implement frontend views.
> - Compute the final composite 0–100 risk score (reserved for backend risk fusion).

---

## 1. Pipeline Execution Order

The orchestrator (`IntelligencePipeline`) executes stages in a deterministic sequence:

| Step | Stage Name | Component | Output / Evidence Added |
|:---:|:---|:---|:---|
| 1 | `email_parser` | `forensics/email_parser/` | `ParsedEmail`: Normalized addresses, extracted URLs, Received hops, attachment metadata. |
| 2 | `header_forensics` | `forensics/headers/` | `HeaderForensicResult`: Anomalous headers, hop delays, client spoofing indicators. |
| 3 | `authentication` | `forensics/authentication/` | `AuthenticationResult`: Verified SPF, DKIM signatures, DMARC policy, domain alignment. |
| 4 | `ml_classification` | `ml/inference/` | `MlClassificationResult`: DistilBERT prediction (`BENIGN` / `MALICIOUS`), confidence, class probabilities. |
| 5 | `threat_intelligence` | `intelligence/` | `EmailIntelligenceResult`: DNS records, RDAP registration, GeoIP location, reputation status. |
| 6 | `graph` | `graph/correlation/` | `EmailGraph`: Typed entities (`email`, `address`, `domain`, `ip`, `url`, `dkim_domain`, etc.) and relationships. |
| 7 | `correlation` | `graph/correlation/` | `list[CorrelationMatch]`: Deterministic pairwise matches (`shared_sender`, `shared_domain`, `shared_url`, `shared_ip`, etc.). |
| 8 | `campaign` | `graph/campaign/` | `CampaignCluster`: Deterministic campaign ID, member IDs, shared indicators, and explainable strength score. |
| 9 | `timeline` | `graph/timeline/` | `EmailTimeline`: Chronologically sorted events from email date, hops, auth checks, and RDAP dates. |

---

## 2. Input and Output Models

### Input
- `NormalizedEmail` (`app.services.mail.models.NormalizedEmail`): In-memory output from the Gmail connector (Chunk 1).
- Alternatively accepts pre-parsed `ParsedEmail` (`forensics.email_parser.models.ParsedEmail`).
- Optional `related_emails`: List of related or historical emails to correlate against for campaign clustering.

### Output (`IntelligenceAnalysisResult`)
```python
class IntelligenceAnalysisResult(BaseModel):
    message_id: str
    provider_message_id: str | None
    thread_id: str | None
    subject: str | None
    date: str | None

    # Stage Diagnostics
    stages: dict[str, StageExecutionMetadata]

    # Structured Component Evidences
    parsed_email: ParsedEmail | None
    header_forensics: HeaderForensicResult | None
    authentication: AuthenticationResult | None
    ml_classification: MlClassificationResult | None
    threat_intelligence: EmailIntelligenceResult | None
    graph: EmailGraph | None
    correlations: list[CorrelationMatch]
    campaign: CampaignCluster | None
    timeline: EmailTimeline | None

    # Global Status and Provenance
    evidence: dict[str, Any]
    success: bool
    errors: list[str]
```

---

## 3. Failure Isolation

The pipeline employs strict fault tolerance to prevent transient or external service failures from discarding valid evidence:

- **Independent Execution**: If a stage fails (e.g. `ml_classification` weights missing, or `threat_intelligence` external API timeout), the stage status is marked as `FAILED` or `UNAVAILABLE`. All subsequent independent stages (e.g. `graph`, `timeline`) continue execution.
- **Diagnostics Preservation**: Every stage produces a `StageExecutionMetadata` record documenting its status (`SUCCESS`, `FAILED`, `UNAVAILABLE`, `PARTIAL`, `SKIPPED`), duration in milliseconds, and detailed error string.
- **Fail-Fast only on Core Parser**: If the initial email parsing stage (`email_parser`) fails, execution stops immediately because subsequent stages require a structured `ParsedEmail`. A partial result with error diagnostics is returned.

---

## 4. Dependency Injection

The pipeline supports full dependency injection via `PipelineDependencies`:

```python
from app.services.intelligence import IntelligencePipeline, PipelineDependencies

# Custom or mock dependencies for testing
deps = PipelineDependencies(
    dns_resolver=mock_dns_resolver,
    rdap_client=mock_rdap_client,
    geoip_resolver=mock_geoip_resolver,
    reputation_service=mock_reputation_service,
    model_loader=mock_model_loader,
)
pipeline = IntelligencePipeline(dependencies=deps)
```

In production, `create_default_dependencies()` initializes standard offline-first resolvers, local MaxMind readers, and in-memory TTL caches.

---

## 5. Privacy & Logging Policy

- **In-Memory Only**: Raw MIME data and decrypted email bodies are processed exclusively in memory.
- **No Disk Storage**: No `.eml` files, body dumps, or temporary files (`tempfile`) are created or written to disk.
- **Sanitized Logging**: All logging uses `app.core.logging.get_logger`. Logs record only `message_id`, stage name, execution time, and error categories. Full message bodies, HTML content, and raw headers are never logged.

---

## 6. Handoff Interface for Backend Integration

Abhinav can consume the intelligence pipeline directly in FastAPI routes or background workers:

```python
from app.services.intelligence import IntelligencePipeline
from app.services.mail.models import NormalizedEmail

pipeline = IntelligencePipeline()

# Async invocation (suitable for FastAPI endpoints)
result = await pipeline.analyze(normalized_email)

# Or synchronous invocation (suitable for Celery/background workers)
result = pipeline.analyze_sync(normalized_email)

if result.success:
    print(f"Parsed Subject: {result.subject}")
    print(f"ML Verdict: {result.ml_classification.label}")
    print(f"SPF Status: {result.authentication.spf.status}")
    print(f"Campaign ID: {result.campaign.campaign_id if result.campaign else 'None'}")
    print(f"Timeline Events: {len(result.timeline.events)}")
```

---

## 7. Risk Fusion Boundary (Handoff to Backend)

The AI/Intelligence engine produces objective evidence and component-level signals. It deliberately does **not** compute a final 0–100 risk score.

Downstream backend risk fusion is responsible for mapping these dimensions:
1. **AI Threat**: `result.ml_classification` (DistilBERT probability).
2. **Identity**: `result.header_forensics` and sender alignment.
3. **Authentication**: `result.authentication` (SPF, DKIM, DMARC statuses).
4. **URL / Domain**: `result.threat_intelligence.dns`, `rdap`, and `reputation`.
5. **Infrastructure**: `result.threat_intelligence.geoip` and Received hops.
6. **Campaign**: `result.campaign` and `result.correlations`.
