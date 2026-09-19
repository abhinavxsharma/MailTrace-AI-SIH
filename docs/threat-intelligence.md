# MAILTRACE AI — Threat Intelligence and Infrastructure Enrichment (Chunk 5/7)

## Overview

Chunk 5 implements the **Threat Intelligence and Infrastructure Enrichment** engine in `intelligence/`. It takes the structured `ParsedEmail` produced by Chunk 2 and enriches its indicators with external and contextual evidence:

```
ParsedEmail (from Chunk 2)
    ↓
Indicator Extraction & Provenance (intelligence/extractors.py)
    [Domains, IPs, URLs with header/body/hop provenance]
    ↓
DNS Intelligence (intelligence/dns/)
    [A, AAAA, MX, NS, TXT, CNAME lookups with timeout & caching]
    ↓
RDAP Registration & Network (intelligence/rdap/)
    [Domain & IP registration, registrar, dates, CIDRs, ASNs]
    ↓
GeoIP Geolocation (intelligence/geoip/)
    [Country, region, city, coordinates, ASN, private IP filtering]
    ↓
Threat Reputation (intelligence/reputation/)
    [Provider abstraction, DNSBL adapter, default NOT_CONFIGURED]
    ↓
Structured Intelligence Evidence (EmailIntelligenceResult)
```

---

## Architectural Boundaries

> [!IMPORTANT]
> **Evidence Enrichment Only — Not a Risk Score**:
> This chunk enriches indicators with factual and provider-supplied evidence.
> It does **not**:
> - Compute a 0–100 risk score.
> - Make unsupported maliciousness claims.
> - Run ML inference or training (handled in Chunk 4).
> - Perform SPF/DKIM/DMARC authentication (handled in Chunk 3).
> - Correlate campaigns or construct graphs (handled in Chunk 6).
> - Expose API routes or persist data to databases/frontend.

Every intelligence result strictly distinguishes between four fundamental states:
1. **Observed Fact**: Empirical data directly extracted from the email or query (e.g. resolved IP address, MX host, RFC1918 private range).
2. **Provider Result**: External evaluation returned by a registered service (e.g. DNSBL listing, registrar name).
3. **Unavailable**: Service or data source not configured, database missing, or record absent (e.g. `NOT_CONFIGURED`, `DATABASE_MISSING`).
4. **Error**: Operational failure during lookup (e.g. `TIMEOUT`, `SERVFAIL`, `MALFORMED`).

---

## 1. Indicator Extraction & Provenance

The indicator extractor (`intelligence/extractors.py`) scans `ParsedEmail` to extract all actionable indicators:
- **Domains**: From `From`, `Sender`, `Return-Path`, `To`, `Cc`, `Bcc`, `Reply-To`, Received hops, and body URL hostnames.
- **IP Addresses**: From Received hops (`from_host`, `by_host`, comment strings) and body URL hosts.
- **URLs**: Extracted from plain text and HTML bodies.

### Source Provenance Tracking
Every indicator retains a list of origin tags (`sources`) indicating where it appeared in the message:
- `header:From`, `header:Reply-To`, `header:Return-Path`
- `hop:Received[0]`, `hop:Received[1]`
- `body:URL`

Indicators are deduplicated by normalized value and type, while accumulating all source tags and context metadata.

---

## 2. DNS Intelligence

The typed DNS resolver (`intelligence/dns/`) queries core DNS records:
- `A` (IPv4 addresses)
- `AAAA` (IPv6 addresses)
- `MX` (Mail exchangers)
- `NS` (Authoritative nameservers)
- `TXT` (SPF, DMARC, verification tokens)
- `CNAME` (Canonical names / aliasing)

### Handled States
- `NOERROR`: Query succeeded with records returned.
- `NO_RECORDS`: Domain exists, but requested record type has no answers.
- `NXDOMAIN`: Domain does not exist.
- `SERVFAIL`: Nameserver failure or query refused.
- `TIMEOUT`: Query timed out under configurable limit (default 3.0s).
- `MALFORMED`: Invalid domain syntax (RFC 1035 check) or unsupported record type.
- `ERROR`: Unexpected resolver exception.

Lookups are bounded, non-recursive beyond standard resolver queries, and cached in memory via `InMemoryTtlCache`.

---

## 3. RDAP Registration & Network Client

The RDAP client (`intelligence/rdap/client.py`) queries standardized registration data for domains and IP addresses:
- **Domains**: Registrar name, registrant organization, registration timestamp, expiration timestamp, last updated timestamp, nameservers.
- **IP Addresses**: CIDR network blocks, start/end address ranges, ASN, organization.

### Key Behaviors
- **No Maliciousness Assumptions**: Missing RDAP records or privacy-masked registrant fields (e.g. GDPR redactions) are never assumed to indicate malice.
- **RFC 1918 Protection**: Private and loopback IP addresses (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `127.0.0.1`, `::1`) are short-circuited with `source="rfc1918_filter"` without initiating network queries.
- **HTTP Status Mapping**: 404 maps to `NOT_FOUND`, 5xx maps to `ERROR`, timeouts map to `TIMEOUT`, and invalid JSON maps to `MALFORMED`.

---

## 4. GeoIP Geolocation

The GeoIP subsystem (`intelligence/geoip/`) abstracts IP geolocation behind `GeoIpProviderProtocol`:
- Exposes: `ip`, `country`, `region`, `city`, `latitude`, `longitude`, `asn`, `organization`, `source`, `status`.
- **Private IP Handling**: Private and loopback IPs are mapped to `status="PRIVATE_IP"` immediately.
- **Missing Database Graceful Degradation**: If no local MaxMind `.mmdb` database is installed or configured, the resolver safely returns `status="DATABASE_MISSING"` rather than crashing.
- **Extensible Providers**:
  - `MaxMindGeoIpProvider`: Uses local `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` if present.
  - `MissingDatabaseProvider`: Safe default fallback.
  - `MockGeoIpProvider`: Injected for offline unit tests.

---

## 5. Threat Reputation Provider Abstraction

Reputation is decoupled from proprietary vendors via `ReputationProviderProtocol`:
```python
class ReputationProviderProtocol(Protocol):
    @property
    def name(self) -> str: ...
    def is_configured(self) -> bool: ...
    def check_indicator(self, indicator: str, indicator_type: IndicatorType) -> ReputationResult: ...
```

### Safety & Defaults
- **Default State**: When no provider is configured, `ReputationService` defaults to `NotConfiguredReputationProvider`, returning `raw_status="NOT_CONFIGURED"`.
- **No Random Services**: No third-party network calls are made without explicit user/admin configuration.
- **No Fabrication**: If a provider does not supply a score or confidence, fields remain `None`.
- **DNSBL Adapter**: Includes `DnsblReputationProvider` for standard DNS blacklists (e.g. Spamhaus ZEN/DBL), supporting reverse IP lookups and offline mock injection.

---

## 6. In-Memory Caching

All lookups (DNS, RDAP, GeoIP, Reputation) support thread-safe, in-memory caching via `InMemoryTtlCache[T]`:
- Items expire automatically after a configurable TTL (e.g. 300s for DNS, 3600s for RDAP/GeoIP).
- Background expiration pruning prevents memory leaks.
- Zero local disk writes or persistent caches.

---

## 7. Privacy & Offline Safety

To satisfy the strict privacy requirements of MAILTRACE AI:
- **In-Memory Only**: All intelligence enrichment operates exclusively on memory objects.
- **No File Writes**: No `.eml` files, raw MIME chunks, or attachment payloads are ever written to disk.
- **No Temp Files**: The `tempfile` module is not imported or used anywhere in `intelligence/`.
- **100% Offline Testing**: All test suites in `backend/tests/` use mock resolvers, mock HTTP handlers, and dependency injection to guarantee zero external network traffic during testing.

---

## 8. Risk Fusion Boundary

Threat intelligence provides enriched forensic indicators. The calculation of the composite 0–100 risk score occurs in the subsequent **Risk Fusion** stage:
```
Email Forensics (Chunk 2)
Email Authentication (Chunk 3)      ──┐
ML Phishing Probability (Chunk 4)    ──┼──►  Risk Fusion Engine (Chunk 6/7)  ──► Final 0–100 Score
Threat Intelligence (Chunk 5)       ──┘
```
This strict boundary ensures intelligence enrichment remains modular, verifiable, and free of premature heuristic scoring.
