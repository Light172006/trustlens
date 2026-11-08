# Backend Integration Guide — Certificate Analyzer

## Audience: Backend Engineer (FastAPI, Redis, Celery, TLS Handshake Scanner)

This document explains how to call the **TrustLens Certificate Analyzer** from backend services (e.g. background Celery workers, website scanning tasks, or FastAPI route handlers).

---

## 1. Public API Interfaces

The analyzer resides in `intelligence/certificate_analyzer/src/certificate_analyzer/api.py`. It exposes three high-throughput, deterministic entrypoints:

```python
from certificate_analyzer.api import (
    analyze_certificate,
    analyze_pem,
    analyze_endpoint_tls,
)
from certificate_analyzer.schemas.assessment import CertificateAssessment
from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine
from certificate_analyzer.errors import (
    AnalysisErrorCode,
    CertificateAnalyzerError,
    InvalidCertificateError,
    ResourceLimitExceededError,
)
```

### Signature A: `analyze_endpoint_tls()` (Primary Endpoint Scanner Call)

Used when the backend scanner performs an active TLS handshake against a target host:

```python
def analyze_endpoint_tls(
    certificate_der: bytes,
    target_hostname: str,
    port: int = 443,
    tls_protocol_version: str = "TLSv1.3",
    cipher_suite: Optional[str] = None,
    presented_intermediates: Optional[List[bytes]] = None,
    revocation_observation: Optional[Dict[str, Any]] = None,
    reference_time: Optional[datetime] = None,
    include_ml_advisory: bool = False,
    engine: Optional[CertificateAnalyzerEngine] = None,
) -> CertificateAssessment:
    ...
```

### Signature B: `analyze_certificate()` (Direct Certificate Analysis)

Used when analyzing a standalone certificate (e.g. uploaded DER/PEM or certificate record from database):

```python
def analyze_certificate(
    certificate_input: Union[bytes, str, Dict[str, Any]],
    target_hostname: Optional[str] = None,
    revocation_observation: Optional[Dict[str, Any]] = None,
    reference_time: Optional[datetime] = None,
    include_ml_advisory: bool = False,
    engine: Optional[CertificateAnalyzerEngine] = None,
) -> CertificateAssessment:
    ...
```

### Signature C: `analyze_pem()` (PEM Bundle Analysis)

Used when analyzing a PEM bundle containing a leaf and intermediates:

```python
def analyze_pem(
    pem_data: str,
    target_hostname: Optional[str] = None,
    revocation_observation: Optional[Dict[str, Any]] = None,
    reference_time: Optional[datetime] = None,
    include_ml_advisory: bool = False,
    engine: Optional[CertificateAnalyzerEngine] = None,
) -> CertificateAssessment:
    ...
```

---

## 2. TLS Scanner Telemetry Collection

When performing a TLS handshake (via `ssl`, `cryptography`, or an async socket), collect the following fields:

| Field Name | Type | Description | Mandatory? |
|:---|:---|:---|:---|
| `certificate_der` | `bytes` | Raw binary DER encoding of the leaf certificate (from `ssl_sock.getpeercert(binary_form=True)`). | **YES** |
| `target_hostname` | `str` | Hostname requested in the scan (and used in TLS SNI). | **YES** (for RFC 9525 check) |
| `port` | `int` | Destination port (default `443`). | Optional (default 443) |
| `tls_protocol_version` | `str` | Negotiated protocol: `"TLSv1.3"`, `"TLSv1.2"`, etc. | Optional (default "TLSv1.3") |
| `cipher_suite` | `str` | Negotiated cipher suite name (e.g. `"TLS_AES_256_GCM_SHA384"`). | Optional |
| `presented_intermediates` | `List[bytes]` | List of raw DER bytes for intermediate certificates sent in the server handshake. | Strongly recommended |
| `include_ml_advisory` | `bool` | Set `True` to populate `assessment.ml_advisory` (default `False`). | Optional |
| `reference_time` | `datetime` | Scan execution timestamp (UTC). Defaults to `datetime.now(timezone.utc)`. | Optional |

---

## 3. Production Celery Worker Example

```python
import ssl
import socket
from datetime import datetime, timezone
from certificate_analyzer.api import analyze_endpoint_tls
from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine

# Re-use a single shared engine instance per worker process
worker_engine = CertificateAnalyzerEngine(cache_size=4096)

def scan_website_certificate_task(hostname: str, port: int = 443) -> dict:
    """Production Celery task: connects to endpoint, retrieves chain, and analyzes trust."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Collect raw bytes even if invalid to diagnose failure!

    with socket.create_connection((hostname, port), timeout=10.0) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            leaf_der = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher_suite = ssock.cipher()[0] if ssock.cipher() else None

    # Deterministic Certificate Assessment (with opt-in ML advisory)
    assessment = analyze_endpoint_tls(
        certificate_der=leaf_der,
        target_hostname=hostname,
        port=port,
        tls_protocol_version=tls_version,
        cipher_suite=cipher_suite,
        reference_time=datetime.now(timezone.utc),
        include_ml_advisory=True,
        engine=worker_engine,
    )

    # Return serialized dictionary ready for PostgreSQL and API response
    return assessment.model_dump(mode="json")
```

---

## 4. PEM Bundle Handling & Leaf Resolution

When multiple certificates are concatenated in a single PEM bundle, the analyzer applies deterministic leaf resolution:

1. **CA Separation**: Identifies all certificates with `is_ca=True` as intermediate/root authorities.
2. **Leaf Candidate Detection**: Identifies certificates with `is_ca=False` that do not issue any other certificate in the bundle.
3. **Automatic Disambiguation**:
   - If exactly one candidate leaf exists, it is selected as the leaf.
   - If multiple candidates exist and `target_hostname` is provided, the candidate matching `target_hostname` is selected.
   - If multiple candidates exist without `target_hostname` (or multiple match), the engine safely emits:
     - `verdict = "INCONCLUSIVE"`
     - Finding: `RULE_AMBIGUOUS_BUNDLE_MULTIPLE_LEAVES` (-60 deduction).

---

## 5. Resource Limits & DoS Mitigations

To protect worker memory and CPU against malicious payloads:

- **Max Payload Size**: Capped at **10 MB** (`MAX_INPUT_BYTES`). Exceeding inputs trigger `ResourceLimitExceededError` and return `RULE_RESOURCE_LIMIT_EXCEEDED` / `INCONCLUSIVE`.
- **Max Bundle Certificates**: Capped at **50 certificates** (`MAX_BUNDLE_CERTS`).
- **Max Subject Alternative Names**: Capped at **10,000 SANs** (`MAX_SAN_COUNT`) to prevent regex/wildcard DoS.

---

## 6. Performance Characteristics

- **Warm-Cache Path Validation**: **14 microseconds (0.014 ms)**, >70,000 ops/sec.
- **Full `analyze_certificate()` Pipeline**: **0.25 ms (253 us)** median, >3,900 ops/sec per CPU core.
- **RFC 9525 Hostname Matching**: **3.0 microseconds**, >330,000 ops/sec.
- **Zero-Blocking Invariant**: ML inference runs via `predict_safe()` and will never block or raise exceptions during deterministic assessment.

---

## 7. Database Persistence (PostgreSQL Schema)

```sql
CREATE TABLE certificate_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_hostname VARCHAR(255) NOT NULL,
    certificate_sha256 VARCHAR(64) NOT NULL,
    trust_score SMALLINT NOT NULL CHECK (trust_score BETWEEN 0 AND 100),
    verdict VARCHAR(20) NOT NULL CHECK (verdict IN ('TRUSTED', 'WARNING', 'DISTRUSTED', 'INCONCLUSIVE')),
    confidence NUMERIC(3, 2) NOT NULL,
    checks_completed SMALLINT NOT NULL,
    policy_evaluation JSONB,
    ml_advisory JSONB,
    assessment_payload JSONB NOT NULL,
    scanned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cert_scans_sha256 ON certificate_scans(certificate_sha256);
CREATE INDEX idx_cert_scans_hostname ON certificate_scans(target_hostname);
CREATE INDEX idx_cert_scans_verdict ON certificate_scans(verdict);
```
