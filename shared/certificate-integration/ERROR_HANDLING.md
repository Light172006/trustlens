# Error Handling & Edge-Case Architecture — TrustLens Certificate Analyzer

## Overview

The **TrustLens Certificate Analyzer** is engineered with a strict **Fail-Safe Contract**:

1. **Non-Crashing Public Interfaces**: Public API entrypoints (`analyze_certificate()`, `analyze_pem()`, `analyze_endpoint_tls()`) will **never throw unhandled exceptions or crash the calling service** when passed corrupt, truncated, non-standard, or malicious inputs.
2. **Structured Findings**: Failures are captured as structured, deterministic findings within a `CertificateAssessment` object.
3. **Internal Typed Exception Hierarchy**: For internal subsystem isolation, diagnostics, and custom workflows, the engine provides strongly-typed exceptions defined in `certificate_analyzer.errors`.

---

## 1. Standard Error Codes (`AnalysisErrorCode`)

Standardized operational error codes identify edge cases and failures:

| Error Code | Enum Member | Description |
|:---|:---|:---|
| `INVALID_CERTIFICATE` | `AnalysisErrorCode.INVALID_CERTIFICATE` | Certificate bytes are malformed, corrupt, or unparseable ASN.1. |
| `EMPTY_CERTIFICATE` | `AnalysisErrorCode.EMPTY_CERTIFICATE` | Input data is null, empty string, or 0 bytes. |
| `UNSUPPORTED_CERTIFICATE_FORMAT` | `AnalysisErrorCode.UNSUPPORTED_CERTIFICATE_FORMAT` | Object type is not bytes, PEM string, or supported mapping. |
| `MULTIPLE_LEAF_CERTIFICATES` | `AnalysisErrorCode.MULTIPLE_LEAF_CERTIFICATES` | PEM bundle contains multiple non-CA leaves with no matching hostname. |
| `RESOURCE_LIMIT_EXCEEDED` | `AnalysisErrorCode.RESOURCE_LIMIT_EXCEEDED` | Input exceeded 10 MB, 50 bundle certs, or 10,000 SANs (DoS mitigation). |
| `HOSTNAME_NOT_PROVIDED` | `AnalysisErrorCode.HOSTNAME_NOT_PROVIDED` | Target hostname context was omitted; identity check skipped. |
| `CHAIN_INCOMPLETE` | `AnalysisErrorCode.CHAIN_INCOMPLETE` | Intermediate CA certificates are missing from the TLS bundle. |
| `CHAIN_VALIDATION_FAILED` | `AnalysisErrorCode.CHAIN_VALIDATION_FAILED` | Digital signature verification failed along the certification path. |
| `TRUST_STORE_UNAVAILABLE` | `AnalysisErrorCode.TRUST_STORE_UNAVAILABLE` | Mozilla root store or custom trust store directory could not be loaded. |
| `REVOCATION_UNAVAILABLE` | `AnalysisErrorCode.REVOCATION_UNAVAILABLE` | OCSP / CRL endpoints timed out or returned HTTP 5xx errors. |
| `MODEL_UNAVAILABLE` | `AnalysisErrorCode.MODEL_UNAVAILABLE` | ML advisory joblib artifacts are missing or corrupt. |
| `INTERNAL_ANALYSIS_ERROR` | `AnalysisErrorCode.INTERNAL_ANALYSIS_ERROR` | Catch-all for unanticipated internal operational errors. |

---

## 2. Typed Exception Hierarchy

All exceptions inherit from `CertificateAnalyzerError`:

```text
CertificateAnalyzerError (base exception)
├── InvalidCertificateError
├── EmptyCertificateError
├── UnsupportedCertificateFormatError
├── MultipleLeafCertificatesAmbiguityError
├── ResourceLimitExceededError
├── TrustStoreUnavailableError
└── ModelUnavailableError
```

Each exception provides structured error metadata via `.to_dict()`:

```python
from certificate_analyzer.errors import ResourceLimitExceededError

try:
    # Internal operation
    ...
except ResourceLimitExceededError as exc:
    print(exc.error_code)  # AnalysisErrorCode.RESOURCE_LIMIT_EXCEEDED
    print(exc.message)     # "Input certificate exceeds maximum size limit of 10485760 bytes"
    print(exc.details)     # {"size_bytes": 15000000, "max_allowed": 10485760}
```

---

## 3. Edge-Case Scenarios & Fail-Safe Resolutions

### 3.1 Malformed, Corrupted, or Truncated Input
When passed random binary noise, truncated ASN.1 structures, or invalid PEM:
- **Verdict**: `INCONCLUSIVE`
- **Trust Score**: `0`
- **Confidence**: `0.0`
- **Finding Emitted**: `RULE_MALFORMED_CERTIFICATE` (Severity: `CRITICAL`, Deduction: `-100`)
- **Evidence**: `{"error": "INVALID_ASN1_STRUCTURE", "detail": "..."}`

### 3.2 Empty Input
When passed `b""`, `""`, or whitespace:
- **Verdict**: `INCONCLUSIVE`
- **Trust Score**: `0`
- **Confidence**: `0.0`
- **Finding Emitted**: `RULE_MALFORMED_CERTIFICATE`
- **Evidence**: `{"error": "EMPTY_CERTIFICATE"}`

### 3.3 Resource Exhaustion / Denial-of-Service Defense
- **Input > 10 MB**: Input rejected immediately before ASN.1 parsing. Returns `INCONCLUSIVE` with `RULE_MALFORMED_CERTIFICATE` and `RULE_RESOURCE_LIMIT_EXCEEDED`.
- **Bundle > 50 Certificates**: Processing capped; returns `INCONCLUSIVE` with resource limit details.
- **Certificate > 10,000 SANs**: Truncated safely; prevents regex and wildcard CPU denial-of-service.

### 3.4 Ambiguous PEM Bundle with Multiple Leaves
When a PEM bundle contains multiple non-CA leaf certificates (e.g. concatenated independent server certs):
1. **With `target_hostname`**: The engine inspects all candidate leaves for SAN/CN matching. If exactly one candidate matches `target_hostname`, it automatically selects it as the target leaf and treats remaining certificates as chain context.
2. **Without `target_hostname` or Multiple Matches**: If ambiguity cannot be resolved, the engine safely returns:
   - **Verdict**: `INCONCLUSIVE`
   - **Trust Score**: `0`
   - **Finding Emitted**: `RULE_AMBIGUOUS_BUNDLE_MULTIPLE_LEAVES` (Severity: `HIGH`, Deduction: `-60`)
   - **Evidence**: `{"candidate_count": 3, "candidate_subjects": ["CN=app1", "CN=app2"]}`
   - **Recommendation**: "Provide target_hostname context to identify the intended leaf certificate or supply a single certificate bundle."

### 3.5 Missing Intermediate vs Invalid Cryptographic Signature
The engine clearly separates structural omission from cryptographic forgery:
- **Missing Intermediate**: `RULE_INCOMPLETE_CERTIFICATION_PATH` (Severity: `HIGH`, Deduction: `-70`). The leaf cannot link to a trusted root, but the certificate itself is not fraudulent.
- **Cryptographic Signature Forgery**: `RULE_INVALID_CERTIFICATE_SIGNATURE` (Severity: `CRITICAL`, Deduction: `-100`). Parent public key mathematically rejects the signature. Unconditionally `DISTRUSTED`.

### 3.6 Revocation Telemetry Outages
If an OCSP responder times out, is unreachable, or returns HTTP 5xx:
- Status is recorded strictly as `UNKNOWN` or `ERROR`.
- **Safety Invariant**: An `UNKNOWN` revocation state **NEVER** defaults to `GOOD`.
- The engine applies `RULE_REVOCATION_STATUS_UNKNOWN` (Deduction: `-5`), caps `confidence` at `0.70`, and alerts the caller that freshness could not be confirmed.

### 3.7 Machine Learning Inference Failure
If `include_ml_advisory=True` is requested but model artifacts are missing, corrupt, or encounter incompatible input:
- The ML advisor uses `CertificateMLAdvisor.predict_safe()`.
- Inference fails silently and non-blockingly, setting `assessment.ml_advisory = None`.
- **Invariant**: ML inference failures **never** impact the deterministic `trust_score`, `verdict`, or `findings`.
