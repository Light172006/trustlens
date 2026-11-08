# TrustLens Web Security Analyzer — Production Engine & Technical Manual

## Executive Summary

The **TrustLens Web Security Analyzer** is an enterprise-grade, evidence-backed security posture evaluation engine. It enables automated, passive, and defensible inspection of target websites to assess their technical security configurations across Transport Layer Security (TLS/SSL), HTTP response security headers, cookie security attributes, DNS resilience, and redirect chains.

The system synthesizes two orthogonal assessment paradigms:
1. **Verifiable Deterministic Rules Engine**: Evaluates 22 strict technical security rules grounded in internet RFCs, NIST standards, CA/B Forum guidelines, and OWASP specifications.
2. **Calibrated Machine Learning Engine**: A `HistGradientBoostingClassifier` trained on **10,708 unique real-world domains** (Tranco Top-1M corpus), calibrated via Platt scaling, providing probabilistic posture ratings (`GOOD`, `MODERATE`, `POOR`) with built-in confidence and margin abstention.

### Architectural Invariant
> **Safety Guarantee**: Machine learning predictions can **NEVER** override verifiable technical weaknesses. Any confirmed `CRITICAL` vulnerability (e.g., expired certificate, plain HTTP without HTTPS, cleartext redirect downgrade) strictly forces the authoritative posture to `POOR` regardless of model optimism.

---

## 1. Repository Isolation & Code Protection Guarantee

This project was built under strict repository isolation constraints:
- **Exclusivity**: All newly created code, models, pipelines, tests, reports, and documentation reside strictly inside:
  ```text
  intelligence/web_security_analysis/
  ```
- **Zero Modifications Outside Authorized Scope**:
  - Backend files: **0 modified** (APIs, routes, models, database schemas untouched).
  - Frontend files: **0 modified** (React components, pages, hooks, UI untouched).
  - Threat Analysis & existing intelligence modules: **0 modified**.
  - Root dependency & configuration files: **0 modified**.

```text
intelligence/web_security_analysis/
│
├── analyzer/                             # Live Inspection & Analysis Engine
│   ├── cli.py                            # Production command-line interface
│   ├── engine.py                         # WebSecurityAnalyzer core orchestrator
│   ├── feature_extractor.py              # Safe asynchronous network telemetry collector
│   ├── ml_predictor.py                   # Calibrated ML predictor with abstention
│   ├── models.py                         # Typed Pydantic data schemas & contracts
│   ├── risk_aggregator.py                # Rubric scoring & safety invariant enforcement
│   ├── security_rules.py                 # 22 deterministic security rules
│   ├── ssrf_guard.py                     # Multi-tier SSRF network defense
│   └── url_validator.py                  # URL sanitizer, Punycode & port parser
│
├── dataset/                              # Production & Benchmark Datasets
│   ├── processed/
│   │   ├── web_security_dataset.parquet  # 10,708 real-world domains (canonical)
│   │   └── web_security_dataset.csv      # CSV analytical export
│   ├── raw/
│   │   └── source-specific/              # Raw JSONL telemetry streams & Tranco archive
│   ├── splits/                           # Zero-leakage partitioned splits
│   │   ├── train.parquet                 # 70% (7,495 domains)
│   │   ├── validation.parquet            # 15% (1,604 domains)
│   │   └── test.parquet                  # 15% (1,609 domains)
│   └── synthetic/
│       └── lab_dataset.parquet           # Isolated controlled test archetypes
│
├── metadata/                             # Schemas, Manifests & Provenance
│   ├── data_dictionary.json              # Schema specifications and column descriptions
│   ├── dataset_manifest.json             # SHA-256 cryptographic hashes & row counts
│   ├── label_taxonomy.json               # Finding definitions, severities & rubric
│   ├── quality_report.json               # Statistical distributions & completeness metrics
│   └── source_provenance.json            # Tranco citations, licenses & ethical constraints
│
├── models/                               # Serialized Model Artifacts
│   ├── best_model/
│   │   ├── model.joblib                  # Calibrated HistGradientBoosting model
│   │   └── preprocessor.joblib           # Scaler, Imputer & OneHotEncoder pipeline
│   └── model_metadata.json               # Artifact SHA-256 hashes & hyperparameter specs
│
├── reports/                              # Audit & Performance Documentation
│   ├── dataset_audit_report.md           # Dataset scale, uniqueness & quality audit
│   ├── model_evaluation_report.md        # 4-model evaluation, PR-AUC & confusion matrix
│   └── performance_benchmark_report.md   # Latency percentiles (P50, P95, P99) & throughput
│
├── scripts/                              # Data Collection & Engineering CLI Scripts
│   ├── audit_dataset.py                  # Comprehensive dataset health checker
│   ├── benchmark_analyzer.py             # Performance & latency benchmark runner
│   ├── collect.py                        # High-throughput asynchronous telemetry collector
│   ├── normalize.py                      # IDN normalization & Public Suffix List parser
│   ├── deduplicate.py                    # Registrable domain deduplication engine
│   ├── annotate.py                       # Multi-label finding annotator & rubric scorer
│   ├── create_splits.py                  # Zero-leakage stratified split generator
│   └── generate_lab_dataset.py           # Synthetic laboratory test case generator
│
├── tests/                                # Comprehensive Automated Test Suite (47 Tests)
│   ├── test_analyzer.py                  # SSRF, URL validation, rules, ML, and engine tests
│   ├── test_labels.py                    # Finding taxonomy, severity & evidence tests
│   ├── test_provenance.py                # Source attribution & privacy/token tests
│   ├── test_schema.py                    # Schema conformity & type enforcement tests
│   ├── test_splits.py                    # Zero-leakage domain isolation tests
│   └── test_uniqueness.py                # ≥10,000 domain scale & zero-duplicate tests
│
├── __main__.py                           # Module entry point (`python -m analyzer`)
├── config.yaml                           # Scanner timeouts, SSRF lists & thresholds
├── requirements.txt                      # Local dependency specifications
└── README.md                             # Comprehensive technical manual
```

---

## 2. Dataset Scale & Provenance

The production dataset was empirically measured and constructed from the **Tranco Top-1M Research List** (TU Delft / Université Côte d'Azur, CC-BY-4.0), resilient against algorithmic manipulation.

| Metric | Specification | Achieved Production Value | Status |
|:---|:---|:---|:---:|
| **Unique Registrable Domains** | **≥ 10,000** | **10,708** | ✅ PASS |
| **Duplicate Registrable Domains** | Strictly 0 | **0 (Zero)** | ✅ PASS |
| **Public Suffix Normalization** | Mozilla PSL (`tld.get_fld`) | 100% conforming | ✅ PASS |
| **Target Label in Features** | Strictly Forbidden | Verified Absent | ✅ PASS |
| **Zero-Leakage Partitioning** | 70% / 15% / 15% | Train: 7,495 / Val: 1,604 / Test: 1,609 | ✅ PASS |
| **Partition Domain Overlap** | Strictly 0 | **$\text{Train} \cap \text{Val} \cap \text{Test} = \emptyset$** | ✅ PASS |
| **Sensitive Tokens / Cookies** | Zero credentials or raw values | Verified 100% Redacted | ✅ PASS |

---

## 3. Machine Learning Training & Model Selection

### Candidate Comparison (Validation Partition, $N=1,604$)

Four candidate model families were evaluated using identical preprocessed feature matrices under stratified validation:

| Candidate Model | Accuracy | Macro F1 | Weighted F1 | Macro ROC-AUC | Log Loss | Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **HistGradientBoosting** | **99.38%** | **0.9879** | **0.9938** | **0.9998** | **0.0270** | 🏆 **SELECTED** |
| **Random Forest** | 98.63% | 0.9676 | 0.9859 | 0.9989 | 0.0898 | Evaluated |
| **Logistic Regression (L2)** | 98.32% | 0.9615 | 0.9830 | 0.9983 | 0.0577 | Evaluated |
| **Extra Trees** | 98.07% | 0.9550 | 0.9802 | 0.9989 | 0.0934 | Evaluated |

### Probability Calibration (Platt Scaling)
- The raw `HistGradientBoostingClassifier` outputs decision scores that can be overconfident on boundary cases.
- We fitted a sigmoid Platt calibrator (`CalibratedClassifierCV`) on the validation partition.
- **Brier Score improved from 0.0094 to 0.0052**, ensuring reliable posterior probabilities.

### Final Held-Out Test Set Performance ($N=1,609$ Unseen Domains)

| Evaluation Metric | Value | Production Requirement |
|:---|:---:|:---:|
| **Overall Accuracy** | **99.44%** | $\ge 90.0\%$ |
| **Balanced Accuracy** | **99.29%** | $\ge 88.0\%$ |
| **Macro-averaged F1 Score** | **99.28%** | $\ge 85.0\%$ |
| **Macro-averaged ROC-AUC** | **0.9999** | $\ge 0.95$ |
| **False GOOD on POOR Rate** | **0.24%** (1 in 410) | $\le 2.0\%$ |

---

## 4. Live Analyzer Engine Architecture

### A. SSRF Defense Guard (`ssrf_guard.py`)
Provides non-bypassable, multi-layered network isolation:
1. **Loopback Filter**: Rejects `127.0.0.0/8`, `::1`, `localhost`.
2. **Private Network Filter**: Rejects RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and RFC 4193 (`fc00::/7`).
3. **Link-Local & Multicast**: Rejects `169.254.0.0/16`, `fe80::/10`, `224.0.0.0/4`.
4. **Cloud Metadata Endpoints**: Rejects AWS/GCP/Azure link-local (`169.254.169.254`, `169.254.169.253`), Alibaba Cloud (`100.100.100.200`), and internal hostnames (`metadata.google.internal`, `instance-data`).
5. **Alternative Encodings**: Decodes integer dwords (`2130706433`), hexadecimal IPs (`0x7f000001`), octal representations, and IPv4-mapped IPv6 (`::ffff:127.0.0.1`).
6. **DNS Resolution Verification**: Pre-resolves domain before initiating HTTP connection and verifies **all** resolved IP addresses.

### B. Safe Live Feature Extractor (`feature_extractor.py`)
- Executes safe, passive HTTP and TLS inspection asynchronously using `aiohttp` and `cryptography`.
- Enforces strict socket timeouts (default: 5.0 seconds).
- Validates SSRF safety on **every redirect hop** up to a maximum of 5 hops.
- Inspects TLS certificates, SANs, validity windows, cipher suites, response headers, cookie flags, and DNS records.

### C. Deterministic Security Rules Engine (`security_rules.py`)
Evaluates 22 concrete security rules across 6 security categories:
- `TLS-MISSING-HTTPS`: Plain HTTP active with no HTTPS listener.
- `TLS-CERT-EXPIRED`: Expired certificate (RFC 5280).
- `TLS-SELF-SIGNED`: Production certificate subject equals issuer.
- `TLS-HOSTNAME-MISMATCH`: Requested domain absent from certificate SANs (RFC 6125).
- `TLS-VERSION-DEPRECATED`: Use of deprecated TLS 1.0 or TLS 1.1 (RFC 8996).
- `SEC-HSTS-MISSING`: Missing `Strict-Transport-Security` header on HTTPS (RFC 6797).
- `SEC-CSP-MISSING`: Absent `Content-Security-Policy` header (W3C Level 3).
- `SEC-XFO-MISSING`: Absent clickjacking framing controls (RFC 7034).
- `SEC-XCTO-MISSING`: Absent MIME-sniffing protection `nosniff`.
- `COOKIE-MISSING-SECURE`: Transmission of cookies without `Secure` attribute over HTTPS.
- `COOKIE-MISSING-HTTPONLY`: State cookies accessible to client scripts without `HttpOnly`.
- `REDIR-INSECURE-DOWNGRADE`: Redirection from initial HTTPS to unencrypted HTTP.

### D. ML Predictor with Abstention (`ml_predictor.py`)
- Emits calibrated probability distributions across `GOOD`, `MODERATE`, and `POOR`.
- Computes confidence and margin between top two classes.
- **Abstention Triggers**:
  - Unresolved domain $\to$ `INSUFFICIENT_EVIDENCE`.
  - Unreachable host $\to$ `INSUFFICIENT_EVIDENCE`.
  - Prediction confidence $< 0.55$ $\to$ Abstains with reason.
  - Confidence margin $< 0.10$ $\to$ Abstains with reason.

### E. Risk Aggregator & Invariant Enforcement (`risk_aggregator.py`)
- Computes numerical base score from 100.0 with severity deductions:
  - `CRITICAL` FAIL: -35.0 pts
  - `HIGH` FAIL: -20.0 pts
  - `MEDIUM` FAIL: -10.0 pts
  - `LOW` FAIL: -3.0 pts
- Enforces deterministic overrides: verified critical vulnerabilities cannot be masked by ML predictions.
- Prioritizes remediation actions by severity rank (`CRITICAL` $\to$ `HIGH` $\to$ `MEDIUM` $\to$ `LOW`).

---

## 5. Command-Line Interface (CLI) Manual

The analyzer provides a standalone CLI via `python -m analyzer` or `python analyzer/cli.py`.

### Basic Usage

```bash
# Analyze a target domain
python -m analyzer https://example.com

# Analyze with JSON output
python -m analyzer https://github.com --json

# Analyze with custom timeout and strict exit codes
python -m analyzer https://cloudflare.com --timeout 8.0 --strict
```

### CLI Arguments & Options

| Option | Type | Default | Description |
|:---|:---:|:---:|:---|
| `url` | Positional | Required | Target website URL or domain name (e.g. `https://example.com`). |
| `--json` | Flag | `False` | Output structured JSON report to stdout instead of formatted terminal tables. |
| `--timeout` | Float | `5.0` | Maximum socket connection and handshake timeout in seconds. |
| `--strict` | Flag | `False` | Exit with status code `1` if posture is `POOR` or `INSUFFICIENT_EVIDENCE`. |

---

## 6. Programmatic Python SDK Integration

Applications can invoke the analyzer programmatically through synchronous or asynchronous APIs:

### Asynchronous API (`analyze_async`)

```python
import asyncio
from analyzer import WebSecurityAnalyzer

async def main():
    analyzer = WebSecurityAnalyzer.from_config()
    report = await analyzer.analyze_async("https://cloudflare.com")
    
    print(f"Target: {report.target_url}")
    print(f"Overall Posture: {report.posture}")
    print(f"Security Score: {report.security_score}/100.0")
    print(f"Consensus Status: {report.consensus.status}")
    print(f"Critical Findings: {report.findings_summary.critical_count}")
    
    for r in report.remediations:
        print(f"[{r.severity}] {r.recommendation}")

asyncio.run(main())
```

### Synchronous API (`analyze`)

```python
from analyzer import WebSecurityAnalyzer

analyzer = WebSecurityAnalyzer.from_config()
report = analyzer.analyze("https://github.com")

print(f"Posture: {report.posture}")
print(f"Calibrated Probabilities: {report.ml_prediction.probabilities}")
```

---

## 7. Performance & Latency Benchmark Results

Benchmarks were executed across **1,000 iterations** using held-out feature vectors (`scripts/benchmark_analyzer.py`):

| Pipeline Stage | Mean | P50 | P95 | P99 | Max |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Feature Transformation (Preprocessor)** | 15.11 ms | 14.24 ms | 22.27 ms | 33.11 ms | 85.19 ms |
| **Model Inference (`predict_proba`)** | 5.83 ms | 5.52 ms | 7.49 ms | 8.98 ms | 23.64 ms |
| **Deterministic Rules Engine** | 0.02 ms | 0.01 ms | 0.05 ms | 0.06 ms | 0.08 ms |
| **Risk Aggregation & Invariants** | 0.005 ms | 0.004 ms | 0.005 ms | 0.010 ms | 0.029 ms |
| **Total In-Memory Pipeline (Excl. I/O)** | **24.38 ms** | **23.93 ms** | **29.37 ms** | **35.33 ms** | **87.55 ms** |

- **In-Memory Assessment Throughput**: **41.0 evaluations/sec** on single CPU core.
- **Model Load Time**: **983 ms** (with full SHA-256 integrity validation).

---

## 8. Automated Test Suite (47 Passing Tests)

Run the full automated test suite using pytest:

```bash
pytest intelligence/web_security_analysis/tests/ -v
```

### Test Coverage Highlights
- **Schema & Types** (`test_schema.py`): Non-nullable fields, boolean representations, score bounds (0–100).
- **Scale & Uniqueness** (`test_uniqueness.py`): Verification of $\ge 10,000$ unique registrable domains, zero duplicates, Mozilla PSL normalization.
- **Labels & Rubric** (`test_labels.py`): Evidence presence on all `FAIL` findings, critical failure enforcement of `POOR` posture, score alignment.
- **Provenance & Privacy** (`test_provenance.py`): ISO 8601 timestamps, source provenance, zero raw cookie values or credentials.
- **Zero-Leakage Splits** (`test_splits.py`): 70/15/15 proportions, zero domain overlap across train/validation/test.
- **Analyzer Engine & SSRF** (`test_analyzer.py`): URL validation edge cases, SSRF blocking of 10+ attack vectors (loopback, private, cloud metadata, dword/hex IPs), deterministic rule firing, ML inference, confidence abstention, and end-to-end report generation.

---

## 9. Recommendations for Future TrustLens Integration

*(Note: Per scope restrictions, zero modifications were made to the backend or frontend during this project.)*

When the TrustLens core engineering team is ready to integrate this analyzer into the broader TrustLens platform, the following non-invasive integration pattern is recommended:

1. **Backend Integration**:
   - Add a lightweight service wrapper in `backend/services/web_security_service.py` that imports `WebSecurityAnalyzer` from `intelligence.web_security_analysis.analyzer.engine`.
   - Expose a REST endpoint in `backend/api/v1/endpoints/web_security.py` (e.g., `POST /api/v1/analyze/web-security`) accepting `{"url": "https://example.com"}` and returning `report.model_dump()`.
   - For batch or background jobs, enqueue the URL in Celery/Redis tasks using `analyzer.analyze_async(url)`.
2. **Frontend Integration**:
   - Create a dedicated component `frontend/src/components/WebSecurityCard.tsx` consuming the typed `WebSecurityReport` response.
   - Display the overall posture pill (`GOOD` green, `MODERATE` yellow, `POOR` red, `INSUFFICIENT_EVIDENCE` gray).
   - Render the numerical score dial (0–100) alongside the calibrated ML confidence bar and the prioritized remediation table.
