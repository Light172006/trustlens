# Configuration & Resource Limits Guide — TrustLens Certificate Analyzer

## Overview

This guide details configuration options, performance tuning parameters, resource protection limits, and environment controls for deploying the **TrustLens Certificate Analyzer** in production environments.

---

## 1. Engine Instantiation & Configuration

The primary runtime engine is `CertificateAnalyzerEngine`. It is designed to be instantiated once at worker boot and reused across millions of invocations:

```python
from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine

# Standard production initialization (recommended for Celery workers & FastAPI)
engine = CertificateAnalyzerEngine(
    cache_size=4096,               # LRU cache entries for path validation
    include_ml_advisory=False,     # Deterministic evaluation by default (opt-in ML)
)
```

### Passing to Public APIs:
All public entrypoints accept an optional `engine` parameter to avoid re-initializing caches per request:

```python
from certificate_analyzer.api import analyze_endpoint_tls, analyze_certificate

# Zero-allocation execution using pre-warmed engine
assessment = analyze_endpoint_tls(
    certificate_der=leaf_der,
    target_hostname="api.trustlens.io",
    engine=engine,
)
```

If `engine` is omitted, the API uses a process-level singleton instance automatically.

---

## 2. Resource Protection Limits (DoS / Resource Exhaustion Prevention)

To protect background workers and API gateways against crafted, oversized, or malicious inputs (e.g. decompression bombs or infinite extension loops), the engine enforces three strict input boundaries:

| Boundary Parameter | Limit | Enforcement Point | Exception Raised | Finding Emitted |
|:---|:---:|:---|:---|:---|
| `MAX_INPUT_BYTES` | **10 MB** (10,485,760 bytes) | Ingestion check on DER/PEM input | `ResourceLimitExceededError` | `RULE_MALFORMED_CERTIFICATE` / `RULE_RESOURCE_LIMIT_EXCEEDED` |
| `MAX_BUNDLE_CERTS` | **50 certificates** | PEM bundle parser | `ResourceLimitExceededError` | `RULE_AMBIGUOUS_BUNDLE_MULTIPLE_LEAVES` / `RULE_MALFORMED_CERTIFICATE` |
| `MAX_SAN_COUNT` | **10,000 SANs** | X.509 feature extraction & RFC 9525 verification | `ResourceLimitExceededError` | `RULE_RESOURCE_LIMIT_EXCEEDED` |

### Why these limits?
1. **Oversized inputs**: Legitimate Web PKI certificates average 1.5 KB to 3 KB. 10 MB accommodates any plausible certificate bundle while preventing memory exhaustion.
2. **Bundle cert limit**: Real-world TLS chains rarely exceed 4 certificates (Leaf -> Intermediate -> Cross-Signed Intermediate -> Root). 50 is a 10x safety ceiling.
3. **SAN explosion**: Defends against certificates with tens of thousands of wildcard entries engineered to consume regex/wildcard CPU cycles.

---

## 3. In-Memory Path Validation Cache

The `CertificationPathValidator` maintains an LRU cache of cryptographic chain verification results.

- **Default Cache Capacity**: `4,096` entries.
- **Cache Key**: Tuple of SHA-256 fingerprints `(leaf_sha256, [intermediate_sha256...])`.
- **Latency Impact**:
  - Cold validation (full crypto verification + signature check): **0.25 ms to 0.40 ms**.
  - Warm cache hit (zero-copy lookup): **14 microseconds (0.014 ms)** — **>70,000 checks/sec**.
- **Memory Footprint**: Less than 4 MB for 4,096 cached verification paths.

### Inspecting and Clearing Cache:
```python
# Check cache statistics in monitoring/health-check endpoints
info = engine.path_validator.cache_info()
print(f"Hits: {info['hits']}, Misses: {info['misses']}, Size: {info['currsize']}")

# Purge cache during maintenance or after trust store reload
engine.path_validator.clear_cache()
```

---

## 4. Trust Store Configuration

The analyzer bundles the **Mozilla Included CA Certificate List** (NSS Root Store) by default.

### Default Location:
`intelligence/certificate_dataset/data/trust_stores/mozilla_roots.json`

### Custom Root Store Loading:
To supplement with private corporate CAs or an internal enterprise PKI:

```python
from certificate_dataset.trust_stores.root_store import RootStore

custom_store = RootStore.load_from_directory("/etc/ssl/certs/enterprise_roots/")
engine = CertificateAnalyzerEngine(root_store=custom_store)
```

---

## 5. Machine Learning Advisory Controls

Machine learning inference is non-authoritative and opt-in:

| Setting | Default | Description |
|:---|:---:|:---|
| `include_ml_advisory` | `False` | When `False`, ML models are not evaluated, ensuring maximum throughput (>3,900 ops/sec). When `True`, the model pipeline runs safely in non-blocking mode. |

### Enabling per-request:
```python
assessment = analyze_certificate(
    certificate_input=cert_der,
    include_ml_advisory=True,
)

if assessment.ml_advisory:
    print(f"Class: {assessment.ml_advisory['predicted_class']}")
    print(f"Anomaly: {assessment.ml_advisory['is_anomaly']}")
```

---

## 6. Environment Variables

The analyzer recognizes the following optional environment variables for containerized deployments:

| Variable Name | Type | Default | Description |
|:---|:---:|:---|:---|
| `TRUSTLENS_ROOT_STORE_PATH` | `str` | Bundled Mozilla list | Path to a custom PEM bundle or JSON root store file. |
| `TRUSTLENS_CACHE_SIZE` | `int` | `4096` | Maximum entries in path validator LRU cache. |
| `TRUSTLENS_ENABLE_ML_ADVISORY` | `bool` | `false` | Global default for `include_ml_advisory` if not specified per call. |
| `TRUSTLENS_LOG_LEVEL` | `str` | `"INFO"` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

---

## 7. Concurrency & Thread-Safety Guarantees

- **Thread-Safety**: `CertificateAnalyzerEngine` is completely thread-safe. Multiple worker threads or asyncio executors may share a single engine instance.
- **Process Isolation**: In multi-process worker architectures (e.g. Gunicorn/Celery with `prefork`), initialize one engine per child process in the post-fork hook to ensure independent cache memory and file descriptors.
- **No Global Locks**: Analysis uses immutable data schemas and local cryptographic verification without acquiring global interpreter locks outside C-extensions (`cryptography`).

