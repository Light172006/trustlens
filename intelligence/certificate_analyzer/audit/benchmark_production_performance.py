"""Production performance and latency benchmarking suite for Certificate Analyzer.

Measures all 12 operational stages:
1. DER parsing
2. PEM parsing
3. Certificate feature extraction
4. Hostname verification (RFC 9525)
5. Chain validation (RFC 5280) - cold vs warm cache
6. Trust-store loading
7. Revocation evidence parsing
8. CT evidence parsing
9. Rule execution
10. Complete analysis (analyze_certificate)
11. ML advisory inference
12. Batch analysis throughput
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEPS_DIR = _ROOT / "intelligence" / "certificate_dataset" / ".deps"
_DATASET_SRC = _ROOT / "intelligence" / "certificate_dataset" / "src"
_ANALYZER_SRC = _ROOT / "intelligence" / "certificate_analyzer" / "src"

for p in [_DEPS_DIR, _DATASET_SRC, _ANALYZER_SRC]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import numpy as np
from cryptography import x509

from certificate_analyzer.api import analyze_certificate
from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine
from certificate_analyzer.engine.path_validator import CertificationPathValidator
from certificate_analyzer.features.extractor import CertificateFeatureExtractor
from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.inference import CertificateMLAdvisor
from certificate_analyzer.rules.ct_verifier import CertificateTransparencyVerifier
from certificate_analyzer.rules.engine import CertificateRuleEngine
from certificate_analyzer.rules.identity_rfc9525 import RFC9525IdentityVerifier
from certificate_analyzer.rules.revocation_verifier import RevocationRules
from certificate_dataset.parsing.parser import X509CertificateParser
from certificate_dataset.trust_stores.root_store import TrustStoreManager


def measure_latencies(fn, iterations=100, warmup=10):
    for _ in range(warmup):
        fn()
    latencies = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        latencies.append((time.perf_counter() - t0) * 1e6)  # microseconds
    return {
        "median_us": float(np.median(latencies)),
        "p95_us": float(np.percentile(latencies, 95)),
        "min_us": float(np.min(latencies)),
        "max_us": float(np.max(latencies)),
        "throughput_ops_sec": float(1e6 / np.median(latencies)),
    }


def main():
    print("=" * 75)
    print("CERTIFICATE ANALYZER PRODUCTION PERFORMANCE BENCHMARK")
    print("=" * 75)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    sample_records = splits["test"][:50]
    sample_rec = sample_records[0]

    # Reconstruct raw PEM and DER
    cert_pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + sample_rec["der_base64"]
        + "\n-----END CERTIFICATE-----"
    )
    import base64
    cert_der = base64.b64decode(sample_rec["der_base64"])
    cert_obj = x509.load_der_x509_certificate(cert_der)

    print(f"Sample Certificate Subject: {sample_rec.get('subject_dn')[:60]}...")
    print(f"DER Size: {len(cert_der)} bytes | PEM Size: {len(cert_pem)} bytes")

    results = {}

    # 1. DER Parsing
    print("\n1. Benchmarking DER Parsing...")
    res_der = measure_latencies(lambda: X509CertificateParser.parse(cert_der))
    results["der_parsing"] = res_der
    print(f"   Median: {res_der['median_us']:.2f} us | P95: {res_der['p95_us']:.2f} us | Throughput: {res_der['throughput_ops_sec']:.0f} ops/sec")

    # 2. PEM Parsing
    print("2. Benchmarking PEM Parsing...")
    res_pem = measure_latencies(lambda: X509CertificateParser.parse(cert_pem.encode("ascii")))
    results["pem_parsing"] = res_pem
    print(f"   Median: {res_pem['median_us']:.2f} us | P95: {res_pem['p95_us']:.2f} us | Throughput: {res_pem['throughput_ops_sec']:.0f} ops/sec")

    # 3. Certificate Feature Extraction
    print("3. Benchmarking Feature Extraction...")
    ref_time = datetime.now(timezone.utc)
    res_feat = measure_latencies(lambda: CertificateFeatureExtractor.extract(sample_rec, reference_time=ref_time))
    results["feature_extraction"] = res_feat
    print(f"   Median: {res_feat['median_us']:.2f} us | P95: {res_feat['p95_us']:.2f} us | Throughput: {res_feat['throughput_ops_sec']:.0f} ops/sec")

    # 4. Hostname Verification (RFC 9525)
    print("4. Benchmarking RFC 9525 Identity Verification...")
    dns_sans = sample_rec.get("domain_identity", {}).get("dns_san_entries", ["example.com"])
    target_host = dns_sans[0] if dns_sans else "example.com"
    res_id = measure_latencies(lambda: RFC9525IdentityVerifier.verify(target_host, dns_sans, []))
    results["hostname_verification"] = res_id
    print(f"   Median: {res_id['median_us']:.2f} us | P95: {res_id['p95_us']:.2f} us | Throughput: {res_id['throughput_ops_sec']:.0f} ops/sec")

    # 5. Chain Validation (RFC 5280) - Cold vs Warm
    print("5. Benchmarking Path Validation (RFC 5280)...")
    store = TrustStoreManager()
    store.load_from_certifi()

    # Cold Cache
    CertificationPathValidator.clear_cache()
    t_cold_start = time.perf_counter()
    _ = CertificationPathValidator.validate_path(cert_obj, [], store, reference_time=ref_time)
    cold_lat_us = (time.perf_counter() - t_cold_start) * 1e6

    # Warm Cache
    res_warm = measure_latencies(lambda: CertificationPathValidator.validate_path(cert_obj, [], store, reference_time=ref_time))
    results["chain_validation"] = {
        "cold_cache_us": float(cold_lat_us),
        "warm_cache": res_warm,
    }
    print(f"   Cold Cache Latency: {cold_lat_us:.2f} us ({cold_lat_us/1000.0:.3f} ms)")
    print(f"   Warm Cache Median:  {res_warm['median_us']:.2f} us ({res_warm['median_us']/1000.0:.3f} ms) | P95: {res_warm['p95_us']:.2f} us | Throughput: {res_warm['throughput_ops_sec']:.0f} ops/sec")

    # 6. Trust-Store Loading
    print("6. Benchmarking Trust-Store Loading...")
    def load_store():
        s = TrustStoreManager()
        s.load_from_certifi()
        return s
    res_store = measure_latencies(load_store, iterations=20, warmup=2)
    results["trust_store_loading"] = res_store
    print(f"   Median: {res_store['median_us']/1000.0:.2f} ms | P95: {res_store['p95_us']/1000.0:.2f} ms")

    # 7. Revocation Evidence Parsing
    print("7. Benchmarking Revocation Evidence Evaluation...")
    rev_obs = {
        "normalized_status": "GOOD",
        "revocation_method": "OCSP",
        "this_update": "2026-03-01T00:00:00Z",
        "next_update": "2026-03-10T00:00:00Z",
    }
    res_rev = measure_latencies(lambda: RevocationRules.evaluate_revocation_observation(rev_obs, ref_time))
    results["revocation_evaluation"] = res_rev
    print(f"   Median: {res_rev['median_us']:.2f} us | P95: {res_rev['p95_us']:.2f} us | Throughput: {res_rev['throughput_ops_sec']:.0f} ops/sec")

    # 8. CT Evidence Parsing
    print("8. Benchmarking CT Evidence Verification...")
    res_ct = measure_latencies(lambda: CertificateTransparencyVerifier.audit_ct(cert_obj))
    results["ct_audit"] = res_ct
    print(f"   Median: {res_ct['median_us']:.2f} us | P95: {res_ct['p95_us']:.2f} us | Throughput: {res_ct['throughput_ops_sec']:.0f} ops/sec")

    # 9. Rule Execution
    print("9. Benchmarking Rule Engine...")
    features = CertificateFeatureExtractor.extract(sample_rec, reference_time=ref_time)
    rule_engine = CertificateRuleEngine()
    res_rules = measure_latencies(lambda: rule_engine.evaluate_all(features, sample_rec, reference_time=ref_time))
    results["rule_execution"] = res_rules
    print(f"   Median: {res_rules['median_us']:.2f} us | P95: {res_rules['p95_us']:.2f} us | Throughput: {res_rules['throughput_ops_sec']:.0f} ops/sec")

    # 10. Complete Analysis Pipeline (analyze_certificate)
    print("10. Benchmarking Complete analyze_certificate() Pipeline...")
    engine = CertificateAnalyzerEngine()
    res_full = measure_latencies(lambda: analyze_certificate(cert_der, target_hostname=target_host, reference_time=ref_time, engine=engine))
    results["complete_analysis"] = res_full
    print(f"   Median: {res_full['median_us']/1000.0:.2f} ms ({res_full['median_us']:.1f} us) | P95: {res_full['p95_us']/1000.0:.2f} ms | Throughput: {res_full['throughput_ops_sec']:.0f} ops/sec")

    # 11. ML Advisory Inference
    print("11. Benchmarking ML Advisory Inference...")
    advisor = CertificateMLAdvisor()
    res_ml = measure_latencies(lambda: advisor.predict_safe(sample_rec))
    results["ml_inference"] = res_ml
    print(f"   Median: {res_ml['median_us']/1000.0:.2f} ms | P95: {res_ml['p95_us']/1000.0:.2f} ms | Throughput: {res_ml['throughput_ops_sec']:.0f} ops/sec")

    # 12. Batch Analysis Throughput (50 distinct real certificates)
    print("12. Benchmarking Batch Analysis Throughput (50 real leaf certs)...")
    batch_raw = [base64.b64decode(r["der_base64"]) for r in sample_records]
    t_batch_start = time.perf_counter()
    for der in batch_raw:
        _ = analyze_certificate(der, reference_time=ref_time, engine=engine)
    batch_total_ms = (time.perf_counter() - t_batch_start) * 1e3
    batch_throughput = len(batch_raw) / (batch_total_ms / 1000.0)
    results["batch_analysis"] = {
        "batch_size": len(batch_raw),
        "total_time_ms": float(batch_total_ms),
        "avg_per_cert_ms": float(batch_total_ms / len(batch_raw)),
        "batch_throughput_certs_sec": float(batch_throughput),
    }
    print(f"   Total Time (50 certs): {batch_total_ms:.2f} ms | Avg per cert: {batch_total_ms/len(batch_raw):.2f} ms | Batch Throughput: {batch_throughput:.1f} certs/sec")

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "production_benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nBenchmark Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()
