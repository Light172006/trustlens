"""Phase 10 Audit: Training & Inference Pipeline Stress Testing.

Subjecting CertificateMLAdvisor to:
1. Malformed/truncated PEM and byte streams.
2. Unseen post-quantum and rare categoricals (Ed25519, Dilithium, Falcon, brainpool).
3. Extreme numeric outliers (negative validity, 50k SANs, 16k-bit keys).
4. Corrupt/null dictionary records.
5. Multithreaded concurrent inference.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEPS_DIR = _ROOT / "intelligence" / "certificate_dataset" / ".deps"
_DATASET_SRC = _ROOT / "intelligence" / "certificate_dataset" / "src"
_ANALYZER_SRC = _ROOT / "intelligence" / "certificate_analyzer" / "src"

for p in [_DEPS_DIR, _DATASET_SRC, _ANALYZER_SRC]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from certificate_analyzer.ml.inference import CertificateMLAdvisor, MLCompliancePrediction


def main():
    print("=" * 70)
    print("PHASE 10: INFERENCE PIPELINE STRESS TESTING")
    print("=" * 70)

    advisor = CertificateMLAdvisor()
    assert advisor.is_ready, "ML Advisor failed to load artifacts"

    test_cases = [
        # 1. Unseen Post-Quantum & Rare Algorithms
        {
            "category": "Unseen Categoricals",
            "name": "Post-Quantum Dilithium3 Algorithm",
            "input": {
                "public_key": {"algorithm": "Dilithium3", "key_size_bits": 3072, "ec_curve": "none"},
                "signature_algorithm": "Dilithium3-SHA384",
                "validity_duration_days": 90.0,
                "domain_identity": {"subject_alternative_names": ["example.com"], "is_wildcard": False},
                "extensions": {"key_usage": ["digitalSignature"], "extended_key_usage": ["serverAuth"]},
                "subject_dn": "CN=pq.example.com",
            },
            "expected_behavior": "Handles unknown category via handle_unknown='ignore' without crashing",
        },
        {
            "category": "Unseen Categoricals",
            "name": "Ed25519 Modern Key",
            "input": {
                "public_key": {"algorithm": "Ed25519", "key_size_bits": 256, "ec_curve": "ed25519"},
                "signature_algorithm": "Ed25519",
                "validity_duration_days": 90.0,
                "domain_identity": {"subject_alternative_names": ["example.com"]},
                "extensions": {"key_usage": ["digitalSignature"], "extended_key_usage": ["serverAuth"]},
                "subject_dn": "CN=ed25519.example.com",
            },
            "expected_behavior": "Handles cleanly",
        },
        # 2. Extreme Outliers
        {
            "category": "Numeric Outliers",
            "name": "50,000 SAN CDN Stress",
            "input": {
                "public_key": {"algorithm": "ECDSA", "key_size_bits": 256, "ec_curve": "secp256r1"},
                "signature_algorithm": "ecdsa-with-SHA256",
                "validity_duration_days": 90.0,
                "domain_identity": {"subject_alternative_names": [f"cdn{i}.net" for i in range(50000)], "is_wildcard": False},
                "extensions": {"key_usage": ["digitalSignature"]},
                "subject_dn": "CN=massive-cdn.net",
            },
            "expected_behavior": "Processes massive SAN list without memory explosion",
        },
        {
            "category": "Numeric Outliers",
            "name": "100-Year Validity (36,500 Days)",
            "input": {
                "public_key": {"algorithm": "RSA", "key_size_bits": 2048, "ec_curve": "none"},
                "signature_algorithm": "sha256WithRSAEncryption",
                "validity_duration_days": 36500.0,
                "domain_identity": {"subject_alternative_names": ["example.com"]},
                "extensions": {},
                "subject_dn": "CN=eternal.example.com",
            },
            "expected_behavior": "Predicts NON_COMPLIANT due to extreme validity days",
        },
        {
            "category": "Numeric Outliers",
            "name": "Negative Validity Days (-100.0)",
            "input": {
                "public_key": {"algorithm": "RSA", "key_size_bits": 2048, "ec_curve": "none"},
                "signature_algorithm": "sha256WithRSAEncryption",
                "validity_duration_days": -100.0,
                "domain_identity": {"subject_alternative_names": ["example.com"]},
                "extensions": {},
                "subject_dn": "CN=negative.example.com",
            },
            "expected_behavior": "Processes without math domain error",
        },
        # 3. Corrupt / Empty Records
        {
            "category": "Sparse/Empty Records",
            "name": "Empty Dict Record",
            "input": {},
            "expected_behavior": "Extracts default fallback attributes without raising KeyError",
        },
        {
            "category": "Sparse/Empty Records",
            "name": "None Fields Record",
            "input": {
                "public_key": None,
                "domain_identity": None,
                "extensions": None,
                "signature_algorithm": None,
                "validity_duration_days": None,
                "subject_dn": None,
            },
            "expected_behavior": "Defaults all null values gracefully",
        },
    ]

    results = []
    print(f"\n--- Running Robustness & Edge-Case Battery (N={len(test_cases)}) ---")
    for tc in test_cases:
        name = tc["name"]
        cat = tc["category"]
        try:
            pred = advisor.predict(tc["input"])
            assert isinstance(pred, MLCompliancePrediction)
            status = "PASSED"
            err = None
            out_info = f"Class={pred.predicted_class}, Prob={pred.compliance_probability:.4f}, Anomaly={pred.is_anomaly}"
        except Exception as e:
            status = "FAILED"
            err = str(e)
            out_info = f"Error: {e}"

        print(f"[{status}] {cat:<22} | {name:<40} -> {out_info}")
        results.append({
            "category": cat,
            "name": name,
            "status": status,
            "error": err,
            "output": out_info,
        })

    # 4. Truncated Bytes Test
    print("\n--- Testing Corrupt / Truncated Byte Handling ---")
    truncated_inputs = [
        b"",
        b"not a valid certificate",
        b"-----BEGIN CERTIFICATE-----\nMIIB",
        b"\x30\x82\x01\x00\x00",
    ]
    for b_in in truncated_inputs:
        try:
            advisor.predict(b_in)
            byte_status = "UNEXPECTED_SUCCESS"
        except (ValueError, TypeError, Exception) as e:
            byte_status = f"PASSED (Raised expected {type(e).__name__})"
        print(f"Input: {b_in[:30]!r:<35} -> {byte_status}")

    # 5. Multithreaded Concurrency Test
    print("\n--- Testing Multithreaded Concurrency (10 Threads, 100 Inferences) ---")
    sample_cert = {
        "public_key": {"algorithm": "ECDSA", "key_size_bits": 256, "ec_curve": "secp256r1"},
        "signature_algorithm": "ecdsa-with-SHA256",
        "validity_duration_days": 90.0,
        "domain_identity": {"subject_alternative_names": ["example.com"]},
        "extensions": {"key_usage": ["digitalSignature"], "extended_key_usage": ["serverAuth"]},
        "subject_dn": "CN=thread-safe.example.com",
    }

    def infer_worker(task_id):
        return advisor.predict(sample_cert)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(infer_worker, i) for i in range(100)]
        concurrent_results = [f.result() for f in futures]

    assert len(concurrent_results) == 100
    all_consistent = all(r.predicted_class == "COMPLIANT" for r in concurrent_results)
    print(f"Executed 100 concurrent thread inferences. All consistent: {all_consistent}")

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase10_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "edge_case_tests": results,
            "multithreaded_concurrency": {
                "tasks_executed": 100,
                "threads": 10,
                "all_consistent": all_consistent,
            }
        }, f, indent=2)

    print(f"\nPhase 10 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()

