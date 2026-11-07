"""Audit Module 3: Tranco Sampling Bias and Deep URL Generalization Stress Test.

Investigates whether Tranco benign samples are exclusively root URLs (https://domain/)
and tests the model against real-world benign deep URLs with paths and query parameters.
"""

import json
from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from trustlens_intelligence.datasets.feature_pipeline import BatchFeaturePipeline
from trustlens_intelligence.datasets.processing.allowlist import ML_INTRINSIC_FEATURE_NAMES
from trustlens_intelligence.datasets.processing.label_validator import ValidatedSample
from trustlens_intelligence.datasets.sources.registry import LabelCategory

BENIGN_DEEP_URLS = [
    # Documentation & Knowledge
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://docs.github.com/en/rest/reference/repos",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    "https://stackoverflow.com/questions/tagged/python?tab=votes&page=2",
    "https://stackoverflow.com/questions/1234567/how-do-i-parse-a-url-in-python",
    # E-Commerce & Portals
    "https://www.amazon.com/s?k=wireless+headphones&crid=3N5P",
    "https://www.amazon.com/gp/bestsellers/electronics/ref=zg_bs_nav_0",
    "https://www.ebay.com/b/Apple-Laptops/111422/bn_16480579?rt=nc&_udlo=500",
    "https://www.walmart.com/browse/electronics/laptops/3944_3951_1089430",
    # Tech & Software Repositories
    "https://github.com/torvalds/linux/commits/master",
    "https://github.com/psf/requests/releases/tag/v2.31.0",
    "https://gitlab.com/gitlab-org/gitlab/-/issues/12345",
    "https://hub.docker.com/_/python/tags?page=1&ordering=last_updated",
    "https://pypi.org/project/scikit-learn/#history",
    # News & Media
    "https://www.bbc.com/news/technology-68123456",
    "https://www.cnn.com/2026/01/15/tech/artificial-intelligence-trends/index.html",
    "https://www.nytimes.com/section/technology",
    "https://www.theverge.com/2026/2/1/tech-review-best-laptops",
    # Search & Cloud
    "https://www.google.com/search?q=trustlens+threat+intelligence+audit&hl=en",
    "https://aws.amazon.com/security/introduction/?sec-nav=true",
    "https://azure.microsoft.com/en-us/solutions/web-apps/",
    "https://cloud.google.com/bigquery/docs/quickstarts",
    "https://stripe.com/docs/api/charges/create",
]


def run_tranco_bias_audit():
    audit_dir = Path(__file__).resolve().parent
    data_dir = repo_root / "data" / "processed"
    df_full = pd.read_parquet(data_dir / "dataset_full.parquet")

    # 1. Structural Comparison: Tranco vs Threats
    df_tranco = df_full[df_full["source_id"] == "tranco"]
    df_threats = df_full[df_full["source_id"] != "tranco"]

    stats = {
        "tranco_sample_count": len(df_tranco),
        "threat_sample_count": len(df_threats),
        "path_length": {
            "tranco_mean": float(df_tranco["path_length"].mean()),
            "threat_mean": float(df_threats["path_length"].mean()),
            "tranco_pct_root_only": float((df_tranco["path_length"] <= 1).mean() * 100),
            "threat_pct_root_only": float((df_threats["path_length"] <= 1).mean() * 100),
        },
        "query_length": {
            "tranco_mean": float(df_tranco["query_length"].mean()),
            "threat_mean": float(df_threats["query_length"].mean()),
            "tranco_pct_has_query": float((df_tranco["query_length"] > 0).mean() * 100),
            "threat_pct_has_query": float((df_threats["query_length"] > 0).mean() * 100),
        },
        "url_length": {
            "tranco_mean": float(df_tranco["url_length"].mean()),
            "threat_mean": float(df_threats["url_length"].mean()),
        },
        "url_entropy": {
            "tranco_mean": float(df_tranco["url_entropy"].mean()),
            "threat_mean": float(df_threats["url_entropy"].mean()),
        },
        "is_ip_host": {
            "tranco_pct_ip": float(df_tranco["is_ip_host"].mean() * 100),
            "threat_pct_ip": float(df_threats["is_ip_host"].mean() * 100),
        },
    }

    # 2. Stress Test Model on Benign Deep URLs
    model_artifact_path = repo_root / "trustlens_intelligence" / "evaluation" / "artifacts" / "baseline_classifier.joblib"
    artifact = joblib.load(model_artifact_path)
    model = artifact["model"]
    feature_names = artifact["feature_names"]

    pipeline = BatchFeaturePipeline()
    deep_samples = []
    for u in BENIGN_DEEP_URLS:
        sample = ValidatedSample(
            url=u,
            canonical_url=u,
            registrable_domain=u.split("/")[2],
            label_category=LabelCategory.LEGITIMATE,
            binary_label=0,
            confidence=1.0,
            source_id="real_benign_audit",
            metadata={"status_code": 200, "domain_age_days": 3000},
        )
        deep_samples.append(sample)

    df_deep = pipeline.extract_dataframe(deep_samples)
    X_deep = df_deep[feature_names].copy()

    probas = model.predict_proba(X_deep)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_deep)
    preds = (probas >= 0.5).astype(int)

    false_positives = []
    for u, p, prob in zip(BENIGN_DEEP_URLS, preds, probas):
        if p == 1:
            false_positives.append({"url": u, "malicious_probability": float(prob)})

    deep_eval = {
        "total_benign_deep_urls": len(BENIGN_DEEP_URLS),
        "false_positive_count": len(false_positives),
        "false_positive_rate_on_deep_benign": float(len(false_positives) / len(BENIGN_DEEP_URLS)),
        "accuracy_on_deep_benign": float(1.0 - (len(false_positives) / len(BENIGN_DEEP_URLS))),
        "false_positive_examples": false_positives,
    }

    results = {
        "structural_bias_comparison": stats,
        "deep_benign_stress_test": deep_eval,
    }

    out_file = audit_dir / "audit_03_tranco_bias.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n=== TRANCO SAMPLING BIAS RESULTS ===")
    print(f"Tranco URLs that are Root Only (path <= 1): {stats['path_length']['tranco_pct_root_only']:.2f}%")
    print(f"Threat URLs that are Root Only (path <= 1): {stats['path_length']['threat_pct_root_only']:.2f}%")
    print(f"Tranco Mean Query Length: {stats['query_length']['tranco_mean']:.2f} vs Threat: {stats['query_length']['threat_mean']:.2f}")
    print(f"\nBenign Deep URLs Stress Test:")
    print(f"  Total Tested: {deep_eval['total_benign_deep_urls']}")
    print(f"  False Positives (Benign flagged as Malicious): {deep_eval['false_positive_count']}")
    print(f"  False Positive Rate on Real Deep Benign URLs: {deep_eval['false_positive_rate_on_deep_benign']*100:.2f}%")
    if false_positives:
        print("\nSample False Positive Blunders:")
        for fp in false_positives[:5]:
            print(f"  - [{fp['malicious_probability']:.4f}] {fp['url']}")


if __name__ == "__main__":
    run_tranco_bias_audit()

