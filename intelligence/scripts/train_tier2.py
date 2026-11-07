"""TrustLens Intelligence — Production Tier 2 Real-World Dataset Ingestion and Model Training.

Downloads verified real-world feeds:
1. Tranco Top Sites (100,000 Benign domains)
2. PhishTank (Verified online phishing URLs)
3. URLhaus (Active malware distribution endpoints)
4. OpenPhish (Community phishing feed)

Processes, canonicalizes, deduplicates, and splits by domain (0% leakage),
extracts 34 allowlisted intrinsic features, and trains production classifiers.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any
import httpx
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Ensure intelligence package is importable
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from trustlens_intelligence.config.constants import FEATURE_SCHEMA_VERSION, MODEL_SCHEMA_VERSION
from trustlens_intelligence.datasets.feature_pipeline import BatchFeaturePipeline
from trustlens_intelligence.datasets.pipeline import DatasetPipeline
from trustlens_intelligence.datasets.processing.allowlist import (
    ML_INTRINSIC_FEATURE_NAMES,
    filter_allowlisted_features,
)
from trustlens_intelligence.datasets.processing.deduplicator import DatasetDeduplicator
from trustlens_intelligence.datasets.processing.label_validator import (
    LabelValidator,
    ValidatedSample,
)
from trustlens_intelligence.datasets.processing.normalizer import URLNormalizer
from trustlens_intelligence.datasets.sources.openphish import OpenPhishSource
from trustlens_intelligence.datasets.sources.phishtank import PhishTankSource
from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    LabelCategory,
    RawRecord,
    SourceRegistry,
)
from trustlens_intelligence.datasets.sources.tranco import TrancoSource
from trustlens_intelligence.datasets.sources.urlhaus import URLhausSource
from trustlens_intelligence.datasets.splits.domain_split import (
    DomainSplitter,
    verify_zero_domain_leakage,
)
from trustlens_intelligence.datasets.storage.manifest import (
    DatasetManifest,
    create_manifest_from_dataframe,
)
from trustlens_intelligence.datasets.storage.parquet_store import ParquetStore
from trustlens_intelligence.evaluation.metrics import compute_classification_metrics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trustlens.tier2_trainer")


def download_tranco_records(target_count: int = 100000) -> list[RawRecord]:
    """Download and parse top legitimate domains from Tranco."""
    logger.info("Downloading Tranco top sites list (target: %d)...", target_count)
    api_url = "https://tranco-list.eu/api/lists/date/latest"
    with httpx.Client(timeout=30.0) as client:
        r = client.get(api_url)
        r.raise_for_status()
        list_info = r.json()
        list_id = list_info["list_id"]
        download_url = f"https://tranco-list.eu/download/{list_id}/{target_count}"
        logger.info("Fetching Tranco list ID: %s from %s", list_id, download_url)

        dl_resp = client.get(download_url)
        dl_resp.raise_for_status()
        lines = dl_resp.text.splitlines()

    tranco_source = TrancoSource()
    records = list(tranco_source.parse_lines(lines, max_records=target_count))
    logger.info("Ingested %d Tranco legitimate records", len(records))
    return records


def download_phishtank_records(target_count: int = 35000) -> list[RawRecord]:
    """Download verified online phishing records from PhishTank (with resilient mirror fallback)."""
    logger.info("Downloading PhishTank verified phishing database...")
    direct_url = "http://data.phishtank.com/data/online-valid.csv"
    fallback_url = "https://raw.githubusercontent.com/larranaga/phishing-url-detection/master/verified_online.csv"
    headers = {"User-Agent": "phishtank/trustlens-intelligence"}

    lines: list[str] = []
    try:
        with httpx.Client(timeout=30.0, headers=headers, follow_redirects=True) as client:
            resp = client.get(direct_url)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
            else:
                logger.warning("PhishTank direct endpoint returned %d, switching to verified mirror...", resp.status_code)
    except Exception as exc:
        logger.warning("PhishTank direct fetch failed (%s), switching to verified mirror...", exc)

    if not lines:
        logger.info("Fetching from verified PhishTank mirror: %s", fallback_url)
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get(fallback_url)
            resp.raise_for_status()
            lines = resp.text.splitlines()

    source = PhishTankSource()
    records = list(source.parse_lines(lines, max_records=target_count, only_verified=True))
    logger.info("Ingested %d PhishTank verified phishing records", len(records))
    return records


def download_urlhaus_records(target_count: int = 25000) -> list[RawRecord]:
    """Download active malware URLs from the daily URLhaus mirror."""
    logger.info("Downloading active URLhaus malware blocklist (target: %d)...", target_count)
    url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt"

    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        lines = resp.text.splitlines()

    records: list[RawRecord] = []
    now = datetime.now(timezone.utc)
    for line in lines:
        if len(records) >= target_count:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue

        raw_url = stripped if stripped.startswith(("http://", "https://")) else f"http://{stripped}"
        records.append(
            RawRecord(
                url=raw_url,
                source_id="urlhaus",
                raw_label=LabelCategory.MALWARE.value,
                timestamp=now,
                confidence=1.0,
                metadata={"threat": "malware_download", "source": "urlhaus_online_filter"},
            )
        )

    logger.info("Ingested %d URLhaus active malware records", len(records))
    return records


def download_openphish_records(target_count: int = 1000) -> list[RawRecord]:
    """Download real-time phishing feed from OpenPhish."""
    logger.info("Downloading OpenPhish community feed...")
    url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

    with httpx.Client(timeout=20.0, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        lines = resp.text.splitlines()

    source = OpenPhishSource()
    records = list(source.parse_lines(lines, max_records=target_count))
    logger.info("Ingested %d OpenPhish active records", len(records))
    return records


def run_tier2_training():
    """Main workflow: download, preprocess, split, extract, persist, train, and evaluate."""
    t_start = time.perf_counter()
    data_dir = repo_root / "data"
    raw_dir = data_dir / "raw"
    processed_dir = data_dir / "processed"
    raw_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)

    # 1. Ingestion
    logger.info("=== STEP 1: Ingesting Real-World Feeds ===")
    all_raw: list[RawRecord] = []
    all_raw.extend(download_tranco_records(target_count=100000))
    all_raw.extend(download_phishtank_records(target_count=35000))
    all_raw.extend(download_urlhaus_records(target_count=25000))
    all_raw.extend(download_openphish_records(target_count=1000))
    logger.info("Total raw ingested records across 4 feeds: %d", len(all_raw))

    # 2. Canonicalization, Deduplication & Validation
    logger.info("=== STEP 2: Normalization, Deduplication & Conflict Resolution ===")
    normalizer = URLNormalizer()
    deduplicator = DatasetDeduplicator(normalizer=normalizer, max_samples_per_domain=10)
    validator = LabelValidator()

    pipeline = DatasetPipeline(
        normalizer=normalizer,
        deduplicator=deduplicator,
        validator=validator,
    )
    validated_samples = pipeline.process_records(all_raw)
    logger.info(
        "Processed into %d unique validated samples (Dropped %d exact dupes, %d canonical dupes, %d domain-cap dupes)",
        len(validated_samples),
        deduplicator.stats.exact_duplicates_dropped,
        deduplicator.stats.canonical_duplicates_dropped,
        deduplicator.stats.domain_cap_dropped,
    )

    # 3. Batch Feature Extraction
    logger.info("=== STEP 3: Streaming Batch Feature Extraction (34 Allowlisted Features) ===")
    feature_pipeline = BatchFeaturePipeline()
    feature_df = feature_pipeline.extract_dataframe(validated_samples)
    logger.info(
        "Extracted feature matrix shape: %s with %d columns",
        feature_df.shape,
        len(feature_df.columns),
    )

    # 4. Domain-Aware Disjoint Splitting
    logger.info("=== STEP 4: Domain-Aware Disjoint Splitting (0% Domain Leakage) ===")
    splitter = DomainSplitter()
    splits = splitter.split(
        feature_df,
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        seed=42,
    )
    verify_zero_domain_leakage(splits)
    logger.info(
        "Splits generated: Train=%d samples (%d domains), Val=%d samples (%d domains), Test=%d samples (%d domains)",
        len(splits.train_df),
        len(splits.train_domains),
        len(splits.val_df),
        len(splits.val_domains),
        len(splits.test_df),
        len(splits.test_domains),
    )

    # 5. Columnar Parquet Persistence & Manifest
    logger.info("=== STEP 5: Parquet Columnar Persistence & Manifest ===")
    store = ParquetStore()
    files = {
        "full_dataset": processed_dir / "dataset_full.parquet",
        "train": processed_dir / "train.parquet",
        "val": processed_dir / "val.parquet",
        "test": processed_dir / "test.parquet",
    }
    store.write_table(feature_df, files["full_dataset"])
    store.write_table(splits.train_df, files["train"])
    store.write_table(splits.val_df, files["val"])
    store.write_table(splits.test_df, files["test"])

    source_attributions = [APPROVED_SOURCES[s].attribution_text for s in APPROVED_SOURCES]
    manifest = create_manifest_from_dataframe(
        df=feature_df,
        dataset_name="trustlens-tier2-production",
        version="2.0.0",
        files=files,
        source_attributions=source_attributions,
        extra_metadata={
            "train_samples": len(splits.train_df),
            "val_samples": len(splits.val_df),
            "test_samples": len(splits.test_df),
            "train_domains": len(splits.train_domains),
            "val_domains": len(splits.val_domains),
            "test_domains": len(splits.test_domains),
            "deduplication_stats": {
                "exact_duplicates_dropped": deduplicator.stats.exact_duplicates_dropped,
                "canonical_duplicates_dropped": deduplicator.stats.canonical_duplicates_dropped,
                "domain_cap_dropped": deduplicator.stats.domain_cap_dropped,
            },
        },
    )
    manifest.save(processed_dir / "manifest.json")
    logger.info("Saved dataset manifest to %s", processed_dir / "manifest.json")

    # 6. Model Training and Benchmarking
    logger.info("=== STEP 6: Model Training & Evaluation on Unseen Domains ===")
    feature_cols = list(ML_INTRINSIC_FEATURE_NAMES)
    X_train = splits.train_df[feature_cols].copy()
    y_train = splits.train_df["binary_label"].copy()
    X_test = splits.test_df[feature_cols].copy()
    y_test = splits.test_df["binary_label"].copy()

    # Model A: Scaled Logistic Regression
    logger.info("Training Candidate A: Scaled Logistic Regression...")
    lr_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, random_state=42, class_weight="balanced")),
    ])
    lr_pipeline.fit(X_train, y_train)
    lr_y_pred = lr_pipeline.predict(X_test)
    lr_y_proba = lr_pipeline.predict_proba(X_test)[:, 1]
    lr_metrics = compute_classification_metrics(y_test, lr_y_pred, lr_y_proba, model_name="logistic_regression")
    logger.info(
        "Logistic Regression — Acc: %.4f, F1: %.4f, PR-AUC: %.4f, ROC-AUC: %.4f, FPR: %.4f, Brier: %.4f",
        lr_metrics.accuracy,
        lr_metrics.f1,
        lr_metrics.pr_auc,
        lr_metrics.roc_auc,
        lr_metrics.false_positive_rate,
        lr_metrics.brier_score,
    )

    # Model B: HistGradientBoosting
    logger.info("Training Candidate B: HistGradientBoostingClassifier...")
    gb_pipeline = Pipeline([
        (
            "classifier",
            HistGradientBoostingClassifier(
                max_iter=150,
                random_state=42,
                class_weight="balanced",
                early_stopping=True,
                n_iter_no_change=10,
            ),
        )
    ])
    gb_pipeline.fit(X_train, y_train)
    gb_y_pred = gb_pipeline.predict(X_test)
    gb_y_proba = gb_pipeline.predict_proba(X_test)[:, 1]
    gb_metrics = compute_classification_metrics(y_test, gb_y_pred, gb_y_proba, model_name="gradient_boosting")
    logger.info(
        "Gradient Boosting   — Acc: %.4f, F1: %.4f, PR-AUC: %.4f, ROC-AUC: %.4f, FPR: %.4f, Brier: %.4f",
        gb_metrics.accuracy,
        gb_metrics.f1,
        gb_metrics.pr_auc,
        gb_metrics.roc_auc,
        gb_metrics.false_positive_rate,
        gb_metrics.brier_score,
    )

    # 7. Model Selection and Artifact Packaging
    candidates = [
        ("gradient_boosting", gb_pipeline, gb_metrics),
        ("logistic_regression", lr_pipeline, lr_metrics),
    ]
    # Rank by F1 + PR-AUC - FPR
    candidates.sort(key=lambda c: c[2].f1 + c[2].pr_auc - c[2].false_positive_rate, reverse=True)
    best_name, best_model, best_metrics = candidates[0]
    logger.info("Selected winning production model: %s", best_name)

    artifact_dir = repo_root / "trustlens_intelligence" / "evaluation" / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / "baseline_classifier.joblib"

    artifact = {
        "model": best_model,
        "model_name": best_name,
        "model_version": "2.0.0",
        "schema_version": MODEL_SCHEMA_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": feature_cols,
        "evaluation_metrics": best_metrics.to_dict(),
        "training_metadata": {
            "dataset_version": "2.0.0",
            "total_samples": len(feature_df),
            "train_samples": len(splits.train_df),
            "test_samples": len(splits.test_df),
            "train_domains": len(splits.train_domains),
            "test_domains": len(splits.test_domains),
            "source_attributions": source_attributions,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, artifact_path)
    logger.info("Saved production model artifact to %s", artifact_path)

    manifest_path = artifact_dir / "baseline_classifier_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "model_name": best_name,
                "model_version": "2.0.0",
                "schema_version": MODEL_SCHEMA_VERSION,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "num_features": len(feature_cols),
                "feature_names": feature_cols,
                "evaluation_metrics": best_metrics.to_dict(),
                "training_metadata": artifact["training_metadata"],
                "created_at": artifact["created_at"],
            },
            f,
            indent=2,
        )
    logger.info("Saved companion model manifest to %s", manifest_path)

    total_time = time.perf_counter() - t_start
    logger.info("=== Tier 2 Ingestion, Splitting & Training COMPLETED in %.2fs ===", total_time)


if __name__ == "__main__":
    run_tier2_training()
