"""TrustLens Intelligence — Batch Feature Extraction Engine.

Executes streaming batch feature extraction over validated dataset samples,
enforces the ML Feature Allowlist to eliminate target leakage, and returns
analytical pandas DataFrames.
"""

from collections.abc import Iterable, Iterator
from typing import Any
import numpy as np
import pandas as pd

from trustlens_intelligence.datasets.processing.allowlist import (
    ML_INTRINSIC_FEATURE_NAMES,
    filter_allowlisted_features,
)
from trustlens_intelligence.datasets.processing.label_validator import ValidatedSample
from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.schemas.evidence import (
    DomainIntelligenceEvidence,
    HttpEvidence,
    ScanEvidence,
    TlsCertificateEvidence,
)


class BatchFeaturePipeline:
    """Extracts allowlisted machine learning feature vectors in streaming chunks."""

    def __init__(self, extractor: FeatureExtractor | None = None) -> None:
        self.extractor = extractor or FeatureExtractor()

    def sample_to_evidence(self, sample: ValidatedSample) -> ScanEvidence:
        """Convert a ValidatedSample into a ScanEvidence object for feature extraction.

        Uses metadata if present to populate realistic observations.
        """
        url = sample.canonical_url or sample.url
        host = sample.registrable_domain or ""
        scheme = "https" if url.startswith("https://") else "http"

        meta = sample.metadata or {}
        domain_age = meta.get("domain_age_days")

        domain_ev = None
        if domain_age is not None:
            domain_ev = DomainIntelligenceEvidence(domain_age_days=int(domain_age))

        tls_ev = None
        if "tls_valid" in meta or meta.get("has_tls_scan"):
            tls_valid = meta.get("tls_valid", True)
            tls_ev = TlsCertificateEvidence(
                valid=tls_valid,
                chain_valid=meta.get("chain_valid", tls_valid),
                hostname_match=meta.get("hostname_match", tls_valid),
                days_until_expiry=meta.get("days_until_expiry", 90 if tls_valid else -5),
                is_expired=meta.get("is_expired", not tls_valid),
                protocol_version=meta.get("protocol_version", "TLSv1.3"),
            )

        http_ev = None
        if "status_code" in meta or "security_headers" in meta:
            http_ev = HttpEvidence(
                status_code=meta.get("status_code", 200),
                final_url=url,
                security_headers=meta.get("security_headers", {}),
            )

        return ScanEvidence(
            scan_id=f"batch_{abs(hash(url)) % 10000000}",
            original_url=sample.url,
            canonical_url=sample.canonical_url,
            host=host,
            scheme=scheme,
            http=http_ev,
            tls=tls_ev,
            domain_intelligence=domain_ev,
            threat_intelligence=None,  # Intentionally None: ML must learn intrinsic patterns
        )

    def extract_row(self, sample: ValidatedSample) -> dict[str, Any]:
        """Extract allowlisted features for a single sample."""
        evidence = self.sample_to_evidence(sample)
        extracted = self.extractor.extract(evidence)
        ml_dict = extracted.to_ml_dict()
        filtered = filter_allowlisted_features(ml_dict)

        return {
            "url": sample.url,
            "canonical_url": sample.canonical_url,
            "registrable_domain": sample.registrable_domain,
            "label_category": sample.label_category.value,
            "binary_label": sample.binary_label,
            "multiclass_label": sample.multiclass_label,
            "confidence": sample.confidence,
            "source_id": sample.source_id,
            "timestamp": sample.timestamp.isoformat() if sample.timestamp else None,
            "observed_at": sample.observed_at.isoformat() if sample.observed_at else None,
            "first_seen_at": sample.first_seen_at.isoformat() if sample.first_seen_at else None,
            "last_seen_at": sample.last_seen_at.isoformat() if sample.last_seen_at else None,
            "feed_retrieved_at": sample.feed_retrieved_at.isoformat() if sample.feed_retrieved_at else None,
            "ingested_at": sample.ingested_at.isoformat() if sample.ingested_at else None,
            "campaign_id": sample.campaign_id,
            "original_source_label": sample.original_source_label,
            **filtered,
        }

    def process_samples(
        self,
        samples: Iterable[ValidatedSample],
        chunk_size: int = 1000,
    ) -> Iterator[pd.DataFrame]:
        """Process samples in streaming chunks, yielding analytical DataFrames."""
        buffer: list[dict[str, Any]] = []
        for sample in samples:
            buffer.append(self.extract_row(sample))
            if len(buffer) >= chunk_size:
                yield pd.DataFrame(buffer)
                buffer.clear()

        if buffer:
            yield pd.DataFrame(buffer)

    def extract_dataframe(self, samples: list[ValidatedSample]) -> pd.DataFrame:
        """Extract features for a list of samples into a single DataFrame."""
        if not samples:
            cols = [
                "url",
                "canonical_url",
                "registrable_domain",
                "label_category",
                "binary_label",
                "confidence",
                "source_id",
                "timestamp",
            ] + list(ML_INTRINSIC_FEATURE_NAMES)
            return pd.DataFrame(columns=cols)

        chunks = list(self.process_samples(samples))
        return pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame()

