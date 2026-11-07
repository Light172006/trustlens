"""TrustLens Intelligence — Label Taxonomy Mapping, Validation, and Conflict Resolution.

Normalizes heterogeneous source labels into the unified TrustLens taxonomy
and resolves cross-source label conflicts with explicit safety policies.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from trustlens_intelligence.datasets.sources.registry import LabelCategory, RawRecord

LABEL_TAXONOMY_MAP: dict[str, LabelCategory] = {
    "legitimate": LabelCategory.LEGITIMATE,
    "benign": LabelCategory.LEGITIMATE,
    "safe": LabelCategory.LEGITIMATE,
    "clean": LabelCategory.LEGITIMATE,
    "tranco": LabelCategory.LEGITIMATE,
    "legitimate_deep": LabelCategory.LEGITIMATE,
    "phishing": LabelCategory.PHISHING,
    "phish": LabelCategory.PHISHING,
    "credential_harvesting": LabelCategory.PHISHING,
    "malware": LabelCategory.MALWARE,
    "malware_download": LabelCategory.MALWARE,
    "malware_distribution": LabelCategory.MALWARE,
    "payload": LabelCategory.MALWARE,
    "botnet": LabelCategory.MALWARE,
    "c2": LabelCategory.MALWARE,
    "suspicious": LabelCategory.SUSPICIOUS,
    "unverified": LabelCategory.SUSPICIOUS,
}


@dataclass(frozen=True)
class ValidatedSample:
    """A clean, validated, and normalized dataset sample ready for feature extraction."""

    url: str
    canonical_url: str
    registrable_domain: str
    label_category: LabelCategory
    binary_label: int  # 0 = Benign, 1 = Threat
    confidence: float
    source_id: str
    multiclass_label: int = 0  # 0 = Legitimate, 1 = Phishing, 2 = Malware
    timestamp: datetime | None = None
    observed_at: datetime | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    feed_retrieved_at: datetime | None = None
    ingested_at: datetime | None = None
    campaign_id: str | None = None
    original_source_label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class LabelValidator:
    """Validates raw labels and resolves conflicting assertions across intelligence sources."""

    def normalize_label(self, raw_label: str) -> LabelCategory:
        """Map raw source string to standardized LabelCategory."""
        key = raw_label.strip().lower()
        return LABEL_TAXONOMY_MAP.get(key, LabelCategory.UNKNOWN)

    def to_binary_label(self, category: LabelCategory) -> int:
        """Project label category to binary classification target (0 = benign, 1 = threat)."""
        if category == LabelCategory.LEGITIMATE:
            return 0
        return 1

    def to_multiclass_label(self, category: LabelCategory) -> int:
        """Project label category to 3-class target (0 = Legitimate, 1 = Phishing, 2 = Malware)."""
        if category == LabelCategory.LEGITIMATE:
            return 0
        if category == LabelCategory.PHISHING:
            return 1
        if category == LabelCategory.MALWARE:
            return 2
        return -1

    def resolve_conflicts(self, records: list[RawRecord]) -> ValidatedSample:
        """Resolve conflicting assertions for the same canonical URL.

        Resolution precedence:
        1. Confirmed active threat (Phishing or Malware with confidence >= 0.9) overrides Legitimate.
           Rationale: Legitimate ranking lists (Tranco/Alexa) frequently contain compromised domains.
        2. Higher source confidence takes precedence.
        3. Most recent timestamp takes precedence for tie-breaking.
        """
        if not records:
            raise ValueError("Cannot resolve conflicts for empty record list")

        if len(records) == 1:
            r = records[0]
            cat = self.normalize_label(r.raw_label)
            domain = r.metadata.get("registrable_domain", "")
            canonical_url = r.metadata.get("canonical_url", r.url)
            return ValidatedSample(
                url=r.url,
                canonical_url=canonical_url,
                registrable_domain=domain,
                label_category=cat,
                binary_label=self.to_binary_label(cat),
                confidence=r.confidence,
                source_id=r.source_id,
                multiclass_label=self.to_multiclass_label(cat),
                timestamp=r.timestamp,
                observed_at=r.observed_at,
                first_seen_at=r.first_seen_at,
                last_seen_at=r.last_seen_at,
                feed_retrieved_at=r.feed_retrieved_at,
                ingested_at=r.ingested_at,
                campaign_id=r.campaign_id,
                original_source_label=r.original_source_label,
                metadata=r.metadata,
            )

        # Multi-record conflict resolution
        threat_records = [
            r
            for r in records
            if self.normalize_label(r.raw_label) in (LabelCategory.PHISHING, LabelCategory.MALWARE)
            and r.confidence >= 0.9
        ]

        if threat_records:
            # Sort by confidence descending, then timestamp descending
            threat_records.sort(
                key=lambda x: (x.confidence, x.timestamp or datetime.min),
                reverse=True,
            )
            selected = threat_records[0]
        else:
            # Sort all records by confidence descending, then timestamp
            records.sort(
                key=lambda x: (x.confidence, x.timestamp or datetime.min),
                reverse=True,
            )
            selected = records[0]

        cat = self.normalize_label(selected.raw_label)
        domain = selected.metadata.get("registrable_domain", "")
        canonical_url = selected.metadata.get("canonical_url", selected.url)

        return ValidatedSample(
            url=selected.url,
            canonical_url=canonical_url,
            registrable_domain=domain,
            label_category=cat,
            binary_label=self.to_binary_label(cat),
            confidence=selected.confidence,
            source_id=selected.source_id,
            multiclass_label=self.to_multiclass_label(cat),
            timestamp=selected.timestamp,
            observed_at=selected.observed_at,
            first_seen_at=selected.first_seen_at,
            last_seen_at=selected.last_seen_at,
            feed_retrieved_at=selected.feed_retrieved_at,
            ingested_at=selected.ingested_at,
            campaign_id=selected.campaign_id,
            original_source_label=selected.original_source_label,
            metadata={
                **selected.metadata,
                "conflict_sources": [r.source_id for r in records],
                "conflict_count": len(records),
            },
        )

