"""TrustLens Intelligence — Dataset Deduplication and Domain Frequency Control.

Provides multi-tier deduplication by exact URL, canonical URL hash, and
registrable domain frequency capping to prevent single-domain bias.
"""

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from trustlens_intelligence.datasets.processing.normalizer import URLNormalizer
from trustlens_intelligence.datasets.sources.registry import RawRecord


@dataclass
class DeduplicationStats:
    """Statistics recorded during deduplication pass."""

    total_processed: int = 0
    total_retained: int = 0
    exact_duplicates_dropped: int = 0
    canonical_duplicates_dropped: int = 0
    domain_cap_dropped: int = 0


class DatasetDeduplicator:
    """Filters duplicate URLs and applies domain balance constraints."""

    def __init__(
        self,
        normalizer: URLNormalizer | None = None,
        max_samples_per_domain: int | None = None,
    ) -> None:
        self.normalizer = normalizer or URLNormalizer()
        self.max_samples_per_domain = max_samples_per_domain
        self.seen_exact_urls: set[str] = set()
        self.seen_canonical_hashes: set[str] = set()
        self.domain_counts: Counter[str] = Counter()
        self.stats = DeduplicationStats()

    def reset(self) -> None:
        """Reset deduplication state and statistics."""
        self.seen_exact_urls.clear()
        self.seen_canonical_hashes.clear()
        self.domain_counts.clear()
        self.stats = DeduplicationStats()

    def filter_record(self, record: RawRecord) -> RawRecord | None:
        """Evaluate a single record. Returns the record if accepted, None if duplicate."""
        self.stats.total_processed += 1
        raw_url = record.url.strip()

        # 1. Exact URL duplicate check
        if raw_url in self.seen_exact_urls:
            self.stats.exact_duplicates_dropped += 1
            return None

        # 2. Canonical URL duplicate check
        norm = self.normalizer.normalize(raw_url)
        if norm.canonical_hash in self.seen_canonical_hashes:
            self.stats.canonical_duplicates_dropped += 1
            return None

        # 3. Domain frequency cap check
        domain = norm.registrable_domain
        if (
            self.max_samples_per_domain is not None
            and self.domain_counts[domain] >= self.max_samples_per_domain
        ):
            self.stats.domain_cap_dropped += 1
            return None

        # Record accepted
        self.seen_exact_urls.add(raw_url)
        self.seen_canonical_hashes.add(norm.canonical_hash)
        self.domain_counts[domain] += 1
        self.stats.total_retained += 1

        # Enrich metadata with canonical info
        enriched_meta = dict(record.metadata)
        enriched_meta["canonical_url"] = norm.canonical_url
        enriched_meta["registrable_domain"] = norm.registrable_domain
        enriched_meta["canonical_hash"] = norm.canonical_hash

        return RawRecord(
            url=norm.canonical_url,
            source_id=record.source_id,
            raw_label=record.raw_label,
            timestamp=record.timestamp,
            confidence=record.confidence,
            observed_at=record.observed_at,
            first_seen_at=record.first_seen_at,
            last_seen_at=record.last_seen_at,
            feed_retrieved_at=record.feed_retrieved_at,
            ingested_at=record.ingested_at,
            campaign_id=record.campaign_id,
            original_source_label=record.original_source_label,
            metadata=enriched_meta,
        )

    def filter_stream(self, records: Iterable[RawRecord]) -> Iterator[RawRecord]:
        """Process an iterable of RawRecords, yielding deduplicated records."""
        for rec in records:
            accepted = self.filter_record(rec)
            if accepted is not None:
                yield accepted

    def deduplicate_list(self, records: list[RawRecord]) -> list[RawRecord]:
        """Deduplicate a list of records in memory."""
        return list(self.filter_stream(records))

