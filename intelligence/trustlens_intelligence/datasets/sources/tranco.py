"""TrustLens Intelligence — Tranco Top Sites Dataset Source Adapter.

Parses Tranco CSV data (rank, domain) to generate legitimate baseline URLs
for machine learning training and evaluation.
"""

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
import io
from pathlib import Path
from typing import Any
import zipfile

from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    DatasetSourceMeta,
    LabelCategory,
    RawRecord,
)

SAMPLE_TRANCO_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "baidu.com",
    "wikipedia.org",
    "yahoo.com",
    "reddit.com",
    "amazon.com",
    "twitter.com",
    "linkedin.com",
    "instagram.com",
    "netflix.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "stackoverflow.com",
    "cloudflare.com",
    "wordpress.org",
    "zoom.us",
    "bing.com",
]


class TrancoSource:
    """Adapter for ingesting and parsing Tranco Top Sites dataset."""

    def __init__(self, meta: DatasetSourceMeta | None = None) -> None:
        self.meta = meta or APPROVED_SOURCES["tranco"]

    def parse_lines(
        self,
        lines: Iterable[str],
        max_records: int | None = None,
    ) -> Iterator[RawRecord]:
        """Parse raw CSV lines into RawRecord objects.

        Lines may be in format: `rank,domain` or `domain`.
        """
        count = 0
        now = datetime.now(timezone.utc)
        for line in lines:
            if max_records is not None and count >= max_records:
                break
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = [p.strip() for p in stripped.split(",")]
            rank: int | None = None
            domain: str
            if len(parts) >= 2 and parts[0].isdigit():
                rank = int(parts[0])
                domain = parts[1]
            else:
                domain = parts[0]

            if not domain or "." not in domain or " " in domain:
                continue

            url = f"https://{domain}/"
            record = RawRecord(
                url=url,
                source_id=self.meta.source_id,
                raw_label=LabelCategory.LEGITIMATE.value,
                timestamp=now,
                confidence=1.0,
                metadata={"rank": rank, "domain": domain},
            )
            count += 1
            yield record

    def parse_zip_bytes(
        self,
        data: bytes,
        max_records: int | None = None,
    ) -> Iterator[RawRecord]:
        """Parse in-memory Tranco zip archive containing CSV."""
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            namelist = zf.namelist()
            csv_name = next((n for n in namelist if n.endswith(".csv")), None)
            if not csv_name:
                raise ValueError("No CSV file found inside Tranco ZIP archive")
            with zf.open(csv_name) as f:
                text_stream = io.TextIOWrapper(f, encoding="utf-8", errors="replace")
                yield from self.parse_lines(text_stream, max_records=max_records)

    def load_from_file(
        self,
        path: Path | str,
        max_records: int | None = None,
    ) -> list[RawRecord]:
        """Load records from a local file (.csv or .zip)."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Tranco file not found: {file_path}")

        if file_path.suffix == ".zip":
            with open(file_path, "rb") as f:
                return list(self.parse_zip_bytes(f.read(), max_records=max_records))

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return list(self.parse_lines(f, max_records=max_records))

    def generate_mock_records(self, count: int = 50) -> list[RawRecord]:
        """Generate deterministic mock records for offline CI testing."""
        records: list[RawRecord] = []
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(count):
            domain_idx = i % len(SAMPLE_TRANCO_DOMAINS)
            base_domain = SAMPLE_TRANCO_DOMAINS[domain_idx]
            if i >= len(SAMPLE_TRANCO_DOMAINS):
                # Unique subdomain to guarantee unique domains if needed
                domain = f"site{i}.{base_domain}"
            else:
                domain = base_domain
            url = f"https://{domain}/"
            records.append(
                RawRecord(
                    url=url,
                    source_id=self.meta.source_id,
                    raw_label=LabelCategory.LEGITIMATE.value,
                    timestamp=now,
                    confidence=1.0,
                    metadata={"rank": i + 1, "domain": domain},
                )
            )
        return records

