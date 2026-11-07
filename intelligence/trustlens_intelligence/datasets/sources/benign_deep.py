"""TrustLens Intelligence — Benign Deep URL Dataset Source Adapter.

Ingests legitimate web pages containing deep paths, query strings, and diverse
domain structures to eliminate the Tranco root-URL bias.
"""

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    DatasetSourceMeta,
    LabelCategory,
    RawRecord,
)

SAMPLE_BENIGN_DEEP_URLS = [
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://docs.github.com/en/rest/reference/repos",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    "https://stackoverflow.com/questions/tagged/python?tab=votes&page=2",
    "https://stackoverflow.com/questions/1234567/how-do-i-parse-a-url-in-python",
    "https://www.amazon.com/s?k=wireless+headphones&crid=3N5P",
    "https://www.ebay.com/b/Apple-Laptops/111422/bn_16480579?rt=nc&_udlo=500",
    "https://github.com/torvalds/linux/commits/master",
    "https://github.com/psf/requests/releases/tag/v2.31.0",
    "https://gitlab.com/gitlab-org/gitlab/-/issues/12345",
    "https://www.bbc.com/news/technology-68123456",
    "https://www.cnn.com/2026/01/15/tech/artificial-intelligence-trends/index.html",
    "https://www.google.com/search?q=trustlens+threat+intelligence+audit&hl=en",
    "https://aws.amazon.com/security/introduction/?sec-nav=true",
    "https://azure.microsoft.com/en-us/solutions/web-apps/",
    "https://cloud.google.com/bigquery/docs/quickstarts",
    "https://stripe.com/docs/api/charges/create",
    "https://pypi.org/project/scikit-learn/#history",
]


class BenignDeepSource:
    """Adapter for ingesting and parsing verified benign deep URL datasets."""

    def __init__(self, meta: DatasetSourceMeta | None = None) -> None:
        self.meta = meta or APPROVED_SOURCES.get("benign_deep")

    def parse_lines(
        self,
        lines: Iterable[str],
        max_records: int | None = None,
    ) -> Iterator[RawRecord]:
        """Parse lines of legitimate URLs."""
        count = 0
        now = datetime.now(timezone.utc)
        source_id = self.meta.source_id if self.meta else "benign_deep"

        for line in lines:
            if max_records is not None and count >= max_records:
                break
            stripped = line.strip().strip('"').strip("'")
            if not stripped or stripped.startswith(("#", "url,", "URL,")):
                continue

            if stripped.startswith("http://"):
                # Modernize historical 2016 HTTP prefixes to modern HTTPS standard
                raw_url = f"https://{stripped[7:]}"
            elif stripped.startswith("https://"):
                raw_url = stripped
            else:
                raw_url = f"https://{stripped}"
            record = RawRecord(
                url=raw_url,
                source_id=source_id,
                raw_label=LabelCategory.LEGITIMATE.value,
                timestamp=now,
                confidence=1.0,
                feed_retrieved_at=now,
                ingested_at=now,
                original_source_label="legitimate_deep",
                metadata={"source_type": "deep_benign_collection"},
            )
            count += 1
            yield record

    def load_from_file(
        self,
        path: Path | str,
        max_records: int | None = None,
    ) -> list[RawRecord]:
        """Load records from local file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return list(self.parse_lines(f, max_records=max_records))

    def generate_mock_records(self, count: int = 50) -> list[RawRecord]:
        """Generate deterministic mock records for offline CI testing."""
        records: list[RawRecord] = []
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        source_id = self.meta.source_id if self.meta else "benign_deep"

        for i in range(count):
            base_url = SAMPLE_BENIGN_DEEP_URLS[i % len(SAMPLE_BENIGN_DEEP_URLS)]
            url = f"{base_url}&sample={i}" if "?" in base_url else f"{base_url}?sample={i}"
            records.append(
                RawRecord(
                    url=url,
                    source_id=source_id,
                    raw_label=LabelCategory.LEGITIMATE.value,
                    timestamp=now,
                    confidence=1.0,
                    feed_retrieved_at=now,
                    ingested_at=now,
                    original_source_label="legitimate_deep",
                    metadata={"source_type": "mock_deep_benign", "sample_id": i},
                )
            )
        return records

