"""TrustLens Intelligence — OpenPhish Feed Dataset Source Adapter.

Parses OpenPhish URL feeds (one URL per line) to produce phishing records
with timestamps and metadata for training and validation.
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

SAMPLE_OPENPHISH_URLS = [
    "http://paypal-verification-account-secure.com/login?token=847392",
    "http://secure-login-apple-id.xn--e1aybc.com/verify-identity",
    "http://wellsfargo-online-banking-security.net/kyc/customer",
    "http://update-chase-account-validation.xyz/login.html",
    "http://microsoft-office365-password-reset.info/auth/login",
    "https://netflix-subscription-renew-account.org/update",
    "http://secure-bank-login-verification.top/auth/verify",
    "http://account-recovery-google-security.net/challenge",
    "http://ebay-resolution-center-case.biz/signin",
    "https://dhl-tracking-package-delivery-update.cc/track",
]


class OpenPhishSource:
    """Adapter for ingesting and parsing OpenPhish feed URLs."""

    def __init__(self, meta: DatasetSourceMeta | None = None) -> None:
        self.meta = meta or APPROVED_SOURCES["openphish"]

    def parse_lines(
        self,
        lines: Iterable[str],
        max_records: int | None = None,
    ) -> Iterator[RawRecord]:
        """Parse raw text lines from OpenPhish feed."""
        count = 0
        now = datetime.now(timezone.utc)
        for line in lines:
            if max_records is not None and count >= max_records:
                break
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # OpenPhish is 1 URL per line
            url = stripped
            record = RawRecord(
                url=url,
                source_id=self.meta.source_id,
                raw_label=LabelCategory.PHISHING.value,
                timestamp=now,
                confidence=0.95,
                metadata={"feed": "openphish_community"},
            )
            count += 1
            yield record

    def load_from_file(
        self,
        path: Path | str,
        max_records: int | None = None,
    ) -> list[RawRecord]:
        """Load OpenPhish records from a local text file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"OpenPhish file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return list(self.parse_lines(f, max_records=max_records))

    def generate_mock_records(self, count: int = 50) -> list[RawRecord]:
        """Generate deterministic mock records for offline CI testing."""
        records: list[RawRecord] = []
        now = datetime(2026, 1, 2, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(count):
            base_url = SAMPLE_OPENPHISH_URLS[i % len(SAMPLE_OPENPHISH_URLS)]
            if i >= len(SAMPLE_OPENPHISH_URLS):
                url = f"{base_url}&sample={i}" if "?" in base_url else f"{base_url}?sample={i}"
            else:
                url = base_url

            records.append(
                RawRecord(
                    url=url,
                    source_id=self.meta.source_id,
                    raw_label=LabelCategory.PHISHING.value,
                    timestamp=now,
                    confidence=0.95,
                    metadata={"feed": "openphish_community", "sample_id": i},
                )
            )
        return records

