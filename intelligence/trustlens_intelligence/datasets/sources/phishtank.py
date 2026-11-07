"""TrustLens Intelligence — PhishTank Dataset Source Adapter.

Parses PhishTank verified phishing database (CSV format) to extract validated
phishing attack targets, verification status, and timestamps.
"""

from collections.abc import Iterable, Iterator
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    DatasetSourceMeta,
    LabelCategory,
    RawRecord,
)

SAMPLE_PHISHTANK_RECORDS = [
    {
        "url": "http://chase-security-verify-customer.com/portal/login",
        "verified": "yes",
        "online": "yes",
        "target": "Chase Bank",
        "submission_time": "2026-01-04T08:00:00+00:00",
    },
    {
        "url": "http://citibank-card-update-alert.org/auth/index.php",
        "verified": "yes",
        "online": "yes",
        "target": "Citigroup",
        "submission_time": "2026-01-04T09:30:00+00:00",
    },
    {
        "url": "https://secure-login-apple-id.xn--e1aybc.com/verify-identity",
        "verified": "yes",
        "online": "yes",
        "target": "Apple",
        "submission_time": "2026-01-04T10:15:00+00:00",
    },
    {
        "url": "http://dhl-express-reschedule-shipment.info/deliver",
        "verified": "yes",
        "online": "yes",
        "target": "DHL",
        "submission_time": "2026-01-04T11:45:00+00:00",
    },
    {
        "url": "http://microsoft-outlook-web-app-access.net/owa/auth",
        "verified": "yes",
        "online": "yes",
        "target": "Microsoft",
        "submission_time": "2026-01-04T13:00:00+00:00",
    },
]


class PhishTankSource:
    """Adapter for ingesting and parsing PhishTank online-valid dataset."""

    def __init__(self, meta: DatasetSourceMeta | None = None) -> None:
        self.meta = meta or APPROVED_SOURCES["phishtank"]

    def parse_lines(
        self,
        lines: Iterable[str],
        max_records: int | None = None,
        only_verified: bool = True,
    ) -> Iterator[RawRecord]:
        """Parse raw CSV lines from PhishTank export."""
        count = 0
        reader = csv.reader(lines)

        header_parsed = False
        url_idx = 1
        time_idx = 3
        verified_idx = 4
        target_idx = 7
        online_idx = 6

        for row in reader:
            if max_records is not None and count >= max_records:
                break
            if not row or len(row) < 3:
                continue

            # Header inspection
            if not header_parsed and ("phish_id" in row[0].lower() or "url" in row[0].lower()):
                for i, col in enumerate(row):
                    col_lower = col.strip().lower()
                    if col_lower == "url":
                        url_idx = i
                    elif "time" in col_lower and "sub" in col_lower:
                        time_idx = i
                    elif col_lower == "verified":
                        verified_idx = i
                    elif col_lower == "target":
                        target_idx = i
                    elif col_lower == "online":
                        online_idx = i
                header_parsed = True
                continue

            if len(row) <= url_idx:
                continue

            raw_url = row[url_idx].strip()
            if not raw_url or not raw_url.startswith(("http://", "https://")):
                continue

            is_verified = "yes"
            if len(row) > verified_idx:
                is_verified = row[verified_idx].strip().lower()

            if only_verified and is_verified != "yes":
                continue

            # Parse submission timestamp
            timestamp: datetime | None = None
            if len(row) > time_idx and row[time_idx].strip():
                time_str = row[time_idx].strip()
                try:
                    timestamp = datetime.fromisoformat(time_str)
                except ValueError:
                    try:
                        timestamp = datetime.strptime(
                            time_str, "%Y-%m-%d %H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        timestamp = datetime.now(timezone.utc)

            target = row[target_idx].strip() if len(row) > target_idx else ""
            is_online = row[online_idx].strip().lower() == "yes" if len(row) > online_idx else True

            record = RawRecord(
                url=raw_url,
                source_id=self.meta.source_id,
                raw_label=LabelCategory.PHISHING.value,
                timestamp=timestamp,
                confidence=1.0 if is_verified == "yes" else 0.7,
                metadata={
                    "target": target,
                    "online": is_online,
                    "verified": is_verified,
                },
            )
            count += 1
            yield record

    def load_from_file(
        self,
        path: Path | str,
        max_records: int | None = None,
        only_verified: bool = True,
    ) -> list[RawRecord]:
        """Load PhishTank records from a local CSV file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"PhishTank file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return list(self.parse_lines(f, max_records=max_records, only_verified=only_verified))

    def generate_mock_records(self, count: int = 50) -> list[RawRecord]:
        """Generate deterministic mock records for offline CI testing."""
        records: list[RawRecord] = []
        for i in range(count):
            sample = SAMPLE_PHISHTANK_RECORDS[i % len(SAMPLE_PHISHTANK_RECORDS)]
            base_url = sample["url"]
            url = f"{base_url}?sample={i}" if i >= len(SAMPLE_PHISHTANK_RECORDS) else base_url

            timestamp = datetime.fromisoformat(sample["submission_time"])

            records.append(
                RawRecord(
                    url=url,
                    source_id=self.meta.source_id,
                    raw_label=LabelCategory.PHISHING.value,
                    timestamp=timestamp,
                    confidence=1.0,
                    metadata={
                        "target": sample["target"],
                        "online": sample["online"] == "yes",
                        "verified": "yes",
                        "sample_id": i,
                    },
                )
            )
        return records

