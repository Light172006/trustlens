"""TrustLens Intelligence — URLhaus Dataset Source Adapter.

Parses abuse.ch URLhaus malware URL database (CSV format) to extract malware
distribution endpoints with status, threat tags, and timestamps.
"""

from collections.abc import Iterable, Iterator
import csv
from datetime import datetime, timezone
import io
from pathlib import Path
from typing import Any

from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    DatasetSourceMeta,
    LabelCategory,
    RawRecord,
)

SAMPLE_URLHAUS_RECORDS = [
    {
        "url": "http://89.248.163.78/bins/arm7.payload",
        "threat": "malware_download",
        "tags": "elf,mirai,gafgyt",
        "status": "online",
        "dateadded": "2026-01-03 08:30:00",
    },
    {
        "url": "http://malware-drop-site.biz/downloads/invoice_pdf.exe",
        "threat": "malware_download",
        "tags": "exe,agenttesla",
        "status": "online",
        "dateadded": "2026-01-03 09:15:00",
    },
    {
        "url": "http://fast-dropper-payloads.ru/dll/updater.scr",
        "threat": "malware_download",
        "tags": "scr,redline",
        "status": "offline",
        "dateadded": "2026-01-03 10:00:00",
    },
    {
        "url": "http://185.220.101.5/loader.sh",
        "threat": "malware_download",
        "tags": "sh,botnet",
        "status": "online",
        "dateadded": "2026-01-03 11:20:00",
    },
    {
        "url": "http://crypto-miner-distrib.su/xmrig.tar.gz",
        "threat": "malware_download",
        "tags": "miner,xmrig",
        "status": "offline",
        "dateadded": "2026-01-03 12:45:00",
    },
]


class URLhausSource:
    """Adapter for ingesting and parsing URLhaus CSV dataset."""

    def __init__(self, meta: DatasetSourceMeta | None = None) -> None:
        self.meta = meta or APPROVED_SOURCES["urlhaus"]

    def parse_lines(
        self,
        lines: Iterable[str],
        max_records: int | None = None,
    ) -> Iterator[RawRecord]:
        """Parse raw CSV lines from URLhaus dump."""
        count = 0
        cleaned_lines = (line for line in lines if not line.startswith("#"))
        reader = csv.reader(cleaned_lines)

        header_parsed = False
        url_idx = 2
        date_idx = 1
        status_idx = 3
        threat_idx = 5
        tags_idx = 6

        for row in reader:
            if max_records is not None and count >= max_records:
                break
            if not row or len(row) < 3:
                continue

            # Check if this row is the header
            if not header_parsed and ("url" in row[0].lower() or "id" in row[0].lower()):
                for i, col in enumerate(row):
                    col_lower = col.strip().lower()
                    if col_lower == "url":
                        url_idx = i
                    elif col_lower in ("dateadded", "date_added"):
                        date_idx = i
                    elif col_lower in ("url_status", "status"):
                        status_idx = i
                    elif col_lower == "threat":
                        threat_idx = i
                    elif col_lower == "tags":
                        tags_idx = i
                header_parsed = True
                continue

            if len(row) <= url_idx:
                continue

            raw_url = row[url_idx].strip()
            if not raw_url or not raw_url.startswith(("http://", "https://")):
                continue

            # Parse timestamp if available
            timestamp: datetime | None = None
            if len(row) > date_idx and row[date_idx].strip():
                try:
                    timestamp = datetime.strptime(
                        row[date_idx].strip(), "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    timestamp = datetime.now(timezone.utc)

            status = row[status_idx].strip() if len(row) > status_idx else "unknown"
            threat = row[threat_idx].strip() if len(row) > threat_idx else "malware"
            tags = row[tags_idx].strip() if len(row) > tags_idx else ""

            record = RawRecord(
                url=raw_url,
                source_id=self.meta.source_id,
                raw_label=LabelCategory.MALWARE.value,
                timestamp=timestamp,
                confidence=1.0 if status == "online" else 0.9,
                metadata={
                    "threat": threat,
                    "tags": tags.split(",") if tags else [],
                    "url_status": status,
                },
            )
            count += 1
            yield record

    def load_from_file(
        self,
        path: Path | str,
        max_records: int | None = None,
    ) -> list[RawRecord]:
        """Load URLhaus records from a local CSV file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"URLhaus file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return list(self.parse_lines(f, max_records=max_records))

    def generate_mock_records(self, count: int = 50) -> list[RawRecord]:
        """Generate deterministic mock records for offline CI testing."""
        records: list[RawRecord] = []
        for i in range(count):
            sample = SAMPLE_URLHAUS_RECORDS[i % len(SAMPLE_URLHAUS_RECORDS)]
            base_url = sample["url"]
            url = f"{base_url}?variant={i}" if i >= len(SAMPLE_URLHAUS_RECORDS) else base_url

            timestamp = datetime.strptime(
                sample["dateadded"], "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)

            records.append(
                RawRecord(
                    url=url,
                    source_id=self.meta.source_id,
                    raw_label=LabelCategory.MALWARE.value,
                    timestamp=timestamp,
                    confidence=1.0 if sample["status"] == "online" else 0.9,
                    metadata={
                        "threat": sample["threat"],
                        "tags": sample["tags"].split(","),
                        "url_status": sample["status"],
                        "sample_id": i,
                    },
                )
            )
        return records

