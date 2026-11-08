"""Data source registry and verification models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


@dataclass(frozen=True)
class SourceMetadata:
    source_id: str
    source_name: str
    official_website: str
    data_type: str
    available_fields: List[str]
    collection_method: str
    format: str
    update_frequency: str
    license_or_usage_terms: str
    attribution_requirements: str
    bulk_retrieval_permitted: bool
    derived_dataset_creation_permitted: bool
    ml_research_permitted: bool
    known_limitations: str
    retrieval_timestamp: str
    verification_status: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SourceMetadata:
        return cls(
            source_id=str(data["source_id"]),
            source_name=str(data["source_name"]),
            official_website=str(data["official_website"]),
            data_type=str(data["data_type"]),
            available_fields=list(data.get("available_fields", [])),
            collection_method=str(data["collection_method"]),
            format=str(data["format"]),
            update_frequency=str(data["update_frequency"]),
            license_or_usage_terms=str(data["license_or_usage_terms"]),
            attribution_requirements=str(data["attribution_requirements"]),
            bulk_retrieval_permitted=bool(data.get("bulk_retrieval_permitted", False)),
            derived_dataset_creation_permitted=bool(data.get("derived_dataset_creation_permitted", False)),
            ml_research_permitted=bool(data.get("ml_research_permitted", False)),
            known_limitations=str(data.get("known_limitations", "")),
            retrieval_timestamp=str(data["retrieval_timestamp"]),
            verification_status=str(data.get("verification_status", "UNVERIFIED")),
        )


class SourceRegistry:
    """Loads and queries the verified source registry."""

    def __init__(self, sources_path: Optional[Path] = None):
        if sources_path is None:
            sources_path = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "config"
                / "sources.yaml"
            )
        self.sources_path = Path(sources_path)
        self._sources: Dict[str, SourceMetadata] = {}
        self.load()

    def load(self) -> None:
        if not self.sources_path.exists():
            raise FileNotFoundError(f"Sources config not found at: {self.sources_path}")
        with open(self.sources_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        sources_list = data.get("sources", [])
        self._sources = {
            s["source_id"]: SourceMetadata.from_dict(s) for s in sources_list
        }

    def get(self, source_id: str) -> Optional[SourceMetadata]:
        return self._sources.get(source_id)

    def list_all(self) -> List[SourceMetadata]:
        return list(self._sources.values())

    def filter_by_type(self, data_type: str) -> List[SourceMetadata]:
        return [s for s in self._sources.values() if s.data_type == data_type]

    def verify_ml_compliance(self) -> List[str]:
        """Returns list of source_ids that are verified and permit ML research & derived datasets."""
        compliant = []
        for s in self._sources.values():
            if (
                s.verification_status == "VERIFIED_ACTIVE"
                and s.ml_research_permitted
                and s.derived_dataset_creation_permitted
            ):
                compliant.append(s.source_id)
        return compliant

