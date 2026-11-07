"""TrustLens Intelligence — Detection Rule Base Class."""

from abc import ABC, abstractmethod
from typing import Any
import uuid

from trustlens_intelligence.config.constants import FindingCategory, FindingSeverity
from trustlens_intelligence.schemas.evidence import ScanEvidence
from trustlens_intelligence.schemas.features import ExtractedFeatures
from trustlens_intelligence.schemas.findings import Finding


class DetectionRule(ABC):
    """Abstract base class for all deterministic threat detection rules."""

    def __init__(
        self,
        code: str,
        category: FindingCategory,
        severity: FindingSeverity,
        points: int,
        title: str,
        description_template: str,
        remediation: str,
        source: str = "trustlens_detection_rules_v1",
        is_decisive: bool = False,
    ) -> None:
        self.code = code
        self.category = category
        self.severity = severity
        self.points = points
        self.title = title
        self.description_template = description_template
        self.remediation = remediation
        self.source = source
        self.is_decisive = is_decisive

    @abstractmethod
    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        """Evaluate evidence and features against this rule.

        Returns:
            Finding if the rule triggers, or None if conditions are not met.
        """
        pass

    def _build_finding(
        self,
        evidence: dict[str, Any],
        points: int | None = None,
        description_kwargs: dict[str, Any] | None = None,
    ) -> Finding:
        """Construct a structured Finding using rule defaults."""
        description = self.description_template
        if description_kwargs:
            try:
                description = self.description_template.format(**description_kwargs)
            except Exception:
                description = self.description_template

        return Finding(
            id=str(uuid.uuid4()),
            code=self.code,
            category=self.category,
            title=self.title,
            description=description,
            severity=self.severity,
            points=points if points is not None else self.points,
            evidence=evidence,
            remediation=self.remediation,
            source=self.source,
        )

