"""Base rule definition for Certificate Analyzer."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class CertificateRule(ABC):
    """Abstract base class for all certificate evaluation rules."""

    rule_id: str
    name: str

    @abstractmethod
    def evaluate(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
    ) -> List[CertificateFinding]:
        """Evaluates rule against features and records, returning any triggered findings."""
        pass

