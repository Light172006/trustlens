"""TrustLens Certificate Analyzer — Independent PKI & Digital Trust Intelligence Component."""

from __future__ import annotations

from pathlib import Path
import sys

# Ensure dataset package and isolated dependencies are accessible
_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DATASET_SRC = _ROOT / "certificate_dataset" / "src"
_DATASET_DEPS = _ROOT / "certificate_dataset" / ".deps"

if _DATASET_SRC.exists() and str(_DATASET_SRC) not in sys.path:
    sys.path.insert(0, str(_DATASET_SRC))
if _DATASET_DEPS.exists() and str(_DATASET_DEPS) not in sys.path:
    sys.path.insert(0, str(_DATASET_DEPS))

from certificate_analyzer.api import analyze_certificate, analyze_pem, analyze_endpoint_tls
from certificate_analyzer.constants import CertificateVerdict, FindingSeverity
from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine
from certificate_analyzer.errors import (
    AnalysisErrorCode,
    CertificateAnalyzerError,
    InvalidCertificateError,
    EmptyCertificateError,
    UnsupportedCertificateFormatError,
    MultipleLeafCertificatesAmbiguityError,
    ResourceLimitExceededError,
)
from certificate_analyzer.rules.policy import CABFPolicyEvaluator
from certificate_analyzer.schemas.assessment import CertificateAssessment

__version__ = "1.0.0"
__all__ = [
    "analyze_certificate",
    "analyze_pem",
    "analyze_endpoint_tls",
    "CertificateVerdict",
    "FindingSeverity",
    "CertificateAnalyzerEngine",
    "CertificateAssessment",
    "CABFPolicyEvaluator",
    "AnalysisErrorCode",
    "CertificateAnalyzerError",
    "InvalidCertificateError",
    "EmptyCertificateError",
    "UnsupportedCertificateFormatError",
    "MultipleLeafCertificatesAmbiguityError",
    "ResourceLimitExceededError",
]

