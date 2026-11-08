"""Structured error hierarchy and error codes for TrustLens Certificate Analyzer.

Provides typed, predictable error classifications to isolate failures without crashing
or exposing sensitive internal state.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional


class AnalysisErrorCode(str, Enum):
    """Standardized error codes for certificate analysis operations."""

    INVALID_CERTIFICATE = "INVALID_CERTIFICATE"
    EMPTY_CERTIFICATE = "EMPTY_CERTIFICATE"
    UNSUPPORTED_CERTIFICATE_FORMAT = "UNSUPPORTED_CERTIFICATE_FORMAT"
    MULTIPLE_LEAF_CERTIFICATES = "MULTIPLE_LEAF_CERTIFICATES"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    HOSTNAME_NOT_PROVIDED = "HOSTNAME_NOT_PROVIDED"
    CHAIN_INCOMPLETE = "CHAIN_INCOMPLETE"
    CHAIN_VALIDATION_FAILED = "CHAIN_VALIDATION_FAILED"
    TRUST_STORE_UNAVAILABLE = "TRUST_STORE_UNAVAILABLE"
    REVOCATION_UNAVAILABLE = "REVOCATION_UNAVAILABLE"
    CT_DATA_UNAVAILABLE = "CT_DATA_UNAVAILABLE"
    POLICY_PROFILE_UNKNOWN = "POLICY_PROFILE_UNKNOWN"
    FEATURE_EXTRACTION_FAILED = "FEATURE_EXTRACTION_FAILED"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    INTERNAL_ANALYSIS_ERROR = "INTERNAL_ANALYSIS_ERROR"


class CertificateAnalyzerError(Exception):
    """Base exception for all Certificate Analyzer operational errors."""

    def __init__(
        self,
        message: str,
        error_code: AnalysisErrorCode = AnalysisErrorCode.INTERNAL_ANALYSIS_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code.value,
            "message": self.message,
            "details": self.details,
        }


class InvalidCertificateError(CertificateAnalyzerError):
    """Raised when certificate data is corrupt or cannot be decoded as valid ASN.1 DER/PEM."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, AnalysisErrorCode.INVALID_CERTIFICATE, details)


class EmptyCertificateError(CertificateAnalyzerError):
    """Raised when empty or zero-length input is provided."""

    def __init__(self, message: str = "Input certificate data is empty", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, AnalysisErrorCode.EMPTY_CERTIFICATE, details)


class UnsupportedCertificateFormatError(CertificateAnalyzerError):
    """Raised when an unrecognized data structure or unsupported input type is provided."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, AnalysisErrorCode.UNSUPPORTED_CERTIFICATE_FORMAT, details)


class MultipleLeafCertificatesAmbiguityError(CertificateAnalyzerError):
    """Raised or reported when a bundle contains multiple plausible leaf certificates with no clear target."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, AnalysisErrorCode.MULTIPLE_LEAF_CERTIFICATES, details)


class ResourceLimitExceededError(CertificateAnalyzerError):
    """Raised when certificate input exceeds security boundaries (DoS protection)."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, AnalysisErrorCode.RESOURCE_LIMIT_EXCEEDED, details)


class TrustStoreUnavailableError(CertificateAnalyzerError):
    """Raised when the requested trust store cannot be loaded."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, AnalysisErrorCode.TRUST_STORE_UNAVAILABLE, details)


class ModelUnavailableError(CertificateAnalyzerError):
    """Raised when ML advisory model artifacts cannot be loaded."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, AnalysisErrorCode.MODEL_UNAVAILABLE, details)

