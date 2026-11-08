"""Public API entrypoints for TrustLens Certificate Analyzer."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

# Ensure dataset package and isolated dependencies are accessible
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent
_DATASET_SRC = _INTELLIGENCE_DIR / "certificate_dataset" / "src"
_DATASET_DEPS = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"

if _DATASET_SRC.exists() and str(_DATASET_SRC) not in sys.path:
    sys.path.insert(0, str(_DATASET_SRC))
if _DATASET_DEPS.exists() and str(_DATASET_DEPS) not in sys.path:
    sys.path.insert(0, str(_DATASET_DEPS))

from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine
from certificate_analyzer.schemas.assessment import CertificateAssessment
from certificate_analyzer.schemas.context import EndpointTLSContext

_DEFAULT_ENGINE: Optional[CertificateAnalyzerEngine] = None


def get_default_engine() -> CertificateAnalyzerEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = CertificateAnalyzerEngine()
    return _DEFAULT_ENGINE


def analyze_certificate(
    certificate_input: Union[bytes, str, Dict[str, Any]],
    target_hostname: Optional[str] = None,
    revocation_observation: Optional[Dict[str, Any]] = None,
    reference_time: Optional[datetime] = None,
    engine: Optional[CertificateAnalyzerEngine] = None,
    include_ml_advisory: bool = False,
) -> CertificateAssessment:
    """Analyzes a raw DER, PEM, or parsed certificate record with optional hostname context and revocation evidence."""
    active_engine = engine or get_default_engine()
    context = EndpointTLSContext(target_hostname=target_hostname) if target_hostname else None
    return active_engine.analyze(
        certificate_input,
        context=context,
        revocation_observation=revocation_observation,
        reference_time=reference_time,
        include_ml_advisory=include_ml_advisory,
    )


def analyze_pem(
    pem_str: str,
    target_hostname: Optional[str] = None,
    revocation_observation: Optional[Dict[str, Any]] = None,
    reference_time: Optional[datetime] = None,
    include_ml_advisory: bool = False,
) -> CertificateAssessment:
    """Convenience helper to analyze a PEM certificate or fullchain bundle string."""
    return analyze_certificate(
        pem_str,
        target_hostname=target_hostname,
        revocation_observation=revocation_observation,
        reference_time=reference_time,
        include_ml_advisory=include_ml_advisory,
    )


def analyze_endpoint_tls(
    certificate_der: bytes,
    target_hostname: str,
    port: int = 443,
    tls_protocol_version: str = "TLSv1.3",
    cipher_suite: Optional[str] = None,
    presented_intermediates: Optional[List[bytes]] = None,
    revocation_observation: Optional[Dict[str, Any]] = None,
    reference_time: Optional[datetime] = None,
    engine: Optional[CertificateAnalyzerEngine] = None,
    include_ml_advisory: bool = False,
) -> CertificateAssessment:
    """Analyzes a certificate within the context of a negotiated endpoint TLS handshake."""
    active_engine = engine or get_default_engine()
    context = EndpointTLSContext(
        target_hostname=target_hostname,
        port=port,
        sni_hostname=target_hostname,
        tls_protocol_version=tls_protocol_version,
        cipher_suite=cipher_suite,
        presented_intermediates=presented_intermediates or [],
    )
    return active_engine.analyze(
        certificate_der,
        context=context,
        revocation_observation=revocation_observation,
        reference_time=reference_time,
        include_ml_advisory=include_ml_advisory,
    )
