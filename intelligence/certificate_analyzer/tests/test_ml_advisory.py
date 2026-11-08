"""Unit and invariant tests for the Certificate ML Advisory module."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import pytest

# Ensure src and isolated .deps are on sys.path
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent
_ANALYZER_SRC = _INTELLIGENCE_DIR / "certificate_analyzer" / "src"
_DATASET_SRC = _INTELLIGENCE_DIR / "certificate_dataset" / "src"
_DATASET_DEPS = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"

for p in [_ANALYZER_SRC, _DATASET_SRC, _DATASET_DEPS]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from certificate_analyzer.ml.inference import CertificateMLAdvisor
from certificate_analyzer.ml.preprocessing import CertificateFeaturePreprocessor
from certificate_analyzer.api import analyze_certificate


def test_feature_preprocessor_prohibits_leakage():
    """Confirms preprocessor actively blocks target-leaking feature names."""
    leakage_candidates = ["trust_score", "finding_code", "is_policy_compliant", "rule_weak_key"]
    for bad in leakage_candidates:
        with pytest.raises(ValueError, match="Target leakage violation"):
            CertificateFeaturePreprocessor.validate_feature_names([bad])


def test_ml_advisor_inference_on_authentic_certificate():
    """Tests ML advisor prediction on genuine certificate from corpus."""
    advisor = CertificateMLAdvisor()
    assert advisor.is_ready is True

    raw_dir = Path("intelligence/certificate_dataset/data/raw")
    sample_der = next(raw_dir.glob("*.der"))
    with open(sample_der, "rb") as f:
        der_bytes = f.read()

    pred = advisor.predict(der_bytes)
    assert pred.predicted_class in ["COMPLIANT", "NON_COMPLIANT"]
    assert 0.0 <= pred.compliance_probability <= 1.0
    assert isinstance(pred.is_anomaly, bool)
    assert isinstance(pred.anomaly_score, float)
    assert pred.is_advisory is True


def test_ml_advisory_cannot_override_expired_failure():
    """Strict Invariant: Advisory ML output must not override deterministic PKI expiration."""
    key = ec.generate_private_key(ec.SECP256R1())
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "expired.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "expired.test")]))
        .public_key(key.public_key())
        .serial_number(777)
        .not_valid_before(past)
        .not_valid_after(past + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    der = expired_cert.public_bytes(serialization.Encoding.DER)

    # 1. Deterministic assessment
    assessment = analyze_certificate(der)
    assert assessment.verdict.value == "DISTRUSTED"
    assert assessment.trust_score == 0

    # 2. Advisory ML
    advisor = CertificateMLAdvisor()
    ml_pred = advisor.predict(der)
    assert ml_pred.is_advisory is True

    # Even if ML indicates structural attributes, deterministic assessment verdict remains authoritative
    assert assessment.verdict.value == "DISTRUSTED"

