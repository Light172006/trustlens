"""Inference interface for Certificate ML Advisory and Anomaly Detection."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Union

# Ensure isolated .deps is available
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
_DEPS_DIR = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"
_DATASET_SRC = _INTELLIGENCE_DIR / "certificate_dataset" / "src"
for p in [_DEPS_DIR, _DATASET_SRC]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import joblib
import pandas as pd

from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES
from certificate_dataset.parsing.parser import X509CertificateParser


@dataclass
class MLCompliancePrediction:
    """Structured advisory prediction from the Certificate ML pipeline."""

    predicted_class: str  # "COMPLIANT" or "NON_COMPLIANT"
    compliance_probability: float  # 0.0 to 1.0
    is_anomaly: bool  # True if unusual / outlier profile
    anomaly_score: float  # Raw isolation forest decision function
    confidence: float  # Margin confidence metric
    advisory_notes: str
    model_version: str = "1.0.0"
    is_advisory: bool = True  # Strict architectural flag: Advisory only

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CertificateMLAdvisor:
    """Production inference engine for ML advisory predictions."""

    def __init__(self, artifacts_dir: Optional[Path] = None):
        self.artifacts_dir = artifacts_dir or Path(__file__).parent / "artifacts"
        self.classifier_path = self.artifacts_dir / "champion_model.joblib"
        self.anomaly_path = self.artifacts_dir / "anomaly_detector.joblib"

        self._classifier = None
        self._anomaly_detector = None
        self._load_models()

    def _load_models(self) -> None:
        if self.classifier_path.exists():
            self._classifier = joblib.load(self.classifier_path)
        if self.anomaly_path.exists():
            self._anomaly_detector = joblib.load(self.anomaly_path)

    @property
    def is_ready(self) -> bool:
        return self._classifier is not None and self._anomaly_detector is not None

    def predict(self, certificate_input: Union[bytes, str, Dict[str, Any]]) -> MLCompliancePrediction:
        """Generates advisory compliance probability and anomaly score for a certificate."""
        if not self.is_ready:
            raise RuntimeError("ML advisor artifacts are not loaded. Run CertificateMLTrainer first.")

        # Ensure we have a parsed dictionary
        cert_record: Dict[str, Any]
        if isinstance(certificate_input, dict):
            cert_record = certificate_input
        elif isinstance(certificate_input, (bytes, str)):
            input_bytes = certificate_input.encode("utf-8") if isinstance(certificate_input, str) else certificate_input
            cert_record = X509CertificateParser.parse(input_bytes)
        else:
            raise TypeError("Unsupported certificate input type for ML inference")

        # Extract features for single inference row
        row = self._extract_single_features(cert_record)
        df_row = pd.DataFrame([row])

        # Supervised classification prediction
        feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
        X = df_row[feature_cols]

        prob = float(self._classifier.predict_proba(X)[0, 1])
        pred_label = "COMPLIANT" if prob >= 0.5 else "NON_COMPLIANT"
        confidence = float(abs(prob - 0.5) * 2.0)  # Maps [0.5, 1.0] -> [0.0, 1.0]

        # Anomaly detection prediction
        anomaly_pred = int(self._anomaly_detector.predict(X)[0])  # -1 = anomaly, 1 = normal
        anomaly_score = float(self._anomaly_detector.decision_function(X)[0])
        is_anomaly = (anomaly_pred == -1)

        notes = (
            f"Advisory signal: predicted {pred_label} ({prob*100:.1f}% probability). "
            f"{'Profile flagged as atypical/anomalous relative to Web PKI norms.' if is_anomaly else 'Standard structural profile.'} "
            f"Note: This signal is advisory and does NOT supersede deterministic RFC validation."
        )

        return MLCompliancePrediction(
            predicted_class=pred_label,
            compliance_probability=round(prob, 4),
            is_anomaly=is_anomaly,
            anomaly_score=round(anomaly_score, 4),
            confidence=round(confidence, 4),
            advisory_notes=notes,
        )

    def predict_safe(self, certificate_input: Union[bytes, str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Safe non-blocking execution of advisory prediction; returns None on any failure."""
        if not self.is_ready:
            return None
        try:
            prediction = self.predict(certificate_input)
            return prediction.to_dict()
        except Exception:
            return None

    def _extract_single_features(self, r: Dict[str, Any]) -> Dict[str, Any]:
        pk = r.get("public_key") or {}
        dom = r.get("domain_identity") or {}
        exts = r.get("extensions") or {}

        sans = dom.get("subject_alternative_names") or []
        sct_ext = exts.get("signed_certificate_timestamps")
        has_scts = 1 if sct_ext else 0
        sct_count = len(sct_ext) if isinstance(sct_ext, list) else 0

        ext_count = sum(1 for k, v in exts.items() if v is not None and v != [] and v != {})
        ku = exts.get("key_usage")
        ku_count = len(ku) if isinstance(ku, list) else (sum(1 for v in ku.values() if v) if isinstance(ku, dict) else 0)
        eku = exts.get("extended_key_usage")
        eku_count = len(eku) if isinstance(eku, list) else 0

        is_ca = 1 if (r.get("is_ca") or exts.get("basic_constraints", {}).get("is_ca")) else 0
        is_self_signed = 1 if r.get("is_self_signed") else 0
        subj_len = len(r.get("subject_dn") or "")

        return {
            "key_algorithm": str(pk.get("algorithm") or "UNKNOWN"),
            "key_size_bits": float(pk.get("key_size_bits") or 0),
            "ec_curve": str(pk.get("ec_curve") or "none"),
            "signature_algorithm": str(r.get("signature_algorithm") or "UNKNOWN"),
            "validity_duration_days": float(r.get("validity_duration_days") or 0.0),
            "san_count": int(len(sans)),
            "is_wildcard": int(1 if dom.get("is_wildcard") else 0),
            "has_scts": int(has_scts),
            "sct_count": int(sct_count),
            "extension_count": int(ext_count),
            "key_usage_count": int(ku_count),
            "extended_key_usage_count": int(eku_count),
            "is_ca": int(is_ca),
            "is_self_signed": int(is_self_signed),
            "subject_dn_length": int(subj_len),
        }

