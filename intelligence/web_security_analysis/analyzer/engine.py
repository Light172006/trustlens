"""
TrustLens Web Security Analyzer - Core Analysis Engine
Orchestrates URL validation, safe telemetry extraction, deterministic rule auditing,
ML posture prediction, risk aggregation, and typed report synthesis.
"""

import asyncio
import datetime
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from feature_extractor import SafeLiveFeatureExtractor
from ml_predictor import MLSecurityPosturePredictor
from models import (
    ConsensusModel,
    FindingsSummaryModel,
    MLPredictionModel,
    RemediationItemModel,
    SecurityFindingModel,
    WebSecurityReport,
)
from risk_aggregator import RiskAggregator
from security_rules import evaluate_security_findings
from ssrf_guard import SSRFSecurityException
from url_validator import URLValidationError, normalize_target_url

logger = logging.getLogger("analyzer_engine")

BASE_DIR = Path(__file__).resolve().parent.parent


class WebSecurityAnalyzer:
    """
    Main entry point for analyzing the technical web security posture of target websites.
    """

    def __init__(
        self,
        extractor: Optional[SafeLiveFeatureExtractor] = None,
        predictor: Optional[MLSecurityPosturePredictor] = None,
        aggregator: Optional[RiskAggregator] = None,
    ):
        self.extractor = extractor or SafeLiveFeatureExtractor()
        self.predictor = predictor or MLSecurityPosturePredictor()
        self.aggregator = aggregator or RiskAggregator()

    @classmethod
    def from_config(cls, config_path: Optional[str] = None) -> "WebSecurityAnalyzer":
        if config_path is None:
            config_path = str(BASE_DIR / "config.yaml")
        cfg = {}
        if Path(config_path).exists():
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)

        coll_cfg = cfg.get("collection", {})
        extractor = SafeLiveFeatureExtractor(
            timeout_seconds=coll_cfg.get("timeout_seconds", 5.0),
            max_redirects=coll_cfg.get("max_redirects", 5),
            user_agent=coll_cfg.get("user_agent", "TrustLens-WebSecurity-Analyzer/1.0"),
        )
        predictor = MLSecurityPosturePredictor()
        aggregator = RiskAggregator()
        return cls(extractor=extractor, predictor=predictor, aggregator=aggregator)

    async def analyze_async(self, target_url: str) -> WebSecurityReport:
        """Asynchronously analyzes a target URL and produces a verified security report."""
        scan_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. URL Normalization & Validation
        try:
            url_info = normalize_target_url(target_url)
        except (URLValidationError, SSRFSecurityException) as e:
            logger.warning(f"URL validation rejected for '{target_url}': {e}")
            return self._build_error_report(target_url, str(e), scan_time)

        # 2. Safe Live Feature Extraction
        try:
            features = await self.extractor.extract_features(url_info["normalized_url"])
        except Exception as e:
            logger.error(f"Feature extraction failed for '{target_url}': {e}")
            return self._build_error_report(target_url, f"Extraction failed: {e}", scan_time)

        # 3. Deterministic Security Rules Evaluation
        findings_raw = evaluate_security_findings(features)

        # 4. ML Posture Prediction with Abstention
        ml_res = self.predictor.predict(features)

        # 5. Risk Aggregation & Invariant Synthesis
        agg_res = self.aggregator.aggregate_assessment(features, findings_raw, ml_res)

        # 6. Assemble Typed Pydantic Report
        findings_models = [SecurityFindingModel(**f) for f in findings_raw]
        remediation_models = [RemediationItemModel(**r) for r in agg_res["remediations"]]

        report = WebSecurityReport(
            target_url=target_url,
            normalized_domain=features["normalized_domain"],
            registrable_domain=features["registrable_domain"],
            scan_timestamp=scan_time,
            scanner_version="1.0.0",
            posture=agg_res["final_posture"],
            security_score=agg_res["security_score"],
            deterministic_posture=agg_res["deterministic_posture"],
            ml_prediction=MLPredictionModel(**agg_res["ml_prediction"]),
            consensus=ConsensusModel(**agg_res["consensus"]),
            findings_summary=FindingsSummaryModel(**agg_res["findings_summary"]),
            findings=findings_models,
            remediations=remediation_models,
            telemetry={
                k: v for k, v in features.items()
                if not k.startswith("findings") and k not in ("sample_id", "source_reference")
            },
        )

        return report

    def analyze(self, target_url: str) -> WebSecurityReport:
        """Synchronous wrapper for analyze_async."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # In an active event loop (e.g. Jupyter or async runner)
            import nest_asyncio
            nest_asyncio.apply()
            return loop.run_until_complete(self.analyze_async(target_url))
        else:
            return asyncio.run(self.analyze_async(target_url))

    def _build_error_report(self, target_url: str, error_msg: str, scan_time: str) -> WebSecurityReport:
        """Builds a structured error report for blocked or invalid targets."""
        return WebSecurityReport(
            target_url=target_url,
            normalized_domain="UNKNOWN",
            registrable_domain="UNKNOWN",
            scan_timestamp=scan_time,
            scanner_version="1.0.0",
            posture="INSUFFICIENT_EVIDENCE",
            security_score=0.0,
            deterministic_posture="INSUFFICIENT_EVIDENCE",
            ml_prediction=MLPredictionModel(
                available=False,
                predicted_posture="INSUFFICIENT_EVIDENCE",
                confidence=0.0,
                abstained=True,
                abstention_reason=error_msg,
            ),
            consensus=ConsensusModel(
                status="PRE_VALIDATION_FAILURE",
                discrepancy_explanation=error_msg,
            ),
            findings_summary=FindingsSummaryModel(
                total_findings=1,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                pass_count=0,
                affected_categories=["VALIDATION_SECURITY"],
            ),
            findings=[
                SecurityFindingModel(
                    finding_id="VAL-TARGET-REJECTED",
                    category="VALIDATION_SECURITY",
                    name="Target URL Validation Failure",
                    severity="INFO",
                    status="UNKNOWN",
                    evidence=error_msg,
                    detection_method="PRE_VALIDATION_CHECK",
                    guidance="RFC 3986, SSRF Policy",
                    recommendation="Provide a valid public HTTP or HTTPS web target.",
                )
            ],
            remediations=[],
            telemetry={"error": error_msg},
        )

