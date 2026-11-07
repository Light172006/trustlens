"""TrustLens Intelligence — Unified Feature Extraction Engine.

Coordinates lexical, structural, web security, and intelligence feature extractors
to produce a validated ExtractedFeatures model from normalized ScanEvidence.
"""

import logging
from typing import Any

from trustlens_intelligence.features.lexical import extract_lexical_features
from trustlens_intelligence.features.provenance import build_provenance_metadata
from trustlens_intelligence.features.security import extract_security_features
from trustlens_intelligence.features.structural import extract_structural_features
from trustlens_intelligence.schemas.evidence import ScanEvidence
from trustlens_intelligence.schemas.features import ExtractedFeatures

logger = logging.getLogger("trustlens.intelligence.features.extractor")


class FeatureExtractor:
    """Deterministic feature extractor transforming ScanEvidence into ExtractedFeatures."""

    def extract(self, evidence: ScanEvidence) -> ExtractedFeatures:
        """Extract all feature groups from the provided ScanEvidence.

        Args:
            evidence: Normalized scan observations.

        Returns:
            Validated ExtractedFeatures object.
        """
        target_url = evidence.canonical_url or evidence.original_url
        host = evidence.host

        # 1. Lexical features
        lexical = extract_lexical_features(target_url)

        # 2. Structural features
        structural = extract_structural_features(target_url, explicit_host=host)

        # 3. Security & TLS features
        security = extract_security_features(
            scheme=evidence.scheme,
            http=evidence.http,
            tls=evidence.tls,
        )

        # 4. Domain & Threat Intelligence
        domain_age: int | None = None
        if evidence.domain_intelligence:
            domain_age = evidence.domain_intelligence.domain_age_days

        openphish_match = False
        urlhaus_match = False
        urlhaus_online = False
        if evidence.threat_intelligence:
            openphish_match = bool(evidence.threat_intelligence.openphish_match)
            urlhaus_match = bool(evidence.threat_intelligence.urlhaus_match)
            url_status = (evidence.threat_intelligence.urlhaus_url_status or "").lower()
            urlhaus_online = urlhaus_match and (url_status == "online")

        community_reports = 0
        if evidence.community_intelligence:
            community_reports = evidence.community_intelligence.confirmed_report_count

        combined: dict[str, Any] = {
            **lexical,
            **structural,
            **security,
            "domain_age_days": domain_age,
            "openphish_match": openphish_match,
            "urlhaus_match": urlhaus_match,
            "urlhaus_online": urlhaus_online,
            "community_confirmed_reports": community_reports,
        }

        # 5. Provenance tracking
        provenance = build_provenance_metadata(combined)
        combined["provenance"] = provenance

        features = ExtractedFeatures(**combined)
        return features

