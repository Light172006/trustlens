"""TrustLens Collaborative Threat Intelligence — Deduplication Engine.

Identifies exact duplicate submissions, canonically equivalent URLs,
and related reports across paths or subdomains.

Critical rules:
1. Exact and canonically equivalent reports can be safely grouped.
2. Different paths on the same website are related, but NEVER merged as exact duplicates.
3. Subdomains on the same root domain are related, but NEVER merged as exact duplicates.
4. Independent reporter identities are preserved in the duplicate cluster so corroboration
   remains measurable.
5. Emits indexed hashes (canonical_hash, host_hash) for O(1) database persistence.
"""

from __future__ import annotations

from typing import List, Optional

from collaborative_intelligence.config import DeduplicationConfig, NormalizationConfig
from collaborative_intelligence.enums import DeduplicationStrength
from collaborative_intelligence.models import (
    CommunityReportInput,
    DeduplicationResult,
    DuplicateMatch,
)
from collaborative_intelligence.normalization import NormalizedURL, normalize_url


class DeduplicationEngine:
    """Engine for identifying duplicate and related community threat reports."""

    def __init__(
        self,
        config: DeduplicationConfig | None = None,
        norm_config: NormalizationConfig | None = None,
    ) -> None:
        self.config = config or DeduplicationConfig()
        self.norm_config = norm_config or NormalizationConfig()

    def evaluate_duplicates(
        self,
        target_report: CommunityReportInput,
        candidate_reports: List[CommunityReportInput],
        target_norm: Optional[NormalizedURL] = None,
    ) -> DeduplicationResult:
        """Compare a target report against candidate reports for duplication and relations.

        Args:
            target_report: The report being analyzed.
            candidate_reports: Existing historical reports to compare against.
            target_norm: Pre-calculated NormalizedURL for target if available.

        Returns:
            DeduplicationResult detailing exact matches and related path/host variants.
        """
        if not target_norm:
            target_norm = normalize_url(target_report.original_url, config=self.norm_config)

        duplicate_matches: list[DuplicateMatch] = []
        related_matches: list[DuplicateMatch] = []
        primary_submission_id: str | None = None

        for candidate in candidate_reports:
            if candidate.submission_id == target_report.submission_id:
                continue

            cand_norm = normalize_url(candidate.original_url, config=self.norm_config)

            # 1. Exact match on raw string
            if target_report.original_url == candidate.original_url:
                match = DuplicateMatch(
                    matched_submission_id=candidate.submission_id,
                    strength=DeduplicationStrength.EXACT,
                    method="RAW_URL_EXACT",
                    explanation="Exact string match on raw submitted URL.",
                    safe_to_group=True,
                )
                duplicate_matches.append(match)
                if primary_submission_id is None:
                    primary_submission_id = candidate.submission_id

            # 2. Canonical equivalent (normalized match)
            elif target_norm.canonical_hash == cand_norm.canonical_hash:
                match = DuplicateMatch(
                    matched_submission_id=candidate.submission_id,
                    strength=DeduplicationStrength.CANONICAL_EQUIVALENT,
                    method="CANONICAL_HASH_MATCH",
                    explanation=(
                        f"Canonical equivalent after RFC 3986 normalization "
                        f"('{target_norm.canonical_url}' == '{cand_norm.canonical_url}')."
                    ),
                    safe_to_group=True,
                )
                duplicate_matches.append(match)
                if primary_submission_id is None:
                    primary_submission_id = candidate.submission_id

            # 3. Path variant: Same host, different path or query
            elif target_norm.host_hash == cand_norm.host_hash:
                match = DuplicateMatch(
                    matched_submission_id=candidate.submission_id,
                    strength=DeduplicationStrength.PATH_VARIANT,
                    method="HOST_MATCH_PATH_VARIANT",
                    explanation=(
                        f"Same host '{target_norm.host}' with different paths: "
                        f"'{target_norm.path}' vs '{cand_norm.path}'. "
                        "Preserved as related observation; not merged as duplicate."
                    ),
                    safe_to_group=False,
                )
                related_matches.append(match)

            # 4. Host variant: Same registrable domain, different subdomain/host
            elif target_norm.domain_hash == cand_norm.domain_hash:
                match = DuplicateMatch(
                    matched_submission_id=candidate.submission_id,
                    strength=DeduplicationStrength.HOST_VARIANT,
                    method="DOMAIN_MATCH_HOST_VARIANT",
                    explanation=(
                        f"Same registrable domain '{target_norm.domain}' with different hosts: "
                        f"'{target_norm.host}' vs '{cand_norm.host}'. "
                        "Preserved as related domain campaign; not merged as duplicate."
                    ),
                    safe_to_group=False,
                )
                related_matches.append(match)

        is_duplicate = len(duplicate_matches) > 0

        return DeduplicationResult(
            is_duplicate=is_duplicate,
            primary_submission_id=primary_submission_id,
            duplicate_matches=duplicate_matches,
            related_matches=related_matches,
        )

