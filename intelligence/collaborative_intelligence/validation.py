"""TrustLens Collaborative Threat Intelligence — Input Validation Layer.

Performs strict, defensive syntax and structural validation on untrusted
user reports, URLs, attached evidence references, and reporter metadata.
"""

from __future__ import annotations

import re

from collaborative_intelligence.config import NormalizationConfig, ValidationConfig
from collaborative_intelligence.models import (
    CommunityReportInput,
    ValidationResult,
)
from collaborative_intelligence.normalization import (
    NormalizedURL,
    URLNormalizationError,
    normalize_url,
)


def validate_report_input(
    report: CommunityReportInput,
    val_config: ValidationConfig | None = None,
    norm_config: NormalizationConfig | None = None,
) -> tuple[ValidationResult, NormalizedURL | None]:
    """Validate a community report submission and normalize its indicator.

    Enforces input bounds, checks for suspicious patterns, and guards against
    malformed inputs.

    Args:
        report: Raw structured report input from API boundary.
        val_config: Validation limit configurations.
        norm_config: URL normalization policies.

    Returns:
        A tuple of (ValidationResult, Optional[NormalizedURL]).
    """
    v_cfg = val_config or ValidationConfig()
    n_cfg = norm_config or NormalizationConfig()

    errors: list[str] = []
    warnings: list[str] = []
    norm_url: NormalizedURL | None = None

    # 1. Validate URL presence and bounds
    if not report.original_url or not report.original_url.strip():
        errors.append("Submitted URL cannot be empty or whitespace.")
    elif len(report.original_url.strip()) < v_cfg.min_url_length:
        errors.append(f"Submitted URL is too short (minimum {v_cfg.min_url_length} characters).")
    elif len(report.original_url.strip()) > v_cfg.max_url_length:
        errors.append(f"Submitted URL exceeds maximum allowed length ({v_cfg.max_url_length}).")
    else:
        # 2. Attempt URL normalization
        try:
            norm_url = normalize_url(report.original_url, config=n_cfg)
            if norm_url.has_userinfo:
                warnings.append("URL contains embedded userinfo credentials, which have been isolated from canonical form.")
            if norm_url.port is not None:
                warnings.append(f"URL uses non-standard port: {norm_url.port}.")
            if norm_url.host.startswith("xn--"):
                warnings.append(f"Host uses IDN/Punycode encoding ({norm_url.host}), potential homograph attack.")
            if norm_url.is_ip:
                warnings.append(f"Host is an IP literal ({norm_url.host}) rather than a registered domain.")
        except URLNormalizationError as err:
            errors.append(f"URL normalization failed: {err} (code={err.code})")

    # 3. Validate description bounds
    if len(report.description) > v_cfg.max_description_length:
        errors.append(
            f"Report description exceeds maximum allowed length of {v_cfg.max_description_length} characters."
        )

    # 4. Check for evidence quantity and quality
    if not report.evidence_items:
        warnings.append("No supporting evidence items provided. Report relies solely on user claim.")
    elif len(report.evidence_items) > v_cfg.max_evidence_items:
        errors.append(f"Too many evidence items ({len(report.evidence_items)}). Maximum is {v_cfg.max_evidence_items}.")
    else:
        for idx, item in enumerate(report.evidence_items):
            if len(item.source) > v_cfg.max_evidence_source_length:
                errors.append(f"Evidence item #{idx} source string too long.")
            if len(item.description) > v_cfg.max_evidence_description_length:
                errors.append(f"Evidence item #{idx} description exceeds length limit.")

    # 5. Validate reporter metadata
    reporter = report.reporter
    if not reporter.reporter_id or not reporter.reporter_id.strip():
        errors.append("Reporter ID is missing from metadata.")
    elif len(reporter.reporter_id) > v_cfg.max_reporter_id_length:
        errors.append("Reporter ID string exceeds maximum length.")

    if reporter.previous_accepted_reports < 0 or reporter.previous_rejected_reports < 0:
        errors.append("Reporter previous report counts cannot be negative.")

    if reporter.account_age_days < 0:
        errors.append("Reporter account age cannot be negative.")

    if reporter.is_restricted:
        warnings.append("Reporter account is flagged with restricted status by platform moderation.")

    is_valid = len(errors) == 0

    return (
        ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            normalized_url=norm_url.canonical_url if norm_url else None,
            canonical_host=norm_url.host if norm_url else None,
            registrable_domain=norm_url.domain if norm_url else None,
        ),
        norm_url,
    )

