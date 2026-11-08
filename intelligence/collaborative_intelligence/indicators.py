"""TrustLens Collaborative Threat Intelligence — Confirmed Indicator Engine.

Manages indicator lifecycle (confirmation, dispute, expiration, revocation)
and performs scoped threat indicator matching for future TrustLens scans.

Guarantees:
1. Unconfirmed, disputed, expired, and revoked indicators NEVER masquerade as active threat intelligence.
2. Explicit indicator scopes (EXACT_URL, HOST, DOMAIN) are strictly respected.
3. Path or subdomain overreach is prevented: single URL reports cannot falsely match an entire domain.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from collaborative_intelligence.config import IndicatorLifecycleConfig, NormalizationConfig
from collaborative_intelligence.enums import IndicatorScope, IndicatorStatus
from collaborative_intelligence.models import (
    ConfirmedIndicator,
    ConfirmedIndicatorMatch,
)
from collaborative_intelligence.normalization import NormalizedURL, normalize_url


def evaluate_indicator_status(
    indicator: ConfirmedIndicator,
    current_time: Optional[datetime] = None,
) -> IndicatorStatus:
    """Evaluate current authoritative lifecycle status of an indicator."""
    now = current_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    # 1. Revocation takes absolute priority
    if indicator.revoked_at is not None:
        return IndicatorStatus.REVOKED

    # 2. Dispute status suspends active matching pending re-investigation
    if indicator.disputed_at is not None:
        return IndicatorStatus.DISPUTED

    # 3. Expiration checks TTL
    exp = indicator.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if now >= exp:
        return IndicatorStatus.EXPIRED

    # 4. Check if status was explicitly set to unconfirmed
    if indicator.status == IndicatorStatus.UNCONFIRMED:
        return IndicatorStatus.UNCONFIRMED

    return IndicatorStatus.CONFIRMED


class IndicatorMatcher:
    """Matches scan target URLs against confirmed threat indicators respecting scope and status."""

    def __init__(
        self,
        norm_config: NormalizationConfig | None = None,
        lifecycle_config: IndicatorLifecycleConfig | None = None,
    ) -> None:
        self.norm_config = norm_config or NormalizationConfig()
        self.lifecycle_config = lifecycle_config or IndicatorLifecycleConfig()

    def match(
        self,
        target_url: str,
        indicators: List[ConfirmedIndicator],
        current_time: Optional[datetime] = None,
    ) -> ConfirmedIndicatorMatch:
        """Query an incoming target URL against a collection of confirmed indicators.

        Args:
            target_url: The URL being scanned.
            indicators: Available threat indicators from database.
            current_time: Time of scan evaluation (defaults to now UTC).

        Returns:
            ConfirmedIndicatorMatch detailing whether an active threat indicator matched.
        """
        now = current_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        try:
            norm_target: NormalizedURL = normalize_url(target_url, config=self.norm_config)
        except Exception as exc:
            return ConfirmedIndicatorMatch(
                matched=False,
                target_url=target_url,
                indicator=None,
                matched_scope=None,
                is_active=False,
                explanation=f"Target URL normalization failed: {exc}",
            )

        # Separate potential matches by scope precedence: EXACT_URL > HOST > DOMAIN
        exact_match: ConfirmedIndicator | None = None
        host_match: ConfirmedIndicator | None = None
        domain_match: ConfirmedIndicator | None = None

        inactive_candidate: tuple[ConfirmedIndicator, IndicatorStatus, IndicatorScope] | None = None

        for ind in indicators:
            status = evaluate_indicator_status(ind, current_time=now)
            is_active = status == IndicatorStatus.CONFIRMED

            # Check matching by scope
            if ind.scope == IndicatorScope.EXACT_URL:
                # Match canonical URL
                try:
                    ind_norm = normalize_url(ind.indicator_value, config=self.norm_config)
                    if ind_norm.canonical_hash == norm_target.canonical_hash:
                        if is_active and exact_match is None:
                            exact_match = ind
                        elif not is_active and inactive_candidate is None:
                            inactive_candidate = (ind, status, IndicatorScope.EXACT_URL)
                except Exception:
                    if ind.indicator_value.strip().lower() == norm_target.canonical_url:
                        if is_active and exact_match is None:
                            exact_match = ind

            elif ind.scope == IndicatorScope.HOST:
                # Match canonical host
                ind_host = ind.indicator_value.strip().lower().rstrip(".")
                if ind_host == norm_target.host:
                    if is_active and host_match is None:
                        host_match = ind
                    elif not is_active and inactive_candidate is None:
                        inactive_candidate = (ind, status, IndicatorScope.HOST)

            elif ind.scope == IndicatorScope.DOMAIN:
                # Match registrable domain or subdomain of domain
                ind_domain = ind.indicator_value.strip().lower().rstrip(".")
                if norm_target.domain == ind_domain or norm_target.host.endswith(f".{ind_domain}"):
                    if is_active and domain_match is None:
                        domain_match = ind
                    elif not is_active and inactive_candidate is None:
                        inactive_candidate = (ind, status, IndicatorScope.DOMAIN)

        # Select highest-precedence active match
        if exact_match:
            return ConfirmedIndicatorMatch(
                matched=True,
                target_url=target_url,
                indicator=exact_match,
                matched_scope=IndicatorScope.EXACT_URL,
                is_active=True,
                explanation=(
                    f"Exact URL match with confirmed threat indicator '{exact_match.indicator_id}' "
                    f"({exact_match.threat_category.value})."
                ),
            )

        if host_match:
            return ConfirmedIndicatorMatch(
                matched=True,
                target_url=target_url,
                indicator=host_match,
                matched_scope=IndicatorScope.HOST,
                is_active=True,
                explanation=(
                    f"Hostname match with confirmed threat indicator '{host_match.indicator_id}' "
                    f"for host '{norm_target.host}' ({host_match.threat_category.value})."
                ),
            )

        if domain_match:
            return ConfirmedIndicatorMatch(
                matched=True,
                target_url=target_url,
                indicator=domain_match,
                matched_scope=IndicatorScope.DOMAIN,
                is_active=True,
                explanation=(
                    f"Domain-level match with confirmed threat indicator '{domain_match.indicator_id}' "
                    f"for domain '{norm_target.domain}' ({domain_match.threat_category.value})."
                ),
            )

        # If no active match was found, but an inactive indicator matched, report inactive
        if inactive_candidate:
            cand_ind, cand_status, cand_scope = inactive_candidate
            return ConfirmedIndicatorMatch(
                matched=False,
                target_url=target_url,
                indicator=cand_ind,
                matched_scope=cand_scope,
                is_active=False,
                explanation=(
                    f"Target matched indicator '{cand_ind.indicator_id}', but indicator is currently "
                    f"inactive ({cand_status.value}). Excluded from threat intelligence signal."
                ),
            )

        return ConfirmedIndicatorMatch(
            matched=False,
            target_url=target_url,
            indicator=None,
            matched_scope=None,
            is_active=False,
            explanation="No confirmed community threat indicators matched the scan target.",
        )

