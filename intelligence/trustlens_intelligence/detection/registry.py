"""TrustLens Intelligence — Detection Rule Registry."""

import logging
from typing import Iterator

from trustlens_intelligence.detection.base_rule import DetectionRule
from trustlens_intelligence.detection.rules import (
    CertChainInvalidRule,
    CertExpiredRule,
    CertHostnameMismatchRule,
    CommunityConfirmedMaliciousRule,
    CookieHttpOnlyMissingRule,
    CookieSameSiteMissingRule,
    CookieSecureMissingRule,
    CspMissingRule,
    DomainRecentlyRegisteredRule,
    HstsMissingRule,
    HttpNoHttpsRedirectRule,
    OpenPhishMatchRule,
    PermissionsPolicyMissingRule,
    ReferrerPolicyMissingRule,
    SuspiciousExcessiveRedirectsRule,
    SuspiciousHomoglyphPunycodeRule,
    SuspiciousIpHostRule,
    SuspiciousUserinfoRule,
    TlsLegacyProtocolRule,
    UrlHighEntropyRule,
    URLhausHistoricalMatchRule,
    URLhausOnlineMatchRule,
    XContentTypeOptionsMissingRule,
)

logger = logging.getLogger("trustlens.intelligence.detection.registry")


class RuleRegistry:
    """Manages available and active threat detection rules."""

    def __init__(self, populate_defaults: bool = True) -> None:
        self._rules: dict[str, DetectionRule] = {}
        self._enabled_rules: set[str] = set()

        if populate_defaults:
            self._load_defaults()

    def _load_defaults(self) -> None:
        """Register the standard TrustLens v1.0 rule suite."""
        default_rules: list[DetectionRule] = [
            # Decisive Threat Intel & Community
            OpenPhishMatchRule(),
            URLhausOnlineMatchRule(),
            CommunityConfirmedMaliciousRule(),
            # Additive Threat Intel
            URLhausHistoricalMatchRule(),
            # Certificate & TLS
            CertChainInvalidRule(),
            CertHostnameMismatchRule(),
            CertExpiredRule(),
            TlsLegacyProtocolRule(),
            # HTTP Security Headers
            HstsMissingRule(),
            CspMissingRule(),
            XContentTypeOptionsMissingRule(),
            ReferrerPolicyMissingRule(),
            PermissionsPolicyMissingRule(),
            # Insecure Cookies
            CookieSecureMissingRule(),
            CookieHttpOnlyMissingRule(),
            CookieSameSiteMissingRule(),
            # Redirect & Transport
            HttpNoHttpsRedirectRule(),
            # Domain & Heuristics
            DomainRecentlyRegisteredRule(),
            SuspiciousIpHostRule(),
            SuspiciousUserinfoRule(),
            SuspiciousHomoglyphPunycodeRule(),
            SuspiciousExcessiveRedirectsRule(),
            UrlHighEntropyRule(),
        ]
        for r in default_rules:
            self.register(r)

    def register(self, rule: DetectionRule, enabled: bool = True) -> None:
        """Register a detection rule."""
        self._rules[rule.code] = rule
        if enabled:
            self._enabled_rules.add(rule.code)
        logger.debug("Registered rule %s (enabled=%s)", rule.code, enabled)

    def enable(self, code: str) -> None:
        """Enable a registered rule by code."""
        if code in self._rules:
            self._enabled_rules.add(code)

    def disable(self, code: str) -> None:
        """Disable a registered rule by code."""
        self._enabled_rules.discard(code)

    def get_rule(self, code: str) -> DetectionRule | None:
        """Retrieve a rule by code."""
        return self._rules.get(code)

    def get_enabled_rules(self) -> list[DetectionRule]:
        """Return all active detection rules."""
        return [self._rules[code] for code in self._enabled_rules if code in self._rules]

    def __iter__(self) -> Iterator[DetectionRule]:
        return iter(self.get_enabled_rules())

    def __len__(self) -> int:
        return len(self._enabled_rules)

