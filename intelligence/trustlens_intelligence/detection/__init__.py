"""TrustLens Intelligence Detection Package."""

from trustlens_intelligence.detection.base_rule import DetectionRule
from trustlens_intelligence.detection.engine import DetectionEngine, DetectionResult
from trustlens_intelligence.detection.registry import RuleRegistry
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
    TlsLegacyProtocolRule,
    UrlHighEntropyRule,
    URLhausHistoricalMatchRule,
    URLhausOnlineMatchRule,
    XContentTypeOptionsMissingRule,
)

__all__ = [
    "DetectionRule",
    "DetectionEngine",
    "DetectionResult",
    "RuleRegistry",
    "OpenPhishMatchRule",
    "URLhausOnlineMatchRule",
    "CommunityConfirmedMaliciousRule",
    "URLhausHistoricalMatchRule",
    "CertChainInvalidRule",
    "CertHostnameMismatchRule",
    "CertExpiredRule",
    "TlsLegacyProtocolRule",
    "HstsMissingRule",
    "CspMissingRule",
    "XContentTypeOptionsMissingRule",
    "ReferrerPolicyMissingRule",
    "PermissionsPolicyMissingRule",
    "CookieSecureMissingRule",
    "CookieHttpOnlyMissingRule",
    "CookieSameSiteMissingRule",
    "HttpNoHttpsRedirectRule",
    "DomainRecentlyRegisteredRule",
    "SuspiciousIpHostRule",
    "SuspiciousHomoglyphPunycodeRule",
    "SuspiciousExcessiveRedirectsRule",
    "UrlHighEntropyRule",
]

