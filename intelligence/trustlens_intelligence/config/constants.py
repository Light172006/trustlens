"""TrustLens Intelligence Engine — System Constants and Enumerations.

Aligned with PRD.md, ARCH.md, and API.md contracts.
"""

from enum import StrEnum


class Verdict(StrEnum):
    """Authoritative scan verdict values."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingCategory(StrEnum):
    """Categories for scan and detection findings."""
    THREAT_INTEL = "threat_intel"
    WEB_SECURITY = "web_security"
    CERTIFICATE = "certificate"
    COMMUNITY = "community"
    DOMAIN_INTELLIGENCE = "domain_intelligence"


class FindingSeverity(StrEnum):
    """Severity levels for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProviderResultStatus(StrEnum):
    """Result status from threat intelligence provider lookups."""
    MATCH = "match"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"
    SKIPPED_SENSITIVE_URL = "skipped_sensitive_url"
    STALE_CACHE = "stale_cache"


class ProviderName(StrEnum):
    """Supported external threat intelligence providers."""
    OPENPHISH = "openphish"
    URLHAUS = "urlhaus"
    COMMUNITY = "community"


class LayerCoverage(StrEnum):
    """Layer coverage status."""
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


# Algorithm and engine versioning
CURRENT_SCORING_VERSION = "trustlens-1.0"
FEATURE_SCHEMA_VERSION = "1.0.0"
MODEL_SCHEMA_VERSION = "1.0.0"

# Standard rule codes defined in PRD FR-09
RULE_OPENPHISH_URL_MATCH = "OPENPHISH_URL_MATCH"
RULE_URLHAUS_ONLINE_URL_MATCH = "URLHAUS_ONLINE_URL_MATCH"
RULE_URLHAUS_HISTORICAL_URL_MATCH = "URLHAUS_HISTORICAL_URL_MATCH"
RULE_COMMUNITY_CONFIRMED_MALICIOUS = "COMMUNITY_CONFIRMED_MALICIOUS"

RULE_CERT_CHAIN_INVALID = "CERT_CHAIN_INVALID"
RULE_CERT_HOSTNAME_MISMATCH = "CERT_HOSTNAME_MISMATCH"
RULE_CERT_EXPIRED = "CERT_EXPIRED"
RULE_TLS_LEGACY_PROTOCOL = "TLS_LEGACY_PROTOCOL"

RULE_HSTS_MISSING = "HSTS_MISSING"
RULE_CSP_MISSING = "CSP_MISSING"
RULE_X_CONTENT_TYPE_OPTIONS_MISSING = "X_CONTENT_TYPE_OPTIONS_MISSING"
RULE_REFERRER_POLICY_MISSING = "REFERRER_POLICY_MISSING"
RULE_PERMISSIONS_POLICY_MISSING = "PERMISSIONS_POLICY_MISSING"

RULE_COOKIE_SECURE_MISSING = "COOKIE_SECURE_MISSING"
RULE_COOKIE_HTTPONLY_MISSING = "COOKIE_HTTPONLY_MISSING"
RULE_COOKIE_SAMESITE_MISSING = "COOKIE_SAMESITE_MISSING"
RULE_HTTP_NO_HTTPS_REDIRECT = "HTTP_NO_HTTPS_REDIRECT"

# Domain & URL Heuristic Rules
RULE_DOMAIN_RECENTLY_REGISTERED = "DOMAIN_RECENTLY_REGISTERED"
RULE_SUSPICIOUS_IP_HOST = "SUSPICIOUS_IP_HOST"
RULE_SUSPICIOUS_USERINFO = "SUSPICIOUS_USERINFO"
RULE_SUSPICIOUS_HOMOGLYPH_PUNYCODE = "SUSPICIOUS_HOMOGLYPH_PUNYCODE"
RULE_SUSPICIOUS_EXCESSIVE_REDIRECTS = "SUSPICIOUS_EXCESSIVE_REDIRECTS"
RULE_URL_HIGH_ENTROPY = "URL_HIGH_ENTROPY"
RULE_SUSPICIOUS_KEYWORD_SUBDOMAIN = "SUSPICIOUS_KEYWORD_SUBDOMAIN"

