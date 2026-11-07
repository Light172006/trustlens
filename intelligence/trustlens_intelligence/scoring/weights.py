"""TrustLens Intelligence — Scoring Weights and Thresholds Configuration."""

from dataclasses import dataclass

from trustlens_intelligence.config.constants import (
    CURRENT_SCORING_VERSION,
    RULE_CERT_CHAIN_INVALID,
    RULE_CERT_EXPIRED,
    RULE_CERT_HOSTNAME_MISMATCH,
    RULE_COMMUNITY_CONFIRMED_MALICIOUS,
    RULE_COOKIE_HTTPONLY_MISSING,
    RULE_COOKIE_SAMESITE_MISSING,
    RULE_COOKIE_SECURE_MISSING,
    RULE_CSP_MISSING,
    RULE_DOMAIN_RECENTLY_REGISTERED,
    RULE_HSTS_MISSING,
    RULE_HTTP_NO_HTTPS_REDIRECT,
    RULE_OPENPHISH_URL_MATCH,
    RULE_PERMISSIONS_POLICY_MISSING,
    RULE_REFERRER_POLICY_MISSING,
    RULE_SUSPICIOUS_EXCESSIVE_REDIRECTS,
    RULE_SUSPICIOUS_HOMOGLYPH_PUNYCODE,
    RULE_SUSPICIOUS_IP_HOST,
    RULE_TLS_LEGACY_PROTOCOL,
    RULE_URL_HIGH_ENTROPY,
    RULE_URLHAUS_HISTORICAL_URL_MATCH,
    RULE_URLHAUS_ONLINE_URL_MATCH,
    RULE_X_CONTENT_TYPE_OPTIONS_MISSING,
)


@dataclass(frozen=True)
class ScoringWeights:
    """Configurable scoring weights aligned with PRD FR-09."""

    version: str = CURRENT_SCORING_VERSION

    # Decisive rules
    openphish_match_points: int = 100
    urlhaus_online_match_points: int = 100
    community_confirmed_points: int = 90

    # Additive rules
    cert_chain_invalid_points: int = 25
    cert_hostname_mismatch_points: int = 25
    cert_expired_points: int = 20
    tls_legacy_protocol_points: int = 10

    hsts_missing_points: int = 5
    csp_missing_points: int = 4
    x_content_type_options_missing_points: int = 2
    referrer_policy_missing_points: int = 1
    permissions_policy_missing_points: int = 1

    cookie_secure_per_cookie: int = 3
    cookie_secure_max_cap: int = 6
    cookie_httponly_per_cookie: int = 2
    cookie_httponly_max_cap: int = 4
    cookie_samesite_per_cookie: int = 2
    cookie_samesite_max_cap: int = 4

    http_no_https_redirect_points: int = 5
    urlhaus_historical_points: int = 25

    # Heuristics
    domain_recently_registered_points: int = 15
    suspicious_ip_host_points: int = 20
    suspicious_homoglyph_points: int = 20
    suspicious_excessive_redirects_points: int = 15
    url_high_entropy_points: int = 10

    # Score caps and boundaries
    max_score: int = 100
    safe_max: int = 24
    suspicious_min: int = 25
    suspicious_max: int = 74


DEFAULT_WEIGHTS = ScoringWeights()

