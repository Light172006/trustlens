"""TrustLens Intelligence — Machine Learning Feature Allowlist.

Defines the explicit set of intrinsic features permitted for machine learning
training and inference. Strictly excludes external threat intelligence lookup
flags (e.g., OpenPhish, URLhaus) to prevent target leakage and ensure generalization
to novel, unseen zero-day attacks.
"""

from typing import Any

# Intrinsic features permitted for ML training and inference
ML_INTRINSIC_FEATURE_NAMES: tuple[str, ...] = (
    # Lexical features (11)
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "url_entropy",
    "host_entropy",
    "digit_count",
    "special_char_count",
    "suspicious_keyword_count",
    "has_executable_extension",
    "malware_keyword_count",
    # Structural features (7)
    "subdomain_count",
    "is_ip_host",
    "has_userinfo",
    "is_punycode",
    "has_homoglyphs",
    "has_non_standard_port",
    "has_c2_port",
    # HTTP & Web security features (12)
    "is_https",
    "redirect_count",
    "has_cross_domain_redirect",
    "http_to_https_redirect",
    "has_hsts",
    "has_csp",
    "has_x_content_type_options",
    "has_referrer_policy",
    "has_permissions_policy",
    "insecure_cookie_count",
    "missing_httponly_cookie_count",
    "missing_samesite_cookie_count",
    # Certificate & TLS features (6)
    "tls_valid",
    "cert_chain_valid",
    "cert_hostname_match",
    "cert_is_expired",
    "cert_days_until_expiry",
    "is_legacy_tls",
    # Domain Intelligence (1)
    "domain_age_days",
)

# Explicitly excluded external lookup features reserved strictly for deterministic rules
THREAT_FEED_EXCLUDED_FEATURES: tuple[str, ...] = (
    "openphish_match",
    "urlhaus_match",
    "urlhaus_online",
    "community_confirmed_reports",
)


def filter_allowlisted_features(
    raw_feature_dict: dict[str, Any],
) -> dict[str, float | int]:
    """Filter a feature dictionary to retain only allowlisted intrinsic features.

    Excludes threat feed lookup flags to avoid target leakage during model training.
    """
    filtered: dict[str, float | int] = {}
    for feature_name in ML_INTRINSIC_FEATURE_NAMES:
        val = raw_feature_dict.get(feature_name, 0.0)
        if isinstance(val, (int, float)):
            filtered[feature_name] = val
        elif isinstance(val, bool):
            filtered[feature_name] = 1.0 if val else 0.0
        else:
            filtered[feature_name] = -1.0
    return filtered

