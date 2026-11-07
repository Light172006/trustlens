"""TrustLens Intelligence — Feature Provenance Mapping."""

STANDARD_PROVENANCE_MAP: dict[str, str] = {
    "url_length": "canonical_url.length",
    "host_length": "canonical_url.host.length",
    "path_length": "canonical_url.path.length",
    "query_length": "canonical_url.query.length",
    "url_entropy": "canonical_url.entropy",
    "host_entropy": "canonical_url.host.entropy",
    "digit_count": "canonical_url.digits",
    "special_char_count": "canonical_url.special_chars",
    "suspicious_keyword_count": "canonical_url.keywords",
    "subdomain_count": "host.subdomains",
    "is_ip_host": "host.ip_detection",
    "is_punycode": "host.idna_punycode",
    "has_homoglyphs": "host.unicode_homoglyphs",
    "has_non_standard_port": "canonical_url.port",
    "is_https": "scheme",
    "redirect_count": "http.redirect_count",
    "has_cross_domain_redirect": "http.redirects.destination",
    "http_to_https_redirect": "http.redirects.scheme_transition",
    "has_hsts": "http.security_headers.strict-transport-security",
    "has_csp": "http.security_headers.content-security-policy",
    "has_x_content_type_options": "http.security_headers.x-content-type-options",
    "has_referrer_policy": "http.security_headers.referrer-policy",
    "has_permissions_policy": "http.security_headers.permissions-policy",
    "insecure_cookie_count": "http.cookies.secure",
    "missing_httponly_cookie_count": "http.cookies.httponly",
    "missing_samesite_cookie_count": "http.cookies.samesite",
    "tls_valid": "tls.valid",
    "cert_chain_valid": "tls.chain_valid",
    "cert_hostname_match": "tls.hostname_match",
    "cert_is_expired": "tls.is_expired",
    "cert_days_until_expiry": "tls.days_until_expiry",
    "is_legacy_tls": "tls.protocol_version",
    "domain_age_days": "domain_intelligence.domain_age_days",
    "openphish_match": "threat_intelligence.openphish_match",
    "urlhaus_match": "threat_intelligence.urlhaus_match",
    "urlhaus_online": "threat_intelligence.urlhaus_url_status",
    "community_confirmed_reports": "community_intelligence.confirmed_report_count",
}


def build_provenance_metadata(features_dict: dict[str, object]) -> dict[str, str]:
    """Build provenance dictionary for all present features."""
    return {k: STANDARD_PROVENANCE_MAP.get(k, "inferred") for k in features_dict}

