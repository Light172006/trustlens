"""TrustLens Intelligence — Extracted Feature Schema."""

from typing import Any
from pydantic import BaseModel, Field

from trustlens_intelligence.config.constants import FEATURE_SCHEMA_VERSION


class ExtractedFeatures(BaseModel):
    """Normalized, typed feature vector extracted from scan evidence.

    Designed for both deterministic rule evaluation and machine learning inference.
    """

    schema_version: str = Field(default=FEATURE_SCHEMA_VERSION, description="Feature schema version")

    # Lexical features
    url_length: int = Field(default=0, ge=0)
    host_length: int = Field(default=0, ge=0)
    path_length: int = Field(default=0, ge=0)
    query_length: int = Field(default=0, ge=0)
    url_entropy: float = Field(default=0.0, ge=0.0)
    host_entropy: float = Field(default=0.0, ge=0.0)
    digit_count: int = Field(default=0, ge=0)
    special_char_count: int = Field(default=0, ge=0)
    suspicious_keyword_count: int = Field(default=0, ge=0)
    has_executable_extension: bool = Field(default=False)
    malware_keyword_count: int = Field(default=0, ge=0)

    # Structural features
    subdomain_count: int = Field(default=0, ge=0)
    is_ip_host: bool = Field(default=False)
    has_userinfo: bool = Field(default=False)
    is_punycode: bool = Field(default=False)
    has_homoglyphs: bool = Field(default=False)
    has_non_standard_port: bool = Field(default=False)
    has_c2_port: bool = Field(default=False)

    # HTTP & Web security features
    is_https: bool = Field(default=False)
    redirect_count: int = Field(default=0, ge=0)
    has_cross_domain_redirect: bool = Field(default=False)
    http_to_https_redirect: bool = Field(default=False)
    has_hsts: bool = Field(default=False)
    has_csp: bool = Field(default=False)
    has_x_content_type_options: bool = Field(default=False)
    has_referrer_policy: bool = Field(default=False)
    has_permissions_policy: bool = Field(default=False)
    insecure_cookie_count: int = Field(default=0, ge=0)
    missing_httponly_cookie_count: int = Field(default=0, ge=0)
    missing_samesite_cookie_count: int = Field(default=0, ge=0)

    # Certificate & TLS features (nullable when TLS was not checked or not available)
    tls_valid: bool | None = Field(default=None)
    cert_chain_valid: bool | None = Field(default=None)
    cert_hostname_match: bool | None = Field(default=None)
    cert_is_expired: bool | None = Field(default=None)
    cert_days_until_expiry: int | None = Field(default=None)
    is_legacy_tls: bool | None = Field(default=None)

    # Domain metadata & Intelligence
    domain_age_days: int | None = Field(default=None)
    openphish_match: bool = Field(default=False)
    urlhaus_match: bool = Field(default=False)
    urlhaus_online: bool = Field(default=False)
    community_confirmed_reports: int = Field(default=0, ge=0)

    # Provenance tracking (which scan observation produced which feature)
    provenance: dict[str, str] = Field(
        default_factory=dict,
        description="Source observation mapping for auditability",
    )

    def to_ml_dict(self) -> dict[str, float | int]:
        """Convert features to numeric dictionary suitable for ML tabular input.

        Missing numeric values (like domain_age_days or cert_days_until_expiry)
        are mapped to sentinel values (-1.0) and missing booleans to 0.0 with
        corresponding missing-indicator flags.
        """
        return {
            "url_length": self.url_length,
            "host_length": self.host_length,
            "path_length": self.path_length,
            "query_length": self.query_length,
            "url_entropy": self.url_entropy,
            "host_entropy": self.host_entropy,
            "digit_count": self.digit_count,
            "special_char_count": self.special_char_count,
            "suspicious_keyword_count": self.suspicious_keyword_count,
            "has_executable_extension": 1.0 if self.has_executable_extension else 0.0,
            "malware_keyword_count": float(self.malware_keyword_count),
            "subdomain_count": self.subdomain_count,
            "is_ip_host": 1.0 if self.is_ip_host else 0.0,
            "has_userinfo": 1.0 if self.has_userinfo else 0.0,
            "is_punycode": 1.0 if self.is_punycode else 0.0,
            "has_homoglyphs": 1.0 if self.has_homoglyphs else 0.0,
            "has_non_standard_port": 1.0 if self.has_non_standard_port else 0.0,
            "has_c2_port": 1.0 if self.has_c2_port else 0.0,
            "is_https": 1.0 if self.is_https else 0.0,
            "redirect_count": self.redirect_count,
            "has_cross_domain_redirect": 1.0 if self.has_cross_domain_redirect else 0.0,
            "http_to_https_redirect": 1.0 if self.http_to_https_redirect else 0.0,
            "has_hsts": 1.0 if self.has_hsts else 0.0,
            "has_csp": 1.0 if self.has_csp else 0.0,
            "has_x_content_type_options": 1.0 if self.has_x_content_type_options else 0.0,
            "has_referrer_policy": 1.0 if self.has_referrer_policy else 0.0,
            "has_permissions_policy": 1.0 if self.has_permissions_policy else 0.0,
            "insecure_cookie_count": self.insecure_cookie_count,
            "missing_httponly_cookie_count": self.missing_httponly_cookie_count,
            "missing_samesite_cookie_count": self.missing_samesite_cookie_count,
            "tls_valid": 1.0 if self.tls_valid is True else (0.0 if self.tls_valid is False else -1.0),
            "cert_chain_valid": 1.0 if self.cert_chain_valid is True else (0.0 if self.cert_chain_valid is False else -1.0),
            "cert_hostname_match": 1.0 if self.cert_hostname_match is True else (0.0 if self.cert_hostname_match is False else -1.0),
            "cert_is_expired": 1.0 if self.cert_is_expired is True else (0.0 if self.cert_is_expired is False else -1.0),
            "cert_days_until_expiry": float(self.cert_days_until_expiry) if self.cert_days_until_expiry is not None else -1.0,
            "is_legacy_tls": 1.0 if self.is_legacy_tls is True else (0.0 if self.is_legacy_tls is False else -1.0),
            "domain_age_days": float(self.domain_age_days) if self.domain_age_days is not None else -1.0,
            "openphish_match": 1.0 if self.openphish_match else 0.0,
            "urlhaus_match": 1.0 if self.urlhaus_match else 0.0,
            "urlhaus_online": 1.0 if self.urlhaus_online else 0.0,
            "community_confirmed_reports": float(self.community_confirmed_reports),
        }

