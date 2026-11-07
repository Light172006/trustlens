"""TrustLens Intelligence — Normalized Scan Evidence Schemas.

Represents normalized observations provided by the scanning backend.
The intelligence engine interprets this evidence without executing target fetches.
"""

from typing import Any
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator

from trustlens_intelligence.common.url_utils import extract_safe_hostname


class CookieEvidence(BaseModel):
    """Normalized cookie observation."""

    name: str = Field(..., description="Cookie name")
    secure: bool = Field(default=False, description="Whether Secure attribute is set")
    httponly: bool = Field(default=False, description="Whether HttpOnly attribute is set")
    samesite: str | None = Field(default=None, description="SameSite value ('Strict', 'Lax', 'None', or None)")


class RedirectHopEvidence(BaseModel):
    """Observation of an individual redirect hop."""

    hop_index: int = Field(..., ge=0, le=10, description="Zero-based hop index")
    source_url: str = Field(..., description="Source URL before redirect")
    destination_url: str = Field(..., description="Target URL specified in Location header")
    http_status: int = Field(..., description="HTTP status code (301, 302, etc.)")
    resolved_host: str = Field(..., description="Resolved hostname for hop")
    resolved_ips: list[str] = Field(default_factory=list, description="Validated IP addresses")
    tls_verified: bool = Field(default=False, description="Whether TLS was verified for this hop")


class HttpEvidence(BaseModel):
    """Normalized HTTP layer evidence."""

    status_code: int | None = Field(default=None, description="Final HTTP status code")
    final_url: str | None = Field(default=None, description="Effective URL after following redirects")
    redirect_count: int = Field(default=0, ge=0, description="Total number of redirect hops followed")
    redirects: list[RedirectHopEvidence] = Field(default_factory=list, description="Redirect hop history")
    security_headers: dict[str, str | None] = Field(
        default_factory=dict,
        description="Observed HTTP response headers (lower-cased keys)",
    )
    cookies: list[CookieEvidence] = Field(default_factory=list, description="Cookies observed in response")
    response_time_ms: float | None = Field(default=None, ge=0, description="Response time in milliseconds")

    @field_validator("security_headers", mode="before")
    @classmethod
    def normalize_header_keys(cls, v: Any) -> dict[str, str | None]:
        if isinstance(v, dict):
            return {str(k).lower(): (str(val) if val is not None else None) for k, val in v.items()}
        return {}


class TlsCertificateEvidence(BaseModel):
    """Normalized TLS handshake and certificate evidence."""

    valid: bool | None = Field(default=None, description="Overall TLS validity")
    chain_valid: bool | None = Field(default=None, description="Whether certificate chain is trusted")
    hostname_match: bool | None = Field(default=None, description="Whether certificate SAN/CN matches target hostname")
    days_until_expiry: int | None = Field(default=None, description="Days remaining until certificate expiration")
    is_expired: bool | None = Field(default=None, description="Whether certificate notAfter date is in the past")
    expires_soon: bool | None = Field(default=None, description="Whether expiring within configured threshold (30 days)")
    protocol_version: str | None = Field(default=None, description="Negotiated TLS version (e.g., 'TLSv1.3', 'TLSv1.0')")
    cipher_suite: str | None = Field(default=None, description="Negotiated cipher suite name")
    subject_cn: str | None = Field(default=None, description="Subject Common Name")
    issuer: str | None = Field(default=None, description="Certificate Issuer string")
    san_dns: list[str] = Field(default_factory=list, description="Subject Alternative Names (DNS entries)")
    sct_present: bool = Field(default=False, description="Signed Certificate Timestamp extension presence")


class DomainIntelligenceEvidence(BaseModel):
    """Domain intelligence and registration facts."""

    domain_age_days: int | None = Field(default=None, ge=0, description="Age of domain in days since registration")
    registrar: str | None = Field(default=None, description="Domain registrar name")
    created_date: str | None = Field(default=None, description="ISO registration date")
    nameservers: list[str] = Field(default_factory=list, description="Domain authoritative nameservers")


class ThreatIntelEvidence(BaseModel):
    """Threat feed query results and indicators."""

    openphish_match: bool | None = Field(default=None, description="True if matched in OpenPhish feed")
    openphish_status: str = Field(default="no_match", description="OpenPhish status (match/no_match/unavailable/etc.)")
    urlhaus_match: bool | None = Field(default=None, description="True if matched in URLhaus database")
    urlhaus_status: str = Field(default="no_match", description="URLhaus status")
    urlhaus_url_status: str | None = Field(
        default=None,
        description="URLhaus URL status: 'online', 'offline', or 'unknown'",
    )


class CommunityIntelligenceEvidence(BaseModel):
    """Community reports and verification data."""

    confirmed_report_count: int = Field(default=0, ge=0, description="Total moderator-confirmed reports")
    distinct_reporter_count: int = Field(default=0, ge=0, description="Count of distinct reporter accounts for confirmed reports")
    pending_report_count: int = Field(default=0, ge=0, description="Unreviewed community reports count")
    reports: list[dict[str, Any]] = Field(default_factory=list, description="Raw confirmed report summaries")


class ScanEvidence(BaseModel):
    """Root container of normalized website scan evidence.

    Passed by the backend orchestrator to the intelligence engine.
    """

    scan_id: str = Field(default="", description="Unique scan identifier")
    original_url: str = Field(..., min_length=1, description="Original URL as submitted")
    canonical_url: str | None = Field(default=None, description="Normalized canonical URL")
    host: str | None = Field(default=None, description="Target hostname")
    scheme: str | None = Field(default=None, description="Target scheme (http or https)")
    is_sensitive: bool = Field(default=False, description="True if URL contains sensitive query parameters")

    http: HttpEvidence | None = Field(default=None, description="HTTP layer observations")
    tls: TlsCertificateEvidence | None = Field(default=None, description="TLS certificate observations")
    domain_intelligence: DomainIntelligenceEvidence | None = Field(default=None, description="Domain metadata")
    threat_intelligence: ThreatIntelEvidence | None = Field(default=None, description="Threat feed match observations")
    community_intelligence: CommunityIntelligenceEvidence | None = Field(default=None, description="Community reports")

    @field_validator("original_url")
    @classmethod
    def validate_original_url(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("original_url cannot be empty or whitespace")
        return cleaned

    def model_post_init(self, __context: Any) -> None:
        """Derive host, scheme, and canonical_url safely if not explicitly provided."""
        if not self.canonical_url:
            self.canonical_url = self.original_url
        if not self.host or not self.scheme:
            target = self.canonical_url or self.original_url
            if not self.host:
                self.host = extract_safe_hostname(target) or None
            if not self.scheme:
                try:
                    parsed = urlparse(target if "://" in target else f"http://{target}")
                    if parsed.scheme:
                        self.scheme = parsed.scheme.lower()
                except Exception:
                    if target.lower().startswith("https://"):
                        self.scheme = "https"
                    elif target.lower().startswith("http://"):
                        self.scheme = "http"
                    else:
                        self.scheme = "http"

