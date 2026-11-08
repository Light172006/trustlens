"""Unit and property tests for URL normalization and report input validation."""

from datetime import datetime, timezone
import pytest

from collaborative_intelligence.config import NormalizationConfig, ValidationConfig
from collaborative_intelligence.enums import (
    EvidenceStance,
    EvidenceType,
    ThreatCategory,
)
from collaborative_intelligence.models import (
    CommunityReportInput,
    EvidenceItem,
    ReporterMetadata,
)
from collaborative_intelligence.normalization import (
    URLNormalizationError,
    extract_registrable_domain,
    normalize_url,
)
from collaborative_intelligence.validation import validate_report_input


def test_url_normalization_scheme_and_hostname_case():
    """Case normalization of scheme and hostname."""
    norm = normalize_url("HTTP://EXAMPLE.COM/Path/To/Page")
    assert norm.scheme == "http"
    assert norm.host == "example.com"
    # Path preserves case sensitivity per RFC 3986
    assert norm.path == "/Path/To/Page"
    assert norm.canonical_url == "http://example.com/Path/To/Page"


def test_url_normalization_default_ports():
    """Standard ports (80 for http, 443 for https) are stripped; non-default preserved."""
    norm_http = normalize_url("http://example.com:80/index.html")
    assert norm_http.port is None
    assert norm_http.canonical_url == "http://example.com/index.html"

    norm_https = normalize_url("https://example.com:443/login")
    assert norm_https.port is None
    assert norm_https.canonical_url == "https://example.com/login"

    norm_custom = normalize_url("https://example.com:8443/login")
    assert norm_custom.port == 8443
    assert norm_custom.canonical_url == "https://example.com:8443/login"


def test_url_normalization_fragments_stripped():
    """URL fragments must be stripped from canonical matching representation."""
    norm = normalize_url("https://example.com/page#section-target-123")
    assert "#" not in norm.canonical_url
    assert norm.canonical_url == "https://example.com/page"


def test_url_normalization_userinfo_isolation():
    """User credentials must be stripped from canonical representation but tracked."""
    norm = normalize_url("https://admin:secret123@phishing-target.com/portal")
    assert norm.has_userinfo is True
    assert "admin" not in norm.canonical_url
    assert "secret123" not in norm.canonical_url
    assert norm.canonical_url == "https://phishing-target.com/portal"


def test_url_normalization_query_sorting_preservation():
    """Query parameters must be preserved and sorted deterministically."""
    norm1 = normalize_url("https://example.com/search?b=2&a=1&c=3")
    norm2 = normalize_url("https://example.com/search?c=3&b=2&a=1")
    assert norm1.canonical_url == "https://example.com/search?a=1&b=2&c=3"
    assert norm1.canonical_url == norm2.canonical_url
    assert norm1.canonical_hash == norm2.canonical_hash


def test_url_normalization_duplicate_query_params():
    """Duplicate query keys must be preserved."""
    norm = normalize_url("https://example.com/search?tag=security&tag=phishing")
    assert "tag=phishing&tag=security" in norm.canonical_url or "tag=security&tag=phishing" in norm.canonical_url
    assert norm.query.count("tag=") == 2


def test_url_normalization_idna_punycode():
    """Internationalized domain names should be canonicalized to Punycode."""
    norm = normalize_url("https://münchen.de/info")
    assert norm.host == "xn--mnchen-3ya.de"
    assert norm.canonical_url == "https://xn--mnchen-3ya.de/info"


def test_url_normalization_trailing_dots():
    """Trailing dot on hostname should be stripped safely."""
    norm = normalize_url("https://example.org./about")
    assert norm.host == "example.org"
    assert norm.canonical_url == "https://example.org/about"


def test_url_normalization_ipv4_and_ipv6():
    """IPv4 and IPv6 literals are handled properly."""
    norm_v4 = normalize_url("http://192.168.1.10:8080/admin")
    assert norm_v4.is_ip is True
    assert norm_v4.ip_version == 4
    assert norm_v4.host == "192.168.1.10"
    assert norm_v4.port == 8080

    norm_v6 = normalize_url("http://[2001:db8::1]:9000/api")
    assert norm_v6.is_ip is True
    assert norm_v6.ip_version == 6
    assert norm_v6.host == "[2001:db8::1]"
    assert norm_v6.port == 9000


def test_url_normalization_dot_segments():
    """RFC 3986 dot segments are resolved safely."""
    norm = normalize_url("https://example.com/a/b/../c/./d")
    assert norm.path == "/a/c/d"


def test_url_normalization_percent_encoding():
    """Unreserved characters are unquoted; reserved are canonical uppercase hex."""
    # '~' is unreserved (0x7E) and should be unquoted
    norm = normalize_url("https://example.com/%7Euser/%2Fpath")
    assert norm.path == "/~user/%2Fpath"


def test_extract_registrable_domain():
    """Registrable domain extraction handles common ccTLDs and standard TLDs."""
    assert extract_registrable_domain("secure.login.example.co.uk") == "example.co.uk"
    assert extract_registrable_domain("bank.portal.hsbc.com.au") == "hsbc.com.au"
    assert extract_registrable_domain("mail.sub.google.com") == "google.com"
    assert extract_registrable_domain("example.com") == "example.com"
    assert extract_registrable_domain("192.168.1.1") == "192.168.1.1"


def test_url_normalization_malformed_rejects():
    """Malformed or invalid schemes/characters are rejected with meaningful errors."""
    with pytest.raises(URLNormalizationError) as exc_empty:
        normalize_url("")
    assert exc_empty.value.code == "EMPTY_URL"

    with pytest.raises(URLNormalizationError) as exc_scheme:
        normalize_url("javascript:alert(1)")
    assert exc_scheme.value.code == "UNSUPPORTED_SCHEME"

    with pytest.raises(URLNormalizationError) as exc_null:
        normalize_url("https://example.com/test\x00malicious")
    assert exc_null.value.code == "INVALID_CONTROL_CHARS"


def test_report_validation_success():
    """A valid report with evidence passes validation."""
    report = CommunityReportInput(
        original_url="https://secure-login-phish.net/account/update",
        category=ThreatCategory.PHISHING,
        description="Fake credential login page impersonating Microsoft 365.",
        evidence_items=[
            EvidenceItem(
                evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT,
                stance=EvidenceStance.SUPPORTS,
                source="community_user",
                description="Observed login form posting password to external drop server.",
            )
        ],
        reporter=ReporterMetadata(
            reporter_id="user_test_123",
            account_age_days=180,
            previous_accepted_reports=10,
            previous_rejected_reports=1,
            is_trusted=True,
        ),
    )
    res, norm = validate_report_input(report)
    assert res.is_valid is True
    assert len(res.errors) == 0
    assert norm is not None
    assert norm.host == "secure-login-phish.net"
    assert norm.domain == "secure-login-phish.net"


def test_report_validation_missing_evidence_warns():
    """A report without evidence passes syntax validation but records a warning."""
    report = CommunityReportInput(
        original_url="https://suspicious-site.org/",
        category=ThreatCategory.SCAM,
        description="I think this is a scam.",
        evidence_items=[],
        reporter=ReporterMetadata(reporter_id="user_abc"),
    )
    res, norm = validate_report_input(report)
    assert res.is_valid is True
    assert any("No supporting evidence" in w for w in res.warnings)


def test_report_validation_oversized_fields_rejected():
    """Oversized fields trigger validation errors (DoS defense)."""
    cfg = ValidationConfig(max_description_length=100)
    report = CommunityReportInput(
        original_url="https://example.com/",
        description="A" * 150,
        reporter=ReporterMetadata(reporter_id="user_abc"),
    )
    res, _ = validate_report_input(report, val_config=cfg)
    assert res.is_valid is False
    assert any("description exceeds maximum allowed length" in e for e in res.errors)


def test_validation_edge_cases():
    """Defensive validation tests for short URLs, negative counts, and invalid metadata."""
    from pydantic import ValidationError

    # 1. Pydantic enforces non-negative counts at model construction
    with pytest.raises(ValidationError):
        ReporterMetadata(
            reporter_id="u_neg",
            account_age_days=-5,
        )

    with pytest.raises(ValidationError):
        ReporterMetadata(
            reporter_id="u_neg",
            previous_accepted_reports=-1,
        )

    # 2. Missing reporter_id
    rep_no_id = CommunityReportInput(
        original_url="https://example.com/",
        reporter=ReporterMetadata(reporter_id="   "),
    )
    res_no_id, _ = validate_report_input(rep_no_id)
    assert res_no_id.is_valid is False
    assert any("Reporter ID is missing" in e for e in res_no_id.errors)

    # 3. Restricted reporter warning
    rep_restricted = CommunityReportInput(
        original_url="https://example.com/",
        reporter=ReporterMetadata(reporter_id="u_restr", is_restricted=True),
    )
    res_restr, _ = validate_report_input(rep_restricted)
    assert any("restricted status" in w for w in res_restr.warnings)

    # 4. Too many evidence items
    cfg_ev = ValidationConfig(max_evidence_items=2)
    rep_many_ev = CommunityReportInput(
        original_url="https://example.com/",
        evidence_items=[
            EvidenceItem(evidence_type=EvidenceType.SCREENSHOT, source="s", description="d1"),
            EvidenceItem(evidence_type=EvidenceType.SCREENSHOT, source="s", description="d2"),
            EvidenceItem(evidence_type=EvidenceType.SCREENSHOT, source="s", description="d3"),
        ],
        reporter=ReporterMetadata(reporter_id="u_test"),
    )
    res_many_ev, _ = validate_report_input(rep_many_ev, val_config=cfg_ev)
    assert res_many_ev.is_valid is False
    assert any("Too many evidence items" in e for e in res_many_ev.errors)


def test_threat_category_aliases():
    """Verify ThreatCategory alias parsing and case-insensitivity."""
    assert ThreatCategory.from_string("phish") == ThreatCategory.PHISHING
    assert ThreatCategory.from_string("MALWARE") == ThreatCategory.MALWARE
    assert ThreatCategory.from_string("redirect") == ThreatCategory.SUSPICIOUS_REDIRECT
    assert ThreatCategory.from_string("unsolicited_bulk") == ThreatCategory.SPAM
    assert ThreatCategory.from_string("unknown_xyz") == ThreatCategory.OTHER

