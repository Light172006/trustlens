"""Tests for TrustLens Feature Extraction Engine."""

import pytest

from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.features.lexical import (
    calculate_shannon_entropy,
    count_suspicious_keywords,
    extract_lexical_features,
)
from trustlens_intelligence.features.structural import (
    count_subdomains,
    extract_structural_features,
    has_homoglyphs_or_mixed_scripts,
    is_ip_address,
)
from trustlens_intelligence.schemas.evidence import (
    CookieEvidence,
    DomainIntelligenceEvidence,
    HttpEvidence,
    ScanEvidence,
    TlsCertificateEvidence,
)


def test_shannon_entropy_calculation():
    """Verify entropy computation for low, medium, and high entropy strings."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # English text typically has entropy ~3.0 - 4.0
    text_entropy = calculate_shannon_entropy("https://www.example.com")
    assert 3.0 < text_entropy < 4.2
    # High randomness (e.g. base64 / hex tokens)
    rand_entropy = calculate_shannon_entropy("8f7b2a9c3d1e4f0a9b8c7d6e5f4a3b2c1d0e")
    assert rand_entropy > 3.8


def test_suspicious_keyword_counter():
    """Verify detection of suspicious tokens in URLs."""
    text = "https://example.com/banking/secure-login-verify/account-update"
    count = count_suspicious_keywords(text)
    assert count >= 4  # banking, secure/security, login, verify, account, update


def test_ip_address_detection():
    """Detect standard IPv4, IPv6, and numeric IP representations."""
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("93.184.216.34") is True
    assert is_ip_address("[2001:db8::1]") is True
    assert is_ip_address("2130706433") is True  # Integer representation of 127.0.0.1
    assert is_ip_address("example.com") is False
    assert is_ip_address("sub.example.co.uk") is False


def test_subdomain_counter():
    """Verify subdomain levels calculation respecting ccTLDs."""
    assert count_subdomains("example.com") == 0
    assert count_subdomains("login.example.com") == 1
    assert count_subdomains("a.b.c.example.com") == 3
    assert count_subdomains("portal.example.co.uk") == 1
    assert count_subdomains("192.168.1.1") == 0


def test_homoglyph_detection():
    """Detect Cyrillic / confusable characters mixed into domains."""
    # Standard Latin
    assert has_homoglyphs_or_mixed_scripts("paypal.com") is False
    # Cyrillic 'а' replacing Latin 'a'
    cyrillic_spoof = "pаypаl.com"
    assert has_homoglyphs_or_mixed_scripts(cyrillic_spoof) is True


def test_missing_evidence_preservation():
    """Missing observations must remain None, never coerced into safe defaults."""
    ev = ScanEvidence(
        original_url="http://example.com",
        http=None,
        tls=None,
        domain_intelligence=None,
    )
    features = FeatureExtractor().extract(ev)
    assert features.tls_valid is None
    assert features.cert_chain_valid is None
    assert features.cert_hostname_match is None
    assert features.cert_is_expired is None
    assert features.domain_age_days is None
    assert features.is_https is False


def test_feature_provenance_metadata():
    """Verify that all extracted features include clear observation provenance."""
    ev = ScanEvidence(
        original_url="https://example.com",
        http=HttpEvidence(status_code=200, security_headers={"content-security-policy": "default-src 'self'"}),
        tls=TlsCertificateEvidence(chain_valid=True),
    )
    features = FeatureExtractor().extract(ev)
    assert "has_csp" in features.provenance
    assert "cert_chain_valid" in features.provenance
    assert "url_length" in features.provenance


def test_cross_domain_redirect_and_non_standard_port():
    """Verify detection of cross-domain redirects and non-standard ports."""
    from trustlens_intelligence.schemas.evidence import RedirectHopEvidence

    ev = ScanEvidence(
        original_url="http://initial-domain.com:8080/path",
        scheme="http",
        http=HttpEvidence(
            status_code=200,
            redirect_count=1,
            redirects=[
                RedirectHopEvidence(
                    hop_index=0,
                    source_url="http://initial-domain.com:8080/path",
                    destination_url="https://destination-domain.org/landing",
                    http_status=302,
                    resolved_host="initial-domain.com",
                    resolved_ips=["1.1.1.1"],
                )
            ],
        ),
    )
    features = FeatureExtractor().extract(ev)
    assert features.has_non_standard_port is True
    assert features.has_cross_domain_redirect is True
    assert features.http_to_https_redirect is True


def test_adversarial_ip_evasion_variants():
    """Verify detection of octal, hex, dword, and shortened IP obfuscation."""
    from trustlens_intelligence.common.url_utils import is_adversarial_or_standard_ip

    # Octal representations of 127.0.0.1
    assert is_adversarial_or_standard_ip("0177.0.0.1") is True
    assert is_adversarial_or_standard_ip("0177.0000.0000.0001") is True

    # Hex representations
    assert is_adversarial_or_standard_ip("0x7f.0.0.1") is True
    assert is_adversarial_or_standard_ip("127.0.0.0x1") is True
    assert is_adversarial_or_standard_ip("0x7f.0x0.0x0.0x1") is True
    assert is_adversarial_or_standard_ip("0x7f000001") is True

    # Dword representation of 127.0.0.1
    assert is_adversarial_or_standard_ip("2130706433") is True

    # Shortened / class-based IPv4
    assert is_adversarial_or_standard_ip("127.1") is True
    assert is_adversarial_or_standard_ip("127.0.1") is True

    # Standard IPv4 and IPv6
    assert is_adversarial_or_standard_ip("192.168.1.1") is True
    assert is_adversarial_or_standard_ip("[::1]") is True
    assert is_adversarial_or_standard_ip("2001:db8::1") is True

    # Valid domain names must not be classified as IP
    assert is_adversarial_or_standard_ip("google.com") is False
    assert is_adversarial_or_standard_ip("sub.domain.co.uk") is False
    assert is_adversarial_or_standard_ip("test123.com") is False


def test_userinfo_credential_extraction_and_safe_host():
    """Verify that credentials in URLs do not corrupt hostname extraction."""
    from trustlens_intelligence.common.url_utils import extract_safe_hostname, has_userinfo_credentials

    url = "https://admin:supersecret@actual-malicious-domain.com/login"
    assert extract_safe_hostname(url) == "actual-malicious-domain.com"
    assert has_userinfo_credentials(url) is True

    ev = ScanEvidence(original_url=url)
    assert ev.host == "actual-malicious-domain.com"
    features = FeatureExtractor().extract(ev)
    assert features.has_userinfo is True
    assert features.host_length == len("actual-malicious-domain.com")


def test_strict_url_canonicalization():
    """Verify strict URL canonicalization eliminates evasive variations."""
    from trustlens_intelligence.common.url_utils import canonicalize_url_strict

    # Default ports
    assert canonicalize_url_strict("http://example.com:80/path") == "http://example.com/path"
    assert canonicalize_url_strict("https://example.com:443/secure") == "https://example.com/secure"

    # Non-default port preserved
    assert canonicalize_url_strict("https://example.com:8443/api") == "https://example.com:8443/api"

    # Userinfo stripped from canonical indicator
    assert canonicalize_url_strict("https://user:pass@example.com/path") == "https://example.com/path"

    # Trailing FQDN dot removed
    assert canonicalize_url_strict("http://example.com./path") == "http://example.com/path"

    # Fragment removed
    assert canonicalize_url_strict("https://example.com/path#section") == "https://example.com/path"


def test_punycode_and_homoglyph_detection():
    """Verify Punycode IDNA decoding detects confusable character substitution."""
    # Cyrillic 'a' encoded as punycode
    punycode_domain = "xn--pypal-4ve.com"
    assert has_homoglyphs_or_mixed_scripts(punycode_domain) is True

    ev = ScanEvidence(original_url=f"https://{punycode_domain}/login")
    features = FeatureExtractor().extract(ev)
    assert features.is_punycode is True
    assert features.has_homoglyphs is True

