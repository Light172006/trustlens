"""Comprehensive test suite for RFC 9525 service identity validation."""

from certificate_analyzer.rules.identity_rfc9525 import RFC9525IdentityVerifier


def test_exact_dns_match():
    matched, status, pattern = RFC9525IdentityVerifier.verify(
        reference_identity="api.trustlens.io",
        dns_sans=["api.trustlens.io", "trustlens.io"],
        ip_sans=[],
    )
    assert matched is True
    assert status == "MATCH_EXACT_DNS"
    assert pattern == "api.trustlens.io"


def test_dns_mismatch():
    matched, status, pattern = RFC9525IdentityVerifier.verify(
        reference_identity="attacker.com",
        dns_sans=["api.trustlens.io"],
        ip_sans=[],
    )
    assert matched is False
    assert status == "MISMATCH_DNS"
    assert pattern is None


def test_wildcard_valid_single_level_match():
    # *.example.com matches foo.example.com
    matched, status, pattern = RFC9525IdentityVerifier.verify(
        reference_identity="foo.example.com",
        dns_sans=["*.example.com"],
        ip_sans=[],
    )
    assert matched is True
    assert status == "MATCH_WILDCARD_DNS"
    assert pattern == "*.example.com"


def test_wildcard_multi_level_mismatch():
    # *.example.com MUST NOT match bar.foo.example.com (RFC 9525 Section 6.4.3)
    matched, status, pattern = RFC9525IdentityVerifier.verify(
        reference_identity="bar.foo.example.com",
        dns_sans=["*.example.com"],
        ip_sans=[],
    )
    assert matched is False
    assert status == "MISMATCH_DNS"


def test_wildcard_apex_mismatch():
    # *.example.com MUST NOT match apex example.com
    matched, status, pattern = RFC9525IdentityVerifier.verify(
        reference_identity="example.com",
        dns_sans=["*.example.com"],
        ip_sans=[],
    )
    assert matched is False
    assert status == "MISMATCH_DNS"


def test_wildcard_invalid_partial_positions():
    # Partial wildcards like f*.com or *foo.com are prohibited by RFC 9525
    matched1, status1, _ = RFC9525IdentityVerifier.verify(
        reference_identity="foo.example.com",
        dns_sans=["f*.example.com"],
        ip_sans=[],
    )
    assert matched1 is False

    matched2, status2, _ = RFC9525IdentityVerifier.verify(
        reference_identity="foo.example.com",
        dns_sans=["*foo.example.com"],
        ip_sans=[],
    )
    assert matched2 is False

    # Embedded wildcards like sub.*.example.com are prohibited
    matched3, status3, _ = RFC9525IdentityVerifier.verify(
        reference_identity="sub.foo.example.com",
        dns_sans=["sub.*.example.com"],
        ip_sans=[],
    )
    assert matched3 is False


def test_ip_address_matching():
    # Exact IPv4 match against iPAddress SAN
    matched_v4, status_v4, pat_v4 = RFC9525IdentityVerifier.verify(
        reference_identity="192.0.2.1",
        dns_sans=["example.com"],
        ip_sans=["192.0.2.1"],
    )
    assert matched_v4 is True
    assert status_v4 == "MATCH_IP"
    assert pat_v4 == "192.0.2.1"

    # Exact IPv6 match against iPAddress SAN
    matched_v6, status_v6, _ = RFC9525IdentityVerifier.verify(
        reference_identity="2001:db8::1",
        dns_sans=[],
        ip_sans=["2001:db8::1"],
    )
    assert matched_v6 is True
    assert status_v6 == "MATCH_IP"


def test_ip_address_mismatch_and_no_wildcard():
    # IP address mismatch
    matched, status, _ = RFC9525IdentityVerifier.verify(
        reference_identity="192.0.2.99",
        dns_sans=[],
        ip_sans=["192.0.2.1"],
    )
    assert matched is False
    assert status == "MISMATCH_IP"

    # Wildcards MUST NOT match IP addresses
    matched_ip_wc, _, _ = RFC9525IdentityVerifier.verify(
        reference_identity="192.0.2.1",
        dns_sans=["*.0.2.1", "*"],
        ip_sans=[],
    )
    assert matched_ip_wc is False


def test_case_insensitivity_and_trailing_dots():
    # Case normalization
    matched_case, status_case, _ = RFC9525IdentityVerifier.verify(
        reference_identity="ApI.ExAmPlE.cOm",
        dns_sans=["api.example.com"],
        ip_sans=[],
    )
    assert matched_case is True
    assert status_case == "MATCH_EXACT_DNS"

    # Trailing root dot normalization
    matched_dot, status_dot, _ = RFC9525IdentityVerifier.verify(
        reference_identity="api.example.com.",
        dns_sans=["api.example.com."],
        ip_sans=[],
    )
    assert matched_dot is True


def test_idna_punycode_matching():
    # Unicode reference domain matched against Punycode SAN
    matched, status, _ = RFC9525IdentityVerifier.verify(
        reference_identity="münchen.de",
        dns_sans=["xn--mnchen-3ya.de"],
        ip_sans=[],
    )
    assert matched is True
    assert status == "MATCH_EXACT_DNS"

