"""Unit tests for domain and certificate normalization."""

from certificate_dataset.normalization.canonicalizer import Canonicalizer


def test_domain_normalization_standard():
    ascii_dom, uni_dom = Canonicalizer.normalize_domain("   ExAmPlE.CoM.  ")
    assert ascii_dom == "example.com"
    assert uni_dom == "example.com"


def test_domain_normalization_wildcard():
    ascii_dom, uni_dom = Canonicalizer.normalize_domain("*.Sub.ExAmPlE.cOm")
    assert ascii_dom == "*.sub.example.com"
    assert uni_dom == "*.sub.example.com"


def test_domain_normalization_punycode():
    # münchen.de in Punycode is xn--mnchen-3ya.de
    ascii_dom, uni_dom = Canonicalizer.normalize_domain("xn--mnchen-3ya.de")
    assert ascii_dom == "xn--mnchen-3ya.de"
    assert "münchen" in uni_dom


def test_record_normalization():
    record = {
        "sha256_fingerprint": "ABCD1234EFFF" + "0" * 52,
        "domain_identity": {
            "dns_san_entries": ["FoO.bAr.CoM", "*.Wild.Org"],
            "ip_san_entries": [" 1.1.1.1 "],
        },
    }
    norm = Canonicalizer.normalize_record(record)
    assert norm["sha256_fingerprint"] == "abcd1234efff" + "0" * 52
    assert "foo.bar.com" in norm["domain_identity"]["dns_san_entries"]
    assert "*.wild.org" in norm["domain_identity"]["wildcard_san_indicators"]
    assert norm["domain_identity"]["has_wildcard"] is True

