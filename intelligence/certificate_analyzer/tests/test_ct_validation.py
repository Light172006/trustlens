"""Unit tests for Certificate Transparency (RFC 6962 / RFC 9162) verification."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timezone, timedelta

from certificate_analyzer.rules.ct_verifier import CertificateTransparencyVerifier
from certificate_analyzer.rules.policy import PolicyRules
from certificate_analyzer.schemas.features import CertificateFeatures


def test_ct_audit_without_scts():
    # Generate clean cert without SCT extension
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=10))
        .sign(key, hashes.SHA256())
    )

    ct_audit = CertificateTransparencyVerifier.audit_ct(cert)
    assert ct_audit["has_scts"] is False
    assert ct_audit["sct_count"] == 0
    assert ct_audit["presence_verified"] is False
    assert ct_audit["cryptographic_signature_verified"] is False
    assert ct_audit["inclusion_proof_verified"] is False


def test_policy_rule_no_scts_finding():
    features = CertificateFeatures(has_scts=False)
    cert_record = {"certificate_type": "LEAF"}
    rules = PolicyRules()

    findings = rules.evaluate(features, cert_record)
    codes = [f.code for f in findings]
    assert "RULE_NO_EMBEDDED_SCTS" in codes
    assert "RULE_CERTIFICATE_TRANSPARENCY_PRESENT" not in codes


def test_policy_rule_scts_present_finding():
    features = CertificateFeatures(has_scts=True, sct_count=2)
    cert_record = {"certificate_type": "LEAF"}
    rules = PolicyRules()

    findings = rules.evaluate(features, cert_record)
    codes = [f.code for f in findings]
    assert "RULE_CERTIFICATE_TRANSPARENCY_PRESENT" in codes
    assert "RULE_NO_EMBEDDED_SCTS" not in codes


def test_parse_single_sct_direct():
    """Verifies RFC 6962 single SCT binary decoding logic."""
    log_id = b"\x01" * 32
    ts_bytes = (1700000000000).to_bytes(8, "big")
    sig_header = b"\x04\x03"  # sha256 + ecdsa
    sig_bytes = b"\xaa" * 16
    sig_len = len(sig_bytes).to_bytes(2, "big")
    sct_body = b"\x00" + log_id + ts_bytes + b"\x00\x00" + sig_header + sig_len + sig_bytes

    parsed = CertificateTransparencyVerifier._parse_single_sct(sct_body)
    assert parsed is not None
    assert parsed["sct_version"] == 0
    assert parsed["hash_algorithm"] == "SHA256"
    assert parsed["signature_algorithm"] == "ECDSA"
    assert parsed["signature_status"] == "LOG_KEY_UNAUTHENTICATED"


def test_ct_audit_on_real_corpus_certificate():
    """Verifies CT auditing on genuine real-world certificates from the corpus."""
    from certificate_dataset.storage.store import DatasetStorage
    store = DatasetStorage()
    certs = store.read_jsonl(store.normalized_dir / "normalized_certificates.jsonl")
    found = False
    for r in certs:
        if r.get("extensions", {}).get("signed_certificate_timestamps"):
            fp = r["sha256_fingerprint"]
            der_path = store.raw_dir / f"{fp}.der"
            if der_path.exists():
                with open(der_path, "rb") as f:
                    c = x509.load_der_x509_certificate(f.read())
                audit = CertificateTransparencyVerifier.audit_ct(c)
                assert audit["has_scts"] is True
                assert audit["sct_count"] > 0
                assert audit["presence_verified"] is True
                found = True
                break
    assert found, "Expected to find at least one real certificate with SCT extension in corpus"


