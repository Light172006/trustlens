"""Unit tests for deduplication and public key reuse detection."""

from certificate_dataset.deduplication.deduplicator import Deduplicator


def test_deduplicator_detects_duplicate_fingerprints():
    dedup = Deduplicator()
    rec1 = {"sha256_fingerprint": "a" * 64, "spki_sha256_fingerprint": "1" * 64}
    rec2 = {"sha256_fingerprint": "a" * 64, "spki_sha256_fingerprint": "1" * 64}

    is_dup1, _ = dedup.process_record(rec1)
    is_dup2, meta2 = dedup.process_record(rec2)

    assert is_dup1 is False
    assert is_dup2 is True
    assert meta2["is_duplicate_fingerprint"] is True


def test_deduplicator_detects_reused_keys():
    dedup = Deduplicator()
    # Reissued cert: different fingerprint, same public key
    cert_a = {"sha256_fingerprint": "1" * 64, "spki_sha256_fingerprint": "k" * 64}
    cert_b = {"sha256_fingerprint": "2" * 64, "spki_sha256_fingerprint": "k" * 64}

    _, meta_a = dedup.process_record(cert_a)
    is_dup_b, meta_b = dedup.process_record(cert_b)

    assert is_dup_b is False
    assert meta_b["is_reused_public_key"] is True
    assert meta_b["key_sharing_count"] == 2

