"""Unit tests for certificate chain construction, hierarchy, and trust anchor resolution."""

from datetime import datetime, timezone
from certificate_dataset.chains.builder import ChainBuilder
from certificate_dataset.trust_stores.root_store import TrustStoreManager
from cryptography import x509


def test_chain_builder_with_root_store():
    # Load Mozilla Trust Store
    ts_manager = TrustStoreManager()
    ts_manager.load_from_certifi()
    builder = ChainBuilder(ts_manager)

    # Ingest roots
    assert ts_manager.total_roots() > 0

    # Pick a genuine root certificate from trust store
    root_fp = list(ts_manager._roots_by_fp.keys())[0]
    root_rec = ts_manager.get_root_record(root_fp)
    import base64
    root_der = base64.b64decode(root_rec["der_base64"])
    root_cert = x509.load_der_x509_certificate(root_der)

    chain_res = builder.build_chain(root_cert, reference_time=datetime.now(timezone.utc), store_name="MOZILLA")
    assert chain_res["is_complete"] is True
    assert chain_res["has_trusted_anchor"] is True
    assert chain_res["validation_result"] == "VALID_TRUSTED"
    assert chain_res["root_sha256_fingerprint"] == root_fp

