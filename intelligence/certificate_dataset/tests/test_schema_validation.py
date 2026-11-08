"""Unit tests for schema validation against JSON schemas."""

import json
from pathlib import Path
import jsonschema


def test_certificate_record_schema_validation(synthetic_fixtures):
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / "certificate_record.schema.json"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Validate each synthetic fixture against the schema
    for fixture in synthetic_fixtures:
        clean_fix = dict(fixture)
        clean_fix.pop("fixture_type", None)
        jsonschema.validate(instance=clean_fix, schema=schema)


def test_endpoint_observation_schema_validation():
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / "endpoint_tls_observation.schema.json"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    sample_obs = {
        "observation_id": "test-obs-1234",
        "hostname": "test.trustlens.io",
        "port": 443,
        "sni_hostname": "test.trustlens.io",
        "observation_timestamp": "2026-11-08T13:45:00Z",
        "leaf_certificate_fingerprint": "a" * 64,
        "presented_intermediate_fingerprints": ["b" * 64],
        "tls_protocol_version": "TLSv1.3",
        "negotiated_cipher_suite": "TLS_AES_256_GCM_SHA384",
        "alpn_protocol": "h2",
        "hostname_verification_result": "MATCH",
        "chain_verification_result": "VALID_TRUSTED",
        "verification_error_codes": [],
        "trust_store_identifier": "MOZILLA",
        "trust_store_version": "2026.06.17",
        "verification_library_and_version": "Python ssl OpenSSL 3.0",
        "handshake_status": "SUCCESS",
        "observation_source": "controlled_endpoint_tls_handshake",
        "collection_method": "TLS_SOCKET_CONNECT_AND_PEERCERT",
    }
    jsonschema.validate(instance=sample_obs, schema=schema)


def test_certificate_chain_schema_validation():
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / "certificate_chain.schema.json"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    sample_chain = {
        "chain_id": "test-chain-1234",
        "leaf_sha256_fingerprint": "a" * 64,
        "intermediate_sha256_fingerprints": ["b" * 64],
        "root_sha256_fingerprint": "c" * 64,
        "chain_length": 3,
        "chain_ordering": ["a" * 64, "b" * 64, "c" * 64],
        "is_complete": True,
        "has_trusted_anchor": True,
        "trust_anchor_name": "CN=Test Root CA",
        "trust_store_identifier": "MOZILLA",
        "trust_store_version": "2026.06.17",
        "aki_ski_matches": [True, True],
        "is_cross_signed": False,
        "validation_result": "VALID_TRUSTED",
        "validation_errors": [],
        "verification_timestamp": "2026-11-08T13:45:00Z",
    }
    jsonschema.validate(instance=sample_chain, schema=schema)


def test_revocation_schema_validation():
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / "revocation_observation.schema.json"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    sample_rev = {
        "observation_id": "rev-obs-1234",
        "certificate_sha256_fingerprint": "a" * 64,
        "serial_number": "deadbeef1234",
        "issuer_sha256_fingerprint": None,
        "issuer_dn": "CN=Test CA",
        "revocation_method": "OCSP",
        "normalized_status": "REVOKED",
        "revocation_reason": "keyCompromise",
        "revocation_timestamp": "2026-11-08T12:00:00Z",
        "this_update": "2026-11-08T12:00:00Z",
        "next_update": "2026-11-09T12:00:00Z",
        "responder_identity": "CN=OCSP Responder",
        "response_verification_result": "VERIFIED",
        "evidence_source_url": "http://ocsp.test.com",
        "retrieval_timestamp": "2026-11-08T13:45:00Z",
        "raw_evidence_base64": None,
        "error_details": None,
    }
    jsonschema.validate(instance=sample_rev, schema=schema)


def test_labels_schema_validation(synthetic_fixtures):
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / "certificate_labels.schema.json"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    from certificate_dataset.labeling.labeler import CertificateLabeler
    labeler = CertificateLabeler()
    fixture = synthetic_fixtures[0]
    eval_res = labeler.evaluate(fixture)

    jsonschema.validate(instance=eval_res, schema=schema)

