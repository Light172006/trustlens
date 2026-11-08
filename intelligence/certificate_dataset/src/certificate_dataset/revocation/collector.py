"""Revocation evidence collector for CRL and OCSP observations."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

import sys

# Ensure isolated .deps is available
_DEPS_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

from cryptography import x509
from cryptography.x509 import ocsp


class RevocationCollector:
    """Ingests and normalizes CRL and OCSP revocation observations."""

    @staticmethod
    def parse_crl_bytes(
        crl_der_bytes: bytes,
        source_url: Optional[str] = None,
        retrieval_timestamp: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Parses a DER-encoded Certificate Revocation List into individual revocation records."""
        now_utc = retrieval_timestamp or datetime.now(timezone.utc).isoformat()
        try:
            crl = x509.load_der_x509_crl(crl_der_bytes)
        except Exception:
            try:
                crl = x509.load_pem_x509_crl(crl_der_bytes)
            except Exception as e:
                return [{
                    "observation_id": str(uuid.uuid4()),
                    "certificate_sha256_fingerprint": "0" * 64,
                    "serial_number": "0",
                    "issuer_sha256_fingerprint": None,
                    "issuer_dn": "UNKNOWN",
                    "revocation_method": "CRL",
                    "normalized_status": "ERROR",
                    "revocation_reason": None,
                    "revocation_timestamp": None,
                    "this_update": None,
                    "next_update": None,
                    "responder_identity": None,
                    "response_verification_result": "PARSE_ERROR",
                    "evidence_source_url": source_url,
                    "retrieval_timestamp": now_utc,
                    "raw_evidence_base64": None,
                    "error_details": f"Failed to parse CRL: {e}",
                }]

        issuer_dn = crl.issuer.rfc4514_string()
        this_up = crl.this_update_utc if hasattr(crl, "this_update_utc") else crl.this_update.replace(tzinfo=timezone.utc)
        next_up = None
        if crl.next_update is not None:
            next_up = crl.next_update_utc if hasattr(crl, "next_update_utc") else crl.next_update.replace(tzinfo=timezone.utc)

        observations: List[Dict[str, Any]] = []
        for revoked in crl:
            serial_hex = format(revoked.serial_number, "x")
            rev_time = revoked.revocation_date_utc if hasattr(revoked, "revocation_date_utc") else revoked.revocation_date.replace(tzinfo=timezone.utc)

            reason_str = None
            try:
                reason_ext = revoked.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_REASON)
                reason_str = reason_ext.value.reason.name
            except x509.ExtensionNotFound:
                reason_str = "unspecified"

            # Create an observation entry
            obs: Dict[str, Any] = {
                "observation_id": str(uuid.uuid4()),
                "certificate_sha256_fingerprint": "0" * 64,  # To be correlated with cert serial
                "serial_number": serial_hex,
                "issuer_sha256_fingerprint": None,
                "issuer_dn": issuer_dn,
                "revocation_method": "CRL",
                "normalized_status": "REVOKED",
                "revocation_reason": reason_str,
                "revocation_timestamp": rev_time.isoformat(),
                "this_update": this_up.isoformat(),
                "next_update": next_up.isoformat() if next_up else None,
                "responder_identity": issuer_dn,
                "response_verification_result": "VERIFIED",
                "evidence_source_url": source_url,
                "retrieval_timestamp": now_utc,
                "raw_evidence_base64": None,
                "error_details": None,
            }
            observations.append(obs)

        return observations

    @staticmethod
    def parse_ocsp_response_bytes(
        ocsp_der_bytes: bytes,
        certificate_fp: str,
        expected_serial: str,
        issuer_dn: str,
        source_url: Optional[str] = None,
        retrieval_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Parses a DER OCSP response into an observation record."""
        now_utc = retrieval_timestamp or datetime.now(timezone.utc).isoformat()
        try:
            resp = ocsp.load_der_ocsp_response(ocsp_der_bytes)
        except Exception as e:
            return {
                "observation_id": str(uuid.uuid4()),
                "certificate_sha256_fingerprint": certificate_fp,
                "serial_number": expected_serial,
                "issuer_sha256_fingerprint": None,
                "issuer_dn": issuer_dn,
                "revocation_method": "OCSP",
                "normalized_status": "ERROR",
                "revocation_reason": None,
                "revocation_timestamp": None,
                "this_update": None,
                "next_update": None,
                "responder_identity": None,
                "response_verification_result": "PARSE_ERROR",
                "evidence_source_url": source_url,
                "retrieval_timestamp": now_utc,
                "raw_evidence_base64": base64.b64encode(ocsp_der_bytes).decode("ascii") if ocsp_der_bytes else None,
                "error_details": f"Failed to parse OCSP response: {e}",
            }

        if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return {
                "observation_id": str(uuid.uuid4()),
                "certificate_sha256_fingerprint": certificate_fp,
                "serial_number": expected_serial,
                "issuer_sha256_fingerprint": None,
                "issuer_dn": issuer_dn,
                "revocation_method": "OCSP",
                "normalized_status": "UNKNOWN",
                "revocation_reason": None,
                "revocation_timestamp": None,
                "this_update": None,
                "next_update": None,
                "responder_identity": None,
                "response_verification_result": "NOT_VERIFIED",
                "evidence_source_url": source_url,
                "retrieval_timestamp": now_utc,
                "raw_evidence_base64": base64.b64encode(ocsp_der_bytes).decode("ascii"),
                "error_details": f"OCSP response status unsuccessful: {resp.response_status.name}",
            }

        cert_status = resp.certificate_status
        this_up = resp.this_update_utc if hasattr(resp, "this_update_utc") else resp.this_update.replace(tzinfo=timezone.utc)
        next_up = None
        if resp.next_update is not None:
            next_up = resp.next_update_utc if hasattr(resp, "next_update_utc") else resp.next_update.replace(tzinfo=timezone.utc)

        responder = None
        if resp.responder_name:
            responder = resp.responder_name.rfc4514_string()
        elif resp.responder_key_hash:
            responder = resp.responder_key_hash.hex().lower()

        if cert_status == ocsp.OCSPCertStatus.GOOD:
            norm_status = "GOOD"
            rev_time = None
            rev_reason = None
        elif cert_status == ocsp.OCSPCertStatus.REVOKED:
            norm_status = "REVOKED"
            rev_time = resp.revocation_time_utc if hasattr(resp, "revocation_time_utc") else resp.revocation_time.replace(tzinfo=timezone.utc)
            rev_time = rev_time.isoformat()
            rev_reason = resp.revocation_reason.name if resp.revocation_reason else "unspecified"
        else:
            norm_status = "UNKNOWN"
            rev_time = None
            rev_reason = None

        return {
            "observation_id": str(uuid.uuid4()),
            "certificate_sha256_fingerprint": certificate_fp,
            "serial_number": expected_serial,
            "issuer_sha256_fingerprint": None,
            "issuer_dn": issuer_dn,
            "revocation_method": "OCSP",
            "normalized_status": norm_status,
            "revocation_reason": rev_reason,
            "revocation_timestamp": rev_time,
            "this_update": this_up.isoformat() if this_up else None,
            "next_update": next_up.isoformat() if next_up else None,
            "responder_identity": responder,
            "response_verification_result": "VERIFIED",
            "evidence_source_url": source_url,
            "retrieval_timestamp": now_utc,
            "raw_evidence_base64": base64.b64encode(ocsp_der_bytes).decode("ascii"),
            "error_details": None,
        }

    @classmethod
    def create_not_checked_observation(
        cls,
        certificate_fp: str,
        serial_number: str,
        issuer_dn: str,
        reason: str = "AIA_OCSP_AND_CRLDP_OMITTED",
    ) -> Dict[str, Any]:
        """Creates a standardized NOT_CHECKED revocation observation when status could not be queried."""
        now_utc = datetime.now(timezone.utc).isoformat()
        return {
            "observation_id": str(uuid.uuid4()),
            "certificate_sha256_fingerprint": certificate_fp,
            "serial_number": serial_number,
            "issuer_sha256_fingerprint": None,
            "issuer_dn": issuer_dn,
            "revocation_method": "OCSP",
            "normalized_status": "NOT_CHECKED",
            "revocation_reason": None,
            "revocation_timestamp": None,
            "this_update": None,
            "next_update": None,
            "responder_identity": None,
            "response_verification_result": "NOT_VERIFIED",
            "evidence_source_url": None,
            "retrieval_timestamp": now_utc,
            "raw_evidence_base64": None,
            "error_details": reason,
        }

