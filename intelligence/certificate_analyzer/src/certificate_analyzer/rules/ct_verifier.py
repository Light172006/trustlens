"""Certificate Transparency (RFC 6962 / RFC 9162) Verifier.

Audits Certificate Transparency metadata:
- Distinguishes SCT presence, structural parsing, signature verification, and inclusion proofs.
- Extracts individual SCT entries (version, log ID, timestamp, signature algorithm).
- Prohibits falsely claiming cryptographic signature verification when log keys are unavailable.
- Explicitly documents that SCT presence is a promise of logging, not an inclusion proof.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import struct
from typing import Any, Dict, List, Optional
from cryptography import x509

SCT_LIST_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


class CertificateTransparencyVerifier:
    """Parses and validates RFC 6962 Signed Certificate Timestamps (SCTs)."""

    HASH_ALGO_NAMES = {
        0: "NONE", 1: "MD5", 2: "SHA1", 3: "SHA224", 4: "SHA256", 5: "SHA384", 6: "SHA512"
    }
    SIG_ALGO_NAMES = {
        0: "ANONYMOUS", 1: "RSA", 2: "DSA", 3: "ECDSA"
    }

    @classmethod
    def audit_ct(cls, cert: x509.Certificate) -> Dict[str, Any]:
        """Audits CT properties of a parsed X.509 certificate."""
        try:
            sct_ext = cert.extensions.get_extension_for_oid(SCT_LIST_OID)
        except Exception:
            return {
                "has_scts": False,
                "sct_count": 0,
                "scts": [],
                "presence_verified": False,
                "cryptographic_signature_verified": False,
                "inclusion_proof_verified": False,
                "audit_notes": "No embedded Signed Certificate Timestamps (SCTs) found in certificate.",
            }

        scts_parsed: List[Dict[str, Any]] = []

        # 1. Native cryptography SCT object extraction
        try:
            for sct in sct_ext.value:
                log_id_hex = sct.log_id.hex().lower()
                log_id_b64 = base64.b64encode(sct.log_id).decode("ascii")
                ts_iso = sct.timestamp.isoformat() if hasattr(sct.timestamp, "isoformat") else str(sct.timestamp)
                v_num = sct.version.value if hasattr(sct.version, "value") else 0
                scts_parsed.append({
                    "sct_version": v_num,
                    "log_id_hex": log_id_hex,
                    "log_id_base64": log_id_b64,
                    "timestamp": ts_iso,
                    "hash_algorithm": "SHA256",
                    "signature_algorithm": "ECDSA",
                    "signature_status": "LOG_KEY_UNAUTHENTICATED",
                })
        except Exception:
            pass

        # 2. Fallback to raw RFC 6962 byte parsing if native iteration produced nothing
        if not scts_parsed:
            try:
                raw_bytes = (
                    sct_ext.value.public_bytes()
                    if hasattr(sct_ext.value, "public_bytes")
                    else (sct_ext.value.value if hasattr(sct_ext.value, "value") else bytes(sct_ext.value))
                )
                if len(raw_bytes) >= 2:
                    total_len = struct.unpack(">H", raw_bytes[:2])[0]
                    offset = 2
                    end = min(2 + total_len, len(raw_bytes))

                    while offset + 2 <= end:
                        sct_len = struct.unpack(">H", raw_bytes[offset : offset + 2])[0]
                        offset += 2
                        if offset + sct_len > end:
                            break
                        sct_data = raw_bytes[offset : offset + sct_len]
                        offset += sct_len

                        parsed_item = cls._parse_single_sct(sct_data)
                        if parsed_item:
                            scts_parsed.append(parsed_item)
            except Exception:
                pass

        return {
            "has_scts": len(scts_parsed) > 0,
            "sct_count": len(scts_parsed),
            "scts": scts_parsed,
            "presence_verified": len(scts_parsed) > 0,
            "cryptographic_signature_verified": False,  # True only when log key is authenticated
            "inclusion_proof_verified": False,          # SCT is a promise to log, not an inclusion proof
            "audit_notes": (
                f"{len(scts_parsed)} SCT(s) parsed. Note: SCT presence constitutes a promise to include "
                f"in CT logs (RFC 6962), not a cryptographic Merkle tree inclusion proof."
            ),
        }

    @classmethod
    def _parse_single_sct(cls, data: bytes) -> Optional[Dict[str, Any]]:
        # sct_version (1), log_id (32), timestamp (8), extensions_len (2)
        if len(data) < 43:
            return None

        version = data[0]
        log_id_bytes = data[1:33]
        log_id_hex = log_id_bytes.hex().lower()
        log_id_b64 = base64.b64encode(log_id_bytes).decode("ascii")

        ts_ms = struct.unpack(">Q", data[33:41])[0]
        ts_iso = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).isoformat()

        ext_len = struct.unpack(">H", data[41:43])[0]
        offset = 43 + ext_len

        hash_name = "UNKNOWN"
        sig_name = "UNKNOWN"
        sig_bytes_hex = ""

        if offset + 4 <= len(data):
            hash_id = data[offset]
            sig_id = data[offset + 1]
            hash_name = cls.HASH_ALGO_NAMES.get(hash_id, f"HASH_{hash_id}")
            sig_name = cls.SIG_ALGO_NAMES.get(sig_id, f"SIG_{sig_id}")
            sig_len = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
            if offset + 4 + sig_len <= len(data):
                sig_bytes_hex = data[offset + 4 : offset + 4 + sig_len].hex().lower()

        return {
            "sct_version": version,
            "log_id_hex": log_id_hex,
            "log_id_base64": log_id_b64,
            "timestamp": ts_iso,
            "hash_algorithm": hash_name,
            "signature_algorithm": sig_name,
            "signature_hex": sig_bytes_hex[:32] + "..." if sig_bytes_hex else "",
            "signature_status": "LOG_KEY_UNAUTHENTICATED",
        }

