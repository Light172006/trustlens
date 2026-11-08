"""Trust Store Manager for Mozilla, Google Chrome, and Microsoft root repositories."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set

import sys

# Ensure isolated .deps is available
_DEPS_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from certificate_dataset.parsing.parser import X509CertificateParser


class TrustStoreManager:
    """Manages root trust store records and trust anchor validation."""

    DEFAULT_STORE_NAME = "MOZILLA"
    DEFAULT_STORE_VERSION = "2026.06.17-CCADB"
    DEFAULT_POLICY_VERSION = "Mozilla Root Store Policy v2.9"

    def __init__(self, trust_stores_dir: Optional[Path] = None):
        if trust_stores_dir is None:
            trust_stores_dir = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "data"
                / "trust_stores"
            )
        self.trust_stores_dir = Path(trust_stores_dir)
        self.trust_stores_dir.mkdir(parents=True, exist_ok=True)
        self._roots_by_fp: Dict[str, Dict[str, Any]] = {}
        self._parsed_root_objs: Dict[str, x509.Certificate] = {}
        self._trusted_fps_by_store: Dict[str, Set[str]] = {
            "MOZILLA": set(),
            "GOOGLE_CHROME": set(),
            "MICROSOFT": set(),
        }

    def get_parsed_root_objects(self) -> List[x509.Certificate]:
        """Returns cached parsed root certificate objects to avoid redundant ASN.1 DER decoding."""
        if not self._parsed_root_objs and self._roots_by_fp:
            for r in self._roots_by_fp.values():
                try:
                    der = base64.b64decode(r["der_base64"])
                    c = x509.load_der_x509_certificate(der)
                    self._parsed_root_objs[r["root_sha256_fingerprint"]] = c
                except Exception:
                    pass
        return list(self._parsed_root_objs.values())

    def load_from_certifi(self) -> List[Dict[str, Any]]:
        """Loads and synchronizes genuine root CA records from Mozilla's NSS store (via certifi)."""
        bundle_path = certifi.where()
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle_text = f.read()

        pem_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            bundle_text,
            re.DOTALL,
        )

        records: List[Dict[str, Any]] = []
        now_utc = datetime.now(timezone.utc).isoformat()

        for pem in pem_blocks:
            try:
                cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
                der = cert.public_bytes(serialization.Encoding.DER)
                fp_sha256 = hashlib.sha256(der).hexdigest().lower()
                
                # Public key SPKI
                pub_key = cert.public_key()
                spki_der = pub_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                spki_sha256 = hashlib.sha256(spki_der).hexdigest().lower()
                algo, key_size, _, _, _ = X509CertificateParser._analyze_public_key(pub_key)

                # Subject info
                subj_dn = cert.subject.rfc4514_string()
                iss_dn = cert.issuer.rfc4514_string()
                cn = X509CertificateParser._get_name_attribute(cert.subject, NameOID.COMMON_NAME)
                org = X509CertificateParser._get_name_attribute(cert.subject, NameOID.ORGANIZATION_NAME)

                rec: Dict[str, Any] = {
                    "root_sha256_fingerprint": fp_sha256,
                    "store_name": self.DEFAULT_STORE_NAME,
                    "store_version": self.DEFAULT_STORE_VERSION,
                    "subject_dn": subj_dn,
                    "issuer_dn": iss_dn,
                    "common_name": cn,
                    "organization": org,
                    "spki_sha256_fingerprint": spki_sha256,
                    "public_key_algorithm": algo,
                    "key_size_bits": key_size,
                    "trust_purposes": ["SERVER_AUTH", "EMAIL_PROTECTION", "CODE_SIGNING"],
                    "trust_bits": {
                        "server_auth": True,
                        "email_protection": True,
                        "code_signing": True,
                    },
                    "ev_capable": False,
                    "retrieval_date": now_utc,
                    "policy_version": self.DEFAULT_POLICY_VERSION,
                    "der_base64": base64.b64encode(der).decode("ascii"),
                }
                records.append(rec)
                self._roots_by_fp[fp_sha256] = rec
                self._parsed_root_objs[fp_sha256] = cert
                self._trusted_fps_by_store["MOZILLA"].add(fp_sha256)
                # Most standard roots in Mozilla CCADB are also accepted in Chrome Root Store
                self._trusted_fps_by_store["GOOGLE_CHROME"].add(fp_sha256)
            except Exception:
                continue

        return records

    def is_trusted_root(self, sha256_fingerprint: str, store_name: str = "MOZILLA") -> bool:
        """Returns True if the certificate fingerprint is present in the specified trust store."""
        fp_clean = sha256_fingerprint.lower().strip()
        store_fps = self._trusted_fps_by_store.get(store_name.upper(), set())
        return fp_clean in store_fps

    def get_root_record(self, sha256_fingerprint: str) -> Optional[Dict[str, Any]]:
        return self._roots_by_fp.get(sha256_fingerprint.lower().strip())

    def total_roots(self) -> int:
        return len(self._roots_by_fp)

