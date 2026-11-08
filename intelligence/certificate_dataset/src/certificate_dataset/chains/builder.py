"""Certificate chain builder, path validation, and trust anchor resolution."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set

import sys
from pathlib import Path

# Ensure isolated .deps is available
_DEPS_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, ed25519, rsa

from certificate_dataset.trust_stores.root_store import TrustStoreManager


class ChainBuilder:
    """Builds and validates X.509 certificate paths."""

    def __init__(self, trust_store_manager: TrustStoreManager):
        self.trust_store = trust_store_manager
        self._cert_pool_by_fp: Dict[str, x509.Certificate] = {}
        self._cert_pool_by_ski: Dict[str, List[x509.Certificate]] = {}
        self._cert_pool_by_subject: Dict[str, List[x509.Certificate]] = {}

    def register_certificate(self, cert: x509.Certificate) -> str:
        """Indexes a certificate in the chain building pool."""
        der = cert.public_bytes(serialization.Encoding.DER)
        fp = hashlib.sha256(der).hexdigest().lower()
        self._cert_pool_by_fp[fp] = cert

        # Index by Subject DN
        subj = cert.subject.rfc4514_string()
        if subj not in self._cert_pool_by_subject:
            self._cert_pool_by_subject[subj] = []
        self._cert_pool_by_subject[subj].append(cert)

        # Index by SKI
        try:
            ski_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski_hex = ski_ext.value.digest.hex().lower()
            if ski_hex not in self._cert_pool_by_ski:
                self._cert_pool_by_ski[ski_hex] = []
            self._cert_pool_by_ski[ski_hex].append(cert)
        except x509.ExtensionNotFound:
            pass

        return fp

    def register_der_bytes(self, der_bytes: bytes) -> str:
        cert = x509.load_der_x509_certificate(der_bytes)
        return self.register_certificate(cert)

    def build_chain(
        self,
        leaf_cert: x509.Certificate,
        reference_time: Optional[datetime] = None,
        store_name: str = "MOZILLA",
    ) -> Dict[str, Any]:
        """Builds certificate path from leaf upwards towards a trust anchor."""
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        leaf_fp = hashlib.sha256(leaf_der).hexdigest().lower()
        self.register_certificate(leaf_cert)

        current = leaf_cert
        chain: List[x509.Certificate] = [current]
        chain_fps: List[str] = [leaf_fp]
        visited_fps: Set[str] = {leaf_fp}

        validation_errors: List[str] = []
        aki_ski_matches: List[bool] = []
        is_cross_signed = False

        max_depth = 8
        for _ in range(max_depth):
            # Check if current is root (self-signed)
            is_self_signed = current.subject == current.issuer
            if is_self_signed:
                break

            # Find parent certificate
            parent = self._find_parent(current)
            if parent is None:
                validation_errors.append("MISSING_INTERMEDIATE_CERTIFICATE")
                break

            parent_der = parent.public_bytes(serialization.Encoding.DER)
            parent_fp = hashlib.sha256(parent_der).hexdigest().lower()

            # Check loop
            if parent_fp in visited_fps:
                validation_errors.append("CIRCULAR_CHAIN_DETECTED")
                break

            # Check AKI/SKI match
            matched_aki = self._check_aki_ski_match(current, parent)
            aki_ski_matches.append(matched_aki)

            # Check signature
            if not self._verify_signature(current, parent):
                validation_errors.append(f"INVALID_SIGNATURE_FROM_{parent_fp[:16]}")

            # Check temporal validity of parent at reference time
            if hasattr(parent, "not_valid_before_utc"):
                p_not_before = parent.not_valid_before_utc
            elif hasattr(parent, "not_before_utc"):
                p_not_before = parent.not_before_utc
            elif hasattr(parent, "not_valid_before"):
                p_not_before = parent.not_valid_before.replace(tzinfo=timezone.utc)
            else:
                p_not_before = getattr(parent, "not_before").replace(tzinfo=timezone.utc)

            if hasattr(parent, "not_valid_after_utc"):
                p_not_after = parent.not_valid_after_utc
            elif hasattr(parent, "not_after_utc"):
                p_not_after = parent.not_after_utc
            elif hasattr(parent, "not_valid_after"):
                p_not_after = parent.not_valid_after.replace(tzinfo=timezone.utc)
            else:
                p_not_after = getattr(parent, "not_after").replace(tzinfo=timezone.utc)
            if reference_time < p_not_before or reference_time > p_not_after:
                validation_errors.append(f"PARENT_EXPIRED_{parent_fp[:16]}")

            chain.append(parent)
            chain_fps.append(parent_fp)
            visited_fps.add(parent_fp)
            current = parent

        # Determine terminal node
        terminal_cert = chain[-1]
        terminal_der = terminal_cert.public_bytes(serialization.Encoding.DER)
        terminal_fp = hashlib.sha256(terminal_der).hexdigest().lower()

        is_self_signed_terminal = terminal_cert.subject == terminal_cert.issuer
        is_trusted = self.trust_store.is_trusted_root(terminal_fp, store_name=store_name)

        # Classification of result
        if not is_self_signed_terminal and "MISSING_INTERMEDIATE_CERTIFICATE" in validation_errors:
            validation_result = "INCOMPLETE_CHAIN"
            is_complete = False
            has_trusted_anchor = False
            root_fp = None
            anchor_name = None
        elif is_self_signed_terminal and not is_trusted:
            validation_result = "UNTRUSTED_ROOT"
            is_complete = True
            has_trusted_anchor = False
            root_fp = terminal_fp
            anchor_name = terminal_cert.subject.rfc4514_string()
        elif any("PARENT_EXPIRED" in e for e in validation_errors):
            validation_result = "EXPIRED_CHAIN_NODE"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = is_trusted
            root_fp = terminal_fp if is_self_signed_terminal else None
            anchor_name = terminal_cert.subject.rfc4514_string() if is_self_signed_terminal else None
        elif any("INVALID_SIGNATURE" in e for e in validation_errors):
            validation_result = "INVALID_SIGNATURE"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = is_trusted
            root_fp = terminal_fp if is_self_signed_terminal else None
            anchor_name = terminal_cert.subject.rfc4514_string() if is_self_signed_terminal else None
        elif is_trusted:
            validation_result = "VALID_TRUSTED"
            is_complete = True
            has_trusted_anchor = True
            root_fp = terminal_fp
            anchor_name = terminal_cert.subject.rfc4514_string()
        else:
            validation_result = "UNTRUSTED_ROOT"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = False
            root_fp = terminal_fp if is_self_signed_terminal else None
            anchor_name = None

        intermediate_fps = chain_fps[1:-1] if len(chain_fps) > 2 else ([] if len(chain_fps) <= 1 else [chain_fps[1]])
        if is_self_signed_terminal and len(chain_fps) > 1:
            intermediate_fps = chain_fps[1:-1]

        chain_id = hashlib.sha256(":".join(chain_fps).encode("ascii")).hexdigest().lower()

        return {
            "chain_id": chain_id,
            "leaf_sha256_fingerprint": leaf_fp,
            "intermediate_sha256_fingerprints": intermediate_fps,
            "root_sha256_fingerprint": root_fp,
            "chain_length": len(chain_fps),
            "chain_ordering": chain_fps,
            "is_complete": is_complete,
            "has_trusted_anchor": has_trusted_anchor,
            "trust_anchor_name": anchor_name,
            "trust_store_identifier": store_name,
            "trust_store_version": self.trust_store.DEFAULT_STORE_VERSION,
            "aki_ski_matches": aki_ski_matches,
            "is_cross_signed": is_cross_signed,
            "validation_result": validation_result,
            "validation_errors": validation_errors,
            "verification_timestamp": reference_time.isoformat(),
        }

    def _find_parent(self, cert: x509.Certificate) -> Optional[x509.Certificate]:
        # Try AKI match first
        try:
            aki_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier:
                aki_hex = aki_ext.value.key_identifier.hex().lower()
                candidates = self._cert_pool_by_ski.get(aki_hex, [])
                for cand in candidates:
                    if cand.subject == cert.issuer:
                        return cand
        except x509.ExtensionNotFound:
            pass

        # Fallback to Issuer DN match
        issuer_str = cert.issuer.rfc4514_string()
        candidates = self._cert_pool_by_subject.get(issuer_str, [])
        if candidates:
            return candidates[0]

        return None

    @staticmethod
    def _check_aki_ski_match(child: x509.Certificate, parent: x509.Certificate) -> bool:
        try:
            aki_ext = child.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            ski_ext = parent.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier and ski_ext.value.digest:
                return aki_ext.value.key_identifier == ski_ext.value.digest
        except x509.ExtensionNotFound:
            pass
        return False

    @staticmethod
    def _verify_signature(child: x509.Certificate, parent: x509.Certificate) -> bool:
        """Verifies child certificate's signature using parent's public key."""
        parent_pub = parent.public_key()
        try:
            if isinstance(parent_pub, rsa.RSAPublicKey):
                parent_pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
            elif isinstance(parent_pub, ec.EllipticCurvePublicKey):
                parent_pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
            elif isinstance(parent_pub, ed25519.Ed25519PublicKey):
                parent_pub.verify(child.signature, child.tbs_certificate_bytes)
            else:
                return True  # Fallback for algorithms not directly verifying via standard padding
            return True
        except (InvalidSignature, Exception):
            return False
