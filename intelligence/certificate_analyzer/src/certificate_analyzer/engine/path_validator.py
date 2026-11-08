"""RFC 5280 Certification Path Validation Engine.

Implements rigorous certification-path validation:
- Validates cryptographic signatures along the path.
- Enforces Basic Constraints (is_ca=True and keyCertSign on all issuing intermediates).
- Enforces pathLenConstraint depth limits.
- Evaluates temporal validity of each chain node at the reference timestamp.
- Validates termination at an authentic trust anchor in the configured trust store.
- Distinguishes incomplete chains from invalid chains and untrusted roots.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure dataset package and isolated dependencies are accessible
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
_DATASET_SRC = _INTELLIGENCE_DIR / "certificate_dataset" / "src"
_DATASET_DEPS = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"

if _DATASET_SRC.exists() and str(_DATASET_SRC) not in sys.path:
    sys.path.insert(0, str(_DATASET_SRC))
if _DATASET_DEPS.exists() and str(_DATASET_DEPS) not in sys.path:
    sys.path.insert(0, str(_DATASET_DEPS))

from certificate_dataset.trust_stores.root_store import TrustStoreManager
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


class CertificationPathValidator:
    """Validates X.509 certification paths conforming to RFC 5280."""

    _VALIDATION_CACHE: Dict[Tuple[str, Tuple[str, ...], str, str, str], Dict[str, Any]] = {}
    _MAX_CACHE_ENTRIES: int = 10000

    @classmethod
    def clear_cache(cls) -> None:
        """Clears the path validation cache."""
        cls._VALIDATION_CACHE.clear()

    @classmethod
    def validate_path(
        cls,
        leaf_cert: x509.Certificate,
        presented_intermediates: List[x509.Certificate],
        trust_store: TrustStoreManager,
        reference_time: Optional[datetime] = None,
        store_name: str = "MOZILLA",
    ) -> Dict[str, Any]:
        """Validates certification path from leaf to a trust anchor."""
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        # Context-isolated cache key (fingerprint, presented chain, trust store, version, timestamp)
        leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        leaf_fp = hashlib.sha256(leaf_der).hexdigest().lower()
        presented_fps_tuple = tuple(sorted(
            hashlib.sha256(inter.public_bytes(serialization.Encoding.DER)).hexdigest().lower()
            for inter in presented_intermediates
        ))
        cache_key = (
            leaf_fp,
            presented_fps_tuple,
            store_name,
            trust_store.DEFAULT_STORE_VERSION,
            reference_time.isoformat(),
        )

        if cache_key in cls._VALIDATION_CACHE:
            # Return fresh copy of cached dictionary
            return dict(cls._VALIDATION_CACHE[cache_key])

        # Index available certificates
        pool_by_subject: Dict[str, List[x509.Certificate]] = {}
        pool_by_ski: Dict[str, List[x509.Certificate]] = {}

        def index_cert(cert: x509.Certificate) -> str:
            der = cert.public_bytes(serialization.Encoding.DER)
            fp = hashlib.sha256(der).hexdigest().lower()
            subj = cert.subject.rfc4514_string()
            if subj not in pool_by_subject:
                pool_by_subject[subj] = []
            if cert not in pool_by_subject[subj]:
                pool_by_subject[subj].append(cert)

            try:
                ski_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                ski_hex = ski_ext.value.digest.hex().lower()
                if ski_hex not in pool_by_ski:
                    pool_by_ski[ski_hex] = []
                if cert not in pool_by_ski[ski_hex]:
                    pool_by_ski[ski_hex].append(cert)
            except x509.ExtensionNotFound:
                pass
            return fp

        # Register leaf and presented intermediates
        leaf_fp = index_cert(leaf_cert)
        presented_fps = [leaf_fp]
        for inter in presented_intermediates:
            presented_fps.append(index_cert(inter))

        # Register root store certs in pool (cached objects to avoid redundant ASN.1 decoding)
        for root_cert in trust_store.get_parsed_root_objects():
            index_cert(root_cert)

        # Traverse path from leaf upwards
        current = leaf_cert
        chain: List[x509.Certificate] = [current]
        chain_fps: List[str] = [leaf_fp]
        visited_fps: Set[str] = {leaf_fp}
        validation_errors: List[str] = []

        max_depth = 9
        for depth in range(max_depth):
            is_self_signed = current.subject == current.issuer
            if is_self_signed:
                break

            # Find parent certificate via AKI then Issuer DN
            parent = cls._find_parent(current, pool_by_ski, pool_by_subject)
            if parent is None:
                validation_errors.append("MISSING_INTERMEDIATE_CERTIFICATE")
                break

            parent_der = parent.public_bytes(serialization.Encoding.DER)
            parent_fp = hashlib.sha256(parent_der).hexdigest().lower()

            if parent_fp in visited_fps:
                validation_errors.append("CIRCULAR_CHAIN_DETECTED")
                break

            # 1. Cryptographic signature check
            if not cls._verify_signature(current, parent):
                validation_errors.append(f"INVALID_SIGNATURE_FROM_{parent_fp[:16]}")

            # 2. Basic Constraints: Parent must be CA (RFC 5280 Section 4.2.1.9)
            try:
                bc = parent.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
                if not bc.ca:
                    validation_errors.append(f"PARENT_NOT_CA_{parent_fp[:16]}")
            except x509.ExtensionNotFound:
                # BasicConstraints is mandatory on CA certificates in modern PKI
                validation_errors.append(f"PARENT_MISSING_BASIC_CONSTRAINTS_{parent_fp[:16]}")

            # 3. Key Usage: Parent must assert keyCertSign if KeyUsage present
            try:
                ku = parent.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
                if not ku.key_cert_sign:
                    validation_errors.append(f"PARENT_MISSING_KEY_CERT_SIGN_{parent_fp[:16]}")
            except x509.ExtensionNotFound:
                pass

            # 4. Temporal validity of parent at reference timestamp
            p_not_before = parent.not_valid_before_utc if hasattr(parent, "not_valid_before_utc") else parent.not_valid_before.replace(tzinfo=timezone.utc)
            p_not_after = parent.not_valid_after_utc if hasattr(parent, "not_valid_after_utc") else parent.not_valid_after.replace(tzinfo=timezone.utc)
            if reference_time < p_not_before or reference_time > p_not_after:
                validation_errors.append(f"PARENT_EXPIRED_{parent_fp[:16]}")

            chain.append(parent)
            chain_fps.append(parent_fp)
            visited_fps.add(parent_fp)
            current = parent

        # Check path length constraints on constructed chain (RFC 5280 Section 4.2.1.9)
        for idx in range(1, len(chain)):
            node = chain[idx]
            try:
                bc = node.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
                if bc.path_length is not None:
                    # Number of intermediate CA certificates below this node
                    sub_cas = idx - 1
                    if sub_cas > bc.path_length:
                        validation_errors.append(f"PATH_LENGTH_EXCEEDED_{bc.path_length}")
            except x509.ExtensionNotFound:
                pass

        terminal_cert = chain[-1]
        terminal_der = terminal_cert.public_bytes(serialization.Encoding.DER)
        terminal_fp = hashlib.sha256(terminal_der).hexdigest().lower()

        is_self_signed_terminal = terminal_cert.subject == terminal_cert.issuer
        is_trusted = trust_store.is_trusted_root(terminal_fp, store_name=store_name)

        # Classification of certification path outcome
        if any("PARENT_NOT_CA" in e or "PARENT_MISSING_BASIC_CONSTRAINTS" in e or "PARENT_MISSING_KEY_CERT_SIGN" in e for e in validation_errors):
            val_res = "BASIC_CONSTRAINTS_VIOLATION"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = is_trusted
        elif any("PATH_LENGTH_EXCEEDED" in e for e in validation_errors):
            val_res = "PATH_LENGTH_EXCEEDED"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = is_trusted
        elif any("INVALID_SIGNATURE" in e for e in validation_errors):
            val_res = "INVALID_SIGNATURE"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = is_trusted
        elif any("PARENT_EXPIRED" in e for e in validation_errors):
            val_res = "EXPIRED_CHAIN_NODE"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = is_trusted
        elif not is_self_signed_terminal and "MISSING_INTERMEDIATE_CERTIFICATE" in validation_errors:
            val_res = "INCOMPLETE_CHAIN"
            is_complete = False
            has_trusted_anchor = False
        elif is_self_signed_terminal and not is_trusted:
            val_res = "UNTRUSTED_ROOT"
            is_complete = True
            has_trusted_anchor = False
        elif is_trusted:
            val_res = "VALID_TRUSTED"
            is_complete = True
            has_trusted_anchor = True
        else:
            val_res = "UNTRUSTED_ROOT"
            is_complete = is_self_signed_terminal
            has_trusted_anchor = False

        res_dict = {
            "validation_result": val_res,
            "is_valid": (val_res == "VALID_TRUSTED"),
            "presented_chain_fps": presented_fps,
            "constructed_chain_fps": chain_fps,
            "chain_length": len(chain_fps),
            "is_complete": is_complete,
            "has_trusted_anchor": has_trusted_anchor,
            "trust_anchor_name": terminal_cert.subject.rfc4514_string() if has_trusted_anchor or is_self_signed_terminal else None,
            "trust_store_identifier": store_name,
            "trust_store_version": trust_store.DEFAULT_STORE_VERSION,
            "verification_timestamp": reference_time.isoformat(),
            "validation_errors": validation_errors,
        }
        if len(cls._VALIDATION_CACHE) >= cls._MAX_CACHE_ENTRIES:
            cls._VALIDATION_CACHE.clear()
        cls._VALIDATION_CACHE[cache_key] = res_dict
        return dict(res_dict)

    @staticmethod
    def _find_parent(
        cert: x509.Certificate,
        pool_by_ski: Dict[str, List[x509.Certificate]],
        pool_by_subject: Dict[str, List[x509.Certificate]],
    ) -> Optional[x509.Certificate]:
        # Try AKI match first
        try:
            aki_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier:
                aki_hex = aki_ext.value.key_identifier.hex().lower()
                candidates = pool_by_ski.get(aki_hex, [])
                for cand in candidates:
                    if cand.subject == cert.issuer:
                        return cand
        except x509.ExtensionNotFound:
            pass

        # Fallback to Issuer DN match
        issuer_str = cert.issuer.rfc4514_string()
        candidates = pool_by_subject.get(issuer_str, [])
        if candidates:
            return candidates[0]

        return None

    @staticmethod
    def _verify_signature(child: x509.Certificate, parent: x509.Certificate) -> bool:
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
            return True
        except (InvalidSignature, Exception):
            return False
