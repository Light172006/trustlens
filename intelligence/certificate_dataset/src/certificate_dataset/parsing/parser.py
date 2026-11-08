"""Production-grade X.509 Certificate Parser conforming to RFC 5280 and RFC 6962.

Extracts canonical identity, subject/issuer DNs, SANs, validity, public key,
cryptographic classifications, and extensions with zero private key handling.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple

import sys
from pathlib import Path

# Ensure isolated .deps is available
_DEPS_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


# OID constants
PRECERT_POISON_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
SCT_LIST_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


class CertificateParsingError(Exception):
    """Raised when X.509 certificate parsing fails."""
    pass


class X509CertificateParser:
    """Parses DER/PEM certificates into structured, schema-compliant dictionary records."""

    PARSER_VERSION = "1.0.0"

    @classmethod
    def parse(
        cls,
        cert_bytes: bytes,
        source_name: str = "UNKNOWN_SOURCE",
        source_record_id: str = "",
        observation_timestamp: Optional[str] = None,
        data_origin: str = "REAL_WORLD_PRODUCTION",
        is_precertificate: bool = False,
    ) -> Dict[str, Any]:
        """Parses a raw DER or PEM certificate into a canonical record."""
        # Determine whether input is PEM or DER
        cert = None
        der_bytes: bytes = b""
        pem_str: str = ""

        # Try PEM first
        try:
            if b"-----BEGIN CERTIFICATE-----" in cert_bytes:
                cert = x509.load_pem_x509_certificate(cert_bytes)
                der_bytes = cert.public_bytes(serialization.Encoding.DER)
                pem_str = cert_bytes.decode("utf-8", errors="replace")
            else:
                # Treat as DER
                cert = x509.load_der_x509_certificate(cert_bytes)
                der_bytes = cert_bytes
                pem_str = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        except Exception as e:
            raise CertificateParsingError(f"Failed to parse X.509 certificate: {e}") from e

        # 1. Identity & Fingerprints
        sha256_fp = hashlib.sha256(der_bytes).hexdigest().lower()
        sha1_fp = hashlib.sha1(der_bytes).hexdigest().lower()
        serial_int = cert.serial_number
        serial_hex = format(serial_int, "x")
        version_num = 3 if cert.version == x509.Version.v3 else (2 if cert.version == x509.Version.v2 else 1)

        # 2. Subject Information
        subject = cert.subject
        subject_dn = subject.rfc4514_string()
        cn = cls._get_name_attribute(subject, NameOID.COMMON_NAME)
        org = cls._get_name_attribute(subject, NameOID.ORGANIZATION_NAME)
        ou = cls._get_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
        c = cls._get_name_attribute(subject, NameOID.COUNTRY_NAME)
        st = cls._get_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME)
        loc = cls._get_name_attribute(subject, NameOID.LOCALITY_NAME)

        # 3. Issuer Information
        issuer = cert.issuer
        issuer_dn = issuer.rfc4514_string()
        issuer_cn = cls._get_name_attribute(issuer, NameOID.COMMON_NAME)
        issuer_org = cls._get_name_attribute(issuer, NameOID.ORGANIZATION_NAME)

        # 4. Domain Identity & SAN
        san_dns: List[str] = []
        san_ips: List[str] = []
        san_emails: List[str] = []
        all_sans: List[str] = []
        wildcard_sans: List[str] = []

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_value = san_ext.value
            for name in san_value:
                val = name.value
                if isinstance(name, x509.DNSName):
                    san_dns.append(val)
                    all_sans.append(val)
                    if "*" in val:
                        wildcard_sans.append(val)
                elif isinstance(name, x509.IPAddress):
                    ip_str = str(val)
                    san_ips.append(ip_str)
                    all_sans.append(ip_str)
                elif isinstance(name, x509.RFC822Name):
                    san_emails.append(val)
                    all_sans.append(val)
        except x509.ExtensionNotFound:
            pass

        # 5. Validity
        if hasattr(cert, "not_valid_before_utc"):
            not_before = cert.not_valid_before_utc
        elif hasattr(cert, "not_before_utc"):
            not_before = cert.not_before_utc
        elif hasattr(cert, "not_valid_before"):
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        else:
            not_before = getattr(cert, "not_before").replace(tzinfo=timezone.utc)

        if hasattr(cert, "not_valid_after_utc"):
            not_after = cert.not_valid_after_utc
        elif hasattr(cert, "not_after_utc"):
            not_after = cert.not_after_utc
        elif hasattr(cert, "not_valid_after"):
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        else:
            not_after = getattr(cert, "not_after").replace(tzinfo=timezone.utc)
        
        validity_duration_seconds = int((not_after - not_before).total_seconds())
        validity_duration_days = round(validity_duration_seconds / 86400.0, 4)

        # 6. Public Key & SPKI
        pub_key = cert.public_key()
        spki_der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_sha256 = hashlib.sha256(spki_der).hexdigest().lower()

        key_algo, key_size, rsa_exp, ec_curve, key_sec = cls._analyze_public_key(pub_key)

        # 7. Signature
        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else "unknown"
        sig_hash, sig_sec = cls._analyze_signature(sig_algo)

        # 8. Extensions
        ext_dict = cls._parse_extensions(cert)

        # 9. Certificate Type Classification
        is_ca = ext_dict["basic_constraints"]["is_ca"]
        has_poison = False
        try:
            cert.extensions.get_extension_for_oid(PRECERT_POISON_OID)
            has_poison = True
        except x509.ExtensionNotFound:
            pass

        if is_precertificate or has_poison:
            cert_type = "PRECERTIFICATE"
        elif subject_dn == issuer_dn and is_ca:
            cert_type = "ROOT"
        elif is_ca:
            cert_type = "INTERMEDIATE"
        else:
            cert_type = "LEAF"

        now_utc = datetime.now(timezone.utc).isoformat()

        # Build structured schema-compliant record
        record: Dict[str, Any] = {
            "sha256_fingerprint": sha256_fp,
            "sha1_fingerprint": sha1_fp,
            "serial_number": serial_hex,
            "serial_number_int": str(serial_int),
            "der_base64": base64.b64encode(der_bytes).decode("ascii"),
            "pem": pem_str,
            "version": version_num,
            "certificate_type": cert_type,
            "subject": {
                "common_name": cn,
                "organization": org,
                "organizational_unit": ou,
                "country": c,
                "state_or_province": st,
                "locality": loc,
                "subject_dn": subject_dn,
            },
            "subject_dn": subject_dn,
            "issuer": {
                "common_name": issuer_cn,
                "organization": issuer_org,
                "issuer_dn": issuer_dn,
                "issuer_sha256_fingerprint": None,
                "authority_key_identifier": ext_dict["authority_key_identifier"],
            },
            "issuer_dn": issuer_dn,
            "domain_identity": {
                "subject_alternative_names": all_sans,
                "dns_san_entries": san_dns,
                "ip_san_entries": san_ips,
                "email_san_entries": san_emails,
                "wildcard_san_indicators": wildcard_sans,
                "has_wildcard": len(wildcard_sans) > 0,
                "san_count": len(all_sans),
            },
            "validity": {
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "issuance_timestamp": not_before.isoformat(),
                "validity_duration_seconds": validity_duration_seconds,
                "validity_duration_days": validity_duration_days,
                "observation_timestamp": observation_timestamp or now_utc,
            },
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "validity_duration_seconds": validity_duration_seconds,
            "validity_duration_days": validity_duration_days,
            "public_key": {
                "algorithm": key_algo,
                "key_size_bits": key_size,
                "rsa_exponent": rsa_exp,
                "ec_curve": ec_curve,
                "spki_sha256_fingerprint": spki_sha256,
                "security_classification": key_sec,
            },
            "public_key_algorithm": key_algo,
            "key_size_bits": key_size,
            "spki_sha256_fingerprint": spki_sha256,
            "signature": {
                "algorithm": sig_algo,
                "hash_algorithm": sig_hash,
                "security_classification": sig_sec,
            },
            "signature_algorithm": sig_algo,
            "extensions": ext_dict,
            "transparency": {
                "ct_log_id": None,
                "ct_entry_index": None,
                "sct_timestamp": None,
                "entry_type": "PRECERTIFICATE" if cert_type == "PRECERTIFICATE" else "CERTIFICATE",
            },
            "provenance": {
                "source_name": source_name,
                "source_record_id": source_record_id or sha256_fp,
                "original_retrieval_time": observation_timestamp or now_utc,
                "source_timestamp": not_before.isoformat(),
                "dataset_ingestion_time": now_utc,
                "parsing_version": cls.PARSER_VERSION,
                "record_quality_status": "VALID_PARSED",
                "data_origin": data_origin,
            },
            "source_name": source_name,
            "dataset_ingestion_time": now_utc,
            "parsing_version": cls.PARSER_VERSION,
            "record_quality_status": "VALID_PARSED",
            "data_origin": data_origin,
        }

        return record

    @staticmethod
    def _get_name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            val = attrs[0].value
            return val if isinstance(val, str) else str(val)
        return None

    @staticmethod
    def _analyze_public_key(pub_key: Any) -> Tuple[str, int, Optional[int], Optional[str], str]:
        """Returns (algorithm, key_size, rsa_exponent, ec_curve, security_classification)."""
        if isinstance(pub_key, rsa.RSAPublicKey):
            size = pub_key.key_size
            exp = pub_key.public_numbers().e
            sec = "INSECURE" if size < 2048 else ("ACCEPTABLE" if size == 2048 else "SECURE")
            return "RSA", size, exp, None, sec
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            size = pub_key.key_size
            curve_name = pub_key.curve.name
            sec = "INSECURE" if size < 256 else "SECURE"
            return "ECDSA", size, None, curve_name, sec
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, None, "ed25519", "SECURE"
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            return "Ed448", 448, None, "ed448", "SECURE"
        elif isinstance(pub_key, dsa.DSAPublicKey):
            return "DSA", pub_key.key_size, None, None, "DEPRECATED"
        else:
            return "UNKNOWN", 0, None, None, "DEPRECATED"

    @staticmethod
    def _analyze_signature(sig_algo: str) -> Tuple[Optional[str], str]:
        """Returns (hash_algorithm, security_classification)."""
        upper = sig_algo.upper()
        if "MD5" in upper or "MD2" in upper:
            return "MD5", "INSECURE"
        elif "SHA1" in upper or "SHA-1" in upper:
            return "SHA1", "DEPRECATED"
        elif "SHA256" in upper or "SHA-256" in upper:
            return "SHA256", "SECURE"
        elif "SHA384" in upper or "SHA-384" in upper:
            return "SHA384", "SECURE"
        elif "SHA512" in upper or "SHA-512" in upper:
            return "SHA512", "SECURE"
        elif "ED25519" in upper:
            return "SHA512", "SECURE"
        else:
            return None, "ACCEPTABLE"

    @classmethod
    def _parse_extensions(cls, cert: x509.Certificate) -> Dict[str, Any]:
        """Parses standard X.509 extensions safely."""
        ext_dict: Dict[str, Any] = {
            "basic_constraints": {"is_ca": False, "path_length": None},
            "key_usage": [],
            "extended_key_usage": [],
            "subject_key_identifier": None,
            "authority_key_identifier": None,
            "certificate_policies": [],
            "crl_distribution_points": [],
            "authority_information_access": {"ocsp_urls": [], "ca_issuers_urls": []},
            "tls_features": [],
            "signed_certificate_timestamps": [],
        }

        # Basic Constraints
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            ext_dict["basic_constraints"] = {
                "is_ca": bc.ca,
                "path_length": bc.path_length,
            }
        except x509.ExtensionNotFound:
            pass

        # Key Usage
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            usages = []
            if ku.digital_signature: usages.append("digital_signature")
            if ku.content_commitment: usages.append("content_commitment")
            if ku.key_encipherment: usages.append("key_encipherment")
            if ku.data_encipherment: usages.append("data_encipherment")
            if ku.key_agreement: usages.append("key_agreement")
            if ku.key_cert_sign: usages.append("key_cert_sign")
            if ku.crl_sign: usages.append("crl_sign")
            try:
                if ku.encipher_only: usages.append("encipher_only")
                if ku.decipher_only: usages.append("decipher_only")
            except (ValueError, AttributeError):
                pass
            ext_dict["key_usage"] = usages
        except x509.ExtensionNotFound:
            pass

        # Extended Key Usage
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            ext_dict["extended_key_usage"] = [oid._name for oid in eku]
        except x509.ExtensionNotFound:
            pass

        # Subject Key Identifier
        try:
            ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
            ext_dict["subject_key_identifier"] = ski.digest.hex().lower()
        except x509.ExtensionNotFound:
            pass

        # Authority Key Identifier
        try:
            aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
            if aki.key_identifier:
                ext_dict["authority_key_identifier"] = aki.key_identifier.hex().lower()
        except x509.ExtensionNotFound:
            pass

        # Certificate Policies
        try:
            cp = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
            ext_dict["certificate_policies"] = [pi.policy_identifier.dotted_string for pi in cp]
        except x509.ExtensionNotFound:
            pass

        # CRL Distribution Points
        try:
            crl_dp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            dps = []
            for dp in crl_dp:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            dps.append(name.value)
            ext_dict["crl_distribution_points"] = dps
        except x509.ExtensionNotFound:
            pass

        # Authority Information Access (AIA)
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for desc in aia:
                if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        ext_dict["authority_information_access"]["ocsp_urls"].append(desc.access_location.value)
                elif desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        ext_dict["authority_information_access"]["ca_issuers_urls"].append(desc.access_location.value)
        except x509.ExtensionNotFound:
            pass

        # TLS Feature (Must-Staple)
        try:
            tls_feat = cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE).value
            ext_dict["tls_features"] = [f.name for f in tls_feat]
        except (x509.ExtensionNotFound, AttributeError):
            pass

        # SCTs
        try:
            scts = cert.extensions.get_extension_for_oid(SCT_LIST_OID).value
            for sct in scts:
                ext_dict["signed_certificate_timestamps"].append({
                    "log_id": base64.b64encode(sct.log_id).decode("ascii"),
                    "timestamp": sct.timestamp.isoformat() if hasattr(sct, "timestamp") else "",
                })
        except (x509.ExtensionNotFound, AttributeError):
            pass

        return ext_dict
