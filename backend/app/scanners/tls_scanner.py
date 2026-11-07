"""TLS handshake and X.509 certificate inspection scanner."""

import hashlib
import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from pydantic import BaseModel, Field

from app.core.logging import logger


class TlsCertificateDetails(BaseModel):
    """X.509 leaf certificate details."""

    leaf_fingerprint_sha256: str
    serial_number: str
    subject_cn: str | None = None
    san_dns: list[str] = Field(default_factory=list)
    issuer: str
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    is_expired: bool
    expires_soon: bool
    signature_algorithm: str
    public_key_algorithm: str
    public_key_bits: int | None = None
    sct_present: bool = False
    revocation_status: str = "not_checked"
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    unavailable_reason: str | None = None


class TlsScanResult(BaseModel):
    """Normalized TLS inspection result."""

    host: str
    port: int = 443
    valid: bool = False
    chain_valid: bool = False
    hostname_match: bool = False
    protocol_version: str | None = None
    cipher_suite: str | None = None
    certificate: TlsCertificateDetails | None = None
    error_message: str | None = None
    completed: bool = False


class TlsScanner:
    """Inspects target website TLS configuration and certificates."""

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout

    def scan(self, host: str, port: int = 443, pinned_ip: str | None = None) -> TlsScanResult:
        """Connect via TLS, validate certificate chain and hostname, and parse leaf cert."""
        result = TlsScanResult(host=host, port=port)
        connect_target = pinned_ip if pinned_ip else host

        # Create standard SSL context verifying against system trust store
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((connect_target, port), timeout=self.timeout) as sock:
                with ssl_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result.protocol_version = ssock.version()
                    cipher_info = ssock.cipher()
                    result.cipher_suite = cipher_info[0] if cipher_info else None
                    result.chain_valid = True
                    result.hostname_match = True
                    result.valid = True

                    # Retrieve binary DER certificate for robust cryptography parsing
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        result.certificate = self._parse_der_certificate(der_cert, host)
                    result.completed = True
                    return result

        except ssl.SSLCertVerificationError as exc:
            logger.debug(f"TLS certificate validation failed for {host}: {exc}")
            result.chain_valid = False
            result.valid = False
            result.error_message = str(exc)

            # Check if failure was hostname mismatch
            if "hostname" in str(exc).lower() or "doesn't match" in str(exc).lower():
                result.hostname_match = False
            else:
                result.hostname_match = True

            # Attempt unverified connection to extract leaf certificate metadata for evidence
            result.certificate = self._fetch_unverified_cert(connect_target, port, host)
            result.completed = True
            return result

        except Exception as exc:
            logger.debug(f"TLS handshake failed for {host}:{port}: {exc}")
            result.valid = False
            result.error_message = f"TLS handshake error: {type(exc).__name__}"
            result.completed = False
            return result

    def _fetch_unverified_cert(
        self, target: str, port: int, hostname: str
    ) -> TlsCertificateDetails | None:
        """Fetch certificate without trust verification to record evidence for failed checks."""
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        return self._parse_der_certificate(der_cert, hostname)
        except Exception:
            pass
        return None

    def _parse_der_certificate(self, der_bytes: bytes, hostname: str) -> TlsCertificateDetails:
        """Parse raw DER X.509 certificate using cryptography library."""
        cert = x509.load_der_x509_certificate(der_bytes)
        now = datetime.now(UTC)

        # Fingerprint
        sha256_fp = hashlib.sha256(der_bytes).hexdigest()

        # Subject CN
        subject_cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = subject_cns[0].value if subject_cns else None

        # Issuer
        issuer_str = cert.issuer.rfc4514_string()

        # SANs
        san_dns: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_dns = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Expiration
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_until_expiry = (not_after - now).days
        is_expired = now > not_after
        expires_soon = 0 <= days_until_expiry <= 30

        # Public Key details
        pub_key = cert.public_key()
        pub_key_alg = type(pub_key).__name__.replace("_", "").replace("PublicKey", "")
        pub_key_bits = getattr(pub_key, "key_size", None)

        # SCT detection
        sct_present = False
        try:
            cert.extensions.get_extension_for_oid(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
            )
            sct_present = True
        except x509.ExtensionNotFound:
            pass

        return TlsCertificateDetails(
            leaf_fingerprint_sha256=sha256_fp,
            serial_number=hex(cert.serial_number)[2:].upper(),
            subject_cn=subject_cn,
            san_dns=san_dns,
            issuer=issuer_str,
            not_before=not_before,
            not_after=not_after,
            days_until_expiry=days_until_expiry,
            is_expired=is_expired,
            expires_soon=expires_soon,
            signature_algorithm=cert.signature_algorithm_oid._name,
            public_key_algorithm=pub_key_alg,
            public_key_bits=pub_key_bits,
            sct_present=sct_present,
            revocation_status="not_checked",
        )


tls_scanner = TlsScanner()
