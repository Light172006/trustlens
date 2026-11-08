"""Constants and enumerations for the Certificate Analyzer."""

from enum import Enum


class CertificateVerdict(str, Enum):
    """Categorical verdict representing overall digital trust and security posture."""
    TRUSTED = "TRUSTED"
    WARNING = "WARNING"
    DISTRUSTED = "DISTRUSTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingSeverity(str, Enum):
    """Severity classification for individual certificate analysis findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RevocationStatus(str, Enum):
    """Normalized revocation status enum conforming to RFC 6960."""
    GOOD = "GOOD"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"
    NOT_CHECKED = "NOT_CHECKED"
    ERROR = "ERROR"


CURRENT_CERT_SCORING_VERSION = "cert_v1.0.0"

# Trust score deduction weights (deducted from base score 100)
DEDUCTIONS = {
    # Critical defects (direct path to distrusted)
    "REVOKED": 100,
    "EXPIRED": 90,
    "NOT_YET_VALID": 85,
    "HOSTNAME_MISMATCH": 75,
    "UNTRUSTED_ROOT": 70,
    "INVALID_SIGNATURE": 95,
    "INSECURE_SIGNATURE_MD5": 90,
    "INSECURE_PUBLIC_KEY": 60,

    # High severity defects
    "SELF_SIGNED_LEAF": 50,
    "INCOMPLETE_CHAIN": 45,
    "EXPIRED_CHAIN_NODE": 50,
    "BASIC_CONSTRAINTS_VIOLATION": 35,
    "PATH_LENGTH_EXCEEDED": 35,
    "DEPRECATED_SIGNATURE_SHA1": 40,
    "DEPRECATED_PUBLIC_KEY": 35,

    # Medium severity defects
    "MISSING_SAN_EXTENSION": 30,
    "CABF_MAX_VALIDITY_EXCEEDED": 25,
    "CA_CONSTRAINT_VIOLATION": 30,
    "EKU_MISMATCH": 25,

    # Minor/Warning defects
    "EXPIRING_SOON_30_DAYS": 15,
    "EXPIRING_SOON_7_DAYS": 25,
    "OBSOLETE_TLS_VERSION": 30,
}
