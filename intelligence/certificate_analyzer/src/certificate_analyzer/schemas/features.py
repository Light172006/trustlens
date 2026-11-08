"""Extracted feature vector schema for Certificate Analyzer."""

from typing import Optional
from pydantic import BaseModel, Field


class CertificateFeatures(BaseModel):
    """Deterministic feature vector characterizing cryptographic, temporal, chain, and policy dimensions."""

    # Cryptographic features
    public_key_algorithm: str = Field(default="UNKNOWN")
    key_size_bits: int = Field(default=0)
    is_rsa: bool = Field(default=False)
    is_ecdsa: bool = Field(default=False)
    is_ed25519: bool = Field(default=False)
    is_weak_key: bool = Field(default=False)
    signature_algorithm: str = Field(default="UNKNOWN")
    is_sha1_signature: bool = Field(default=False)
    is_md5_signature: bool = Field(default=False)
    is_secure_signature: bool = Field(default=False)

    # Temporal features
    validity_duration_days: float = Field(default=0.0)
    days_since_issuance: float = Field(default=0.0)
    days_until_expiry: float = Field(default=0.0)
    is_expired: bool = Field(default=False)
    is_not_yet_valid: bool = Field(default=False)
    is_short_lived: bool = Field(default=False)  # <= 90 days

    # Identity and Domain features
    has_san: bool = Field(default=False)
    san_count: int = Field(default=0)
    has_wildcard_san: bool = Field(default=False)
    has_ip_san: bool = Field(default=False)
    matches_tested_hostname: Optional[bool] = Field(default=None)

    # Hierarchy and Chain features
    is_ca: bool = Field(default=False)
    is_self_signed: bool = Field(default=False)
    chain_length: int = Field(default=1)
    is_chain_complete: bool = Field(default=False)
    has_trusted_anchor: bool = Field(default=False)

    # Revocation and Transparency features
    has_crl_distribution_points: bool = Field(default=False)
    has_ocsp_aia: bool = Field(default=False)
    has_scts: bool = Field(default=False)
    sct_count: int = Field(default=0)

    # Policy compliance features
    is_cabf_validity_compliant: bool = Field(default=True)
    cabf_max_allowed_validity_days: Optional[float] = Field(
        default=398.0,
        description="Maximum allowed validity duration in days under CA/B Forum Baseline Requirements v2.3.1",
    )
    policy_applicability: str = Field(
        default="APPLICABLE",
        description="'APPLICABLE' for TLS subscriber certificates; 'NOT_APPLICABLE' for CA or private certificates",
    )
    is_ca_constraint_compliant: bool = Field(default=True)
    is_eku_compliant: bool = Field(default=True)

