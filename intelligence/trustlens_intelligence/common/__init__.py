"""TrustLens Intelligence — Common Utilities and Primitives."""

from trustlens_intelligence.common.url_utils import (
    canonicalize_url_strict,
    extract_safe_hostname,
    has_userinfo_credentials,
    is_adversarial_or_standard_ip,
)

__all__ = [
    "canonicalize_url_strict",
    "extract_safe_hostname",
    "has_userinfo_credentials",
    "is_adversarial_or_standard_ip",
]

