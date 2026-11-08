"""Endpoint TLS execution and observation context schemas."""

from typing import List, Optional
from pydantic import BaseModel, Field


class EndpointTLSContext(BaseModel):
    """Contextual metadata from a live or historical TLS handshake."""

    target_hostname: Optional[str] = Field(default=None, description="Requested server hostname")
    port: int = Field(default=443, ge=1, le=65535)
    sni_hostname: Optional[str] = Field(default=None)
    tls_protocol_version: Optional[str] = Field(default=None, description="e.g. TLSv1.3, TLSv1.2")
    cipher_suite: Optional[str] = Field(default=None)
    alpn_protocol: Optional[str] = Field(default=None)
    presented_intermediates: List[bytes] = Field(default_factory=list, description="DER bytes of presented intermediate CA certificates")
    reference_store: str = Field(default="MOZILLA", description="Trust store used for validation")

