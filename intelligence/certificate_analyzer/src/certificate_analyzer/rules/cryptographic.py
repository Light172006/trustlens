"""Cryptographic security rules."""

from typing import Any, Dict, List, Optional
from certificate_analyzer.constants import DEDUCTIONS, FindingSeverity
from certificate_analyzer.rules.base import CertificateRule
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class CryptographicRules(CertificateRule):
    rule_id = "RULE_GROUP_CRYPTO"
    name = "Cryptographic Security Rules"

    def evaluate(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
    ) -> List[CertificateFinding]:
        findings: List[CertificateFinding] = []

        # 1. Weak Public Key
        if features.is_rsa and features.key_size_bits < 2048:
            findings.append(
                CertificateFinding(
                    code="RULE_INSECURE_PUBLIC_KEY",
                    title="Insecure RSA Key Size (< 2048 bits)",
                    severity=FindingSeverity.CRITICAL,
                    description=f"The certificate uses an obsolete {features.key_size_bits}-bit RSA key, vulnerable to factorization.",
                    evidence={"algorithm": features.public_key_algorithm, "key_size_bits": features.key_size_bits},
                    recommendation="Reissue the certificate using RSA >= 2048 bits or ECDSA P-256.",
                    score_deduction=DEDUCTIONS["INSECURE_PUBLIC_KEY"],
                )
            )

        # 2. Insecure MD5 / Deprecated SHA-1 Signature
        if features.is_md5_signature:
            findings.append(
                CertificateFinding(
                    code="RULE_INSECURE_SIGNATURE_MD5",
                    title="Insecure MD5 Digest Signature",
                    severity=FindingSeverity.CRITICAL,
                    description="The certificate signature uses the broken MD5 digest algorithm, completely untrusted by modern browsers.",
                    evidence={"signature_algorithm": features.signature_algorithm},
                    recommendation="Immediately reissue with SHA-256 or SHA-384.",
                    score_deduction=DEDUCTIONS["INSECURE_SIGNATURE_MD5"],
                )
            )
        elif features.is_sha1_signature:
            findings.append(
                CertificateFinding(
                    code="RULE_DEPRECATED_SIGNATURE_SHA1",
                    title="Deprecated SHA-1 Digest Signature",
                    severity=FindingSeverity.HIGH,
                    description="The certificate signature uses SHA-1, deprecated by the CA/Browser Forum since 2016 due to collision attacks.",
                    evidence={"signature_algorithm": features.signature_algorithm},
                    recommendation="Reissue using SHA-256 or stronger digest algorithm.",
                    score_deduction=DEDUCTIONS["DEPRECATED_SIGNATURE_SHA1"],
                )
            )

        # 3. Modern Crypto Positive Factor
        if (features.is_ecdsa and features.key_size_bits >= 256) or (features.is_rsa and features.key_size_bits >= 3072):
            if features.is_secure_signature:
                findings.append(
                    CertificateFinding(
                        code="RULE_MODERN_CRYPTOGRAPHY",
                        title="Strong Modern Cryptography Parameters",
                        severity=FindingSeverity.INFO,
                        description=f"Certificate employs robust modern parameters: {features.public_key_algorithm}-{features.key_size_bits} with {features.signature_algorithm}.",
                        evidence={"key_size_bits": features.key_size_bits, "algorithm": features.public_key_algorithm},
                        recommendation=None,
                        score_deduction=0,
                    )
                )

        return findings

