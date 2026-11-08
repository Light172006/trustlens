"""Deterministic scoring engine for Certificate Trust Score and Verdict.

Enforces strict digital trust invariants:
1. Malformed input is strictly INCONCLUSIVE (score=0, confidence=0.0).
2. Revoked certificate receives score=0 and DISTRUSTED verdict.
3. Expired certificate cannot receive TRUSTED (score capped <= 20, verdict DISTRUSTED).
4. Untrusted root cannot receive TRUSTED (score capped <= 30, verdict DISTRUSTED).
5. Hostname mismatch caps score <= 25 (verdict DISTRUSTED).
6. Incomplete chain cannot receive TRUSTED (verdict WARNING or DISTRUSTED).
7. Missing hostname context is not treated as matched.
8. Score and confidence are strictly separated.
"""

from typing import List, Tuple
from certificate_analyzer.constants import CertificateVerdict, FindingSeverity
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class CertificateScoringEngine:
    """Calculates deterministic Certificate Trust Score (0-100) and authoritative Verdict."""

    TRUSTED_THRESHOLD = 80
    WARNING_THRESHOLD = 50

    @classmethod
    def calculate(
        cls,
        findings: List[CertificateFinding],
        features: CertificateFeatures,
        is_malformed: bool = False,
    ) -> Tuple[CertificateVerdict, int, float]:
        """Calculates (verdict, trust_score, confidence) under strict PKI invariants."""
        if is_malformed:
            return CertificateVerdict.INCONCLUSIVE, 0, 0.0

        base_score = 100
        total_deduction = 0
        seen_finding_codes = set()

        has_critical = False
        has_high = False
        is_revoked = False
        is_expired = False
        is_untrusted_root = False
        is_hostname_mismatch = False
        is_incomplete_chain = False

        for f in findings:
            # Deduplicate score deductions by unique finding code
            if f.code not in seen_finding_codes:
                total_deduction += f.score_deduction
                seen_finding_codes.add(f.code)

            if f.severity == FindingSeverity.CRITICAL:
                has_critical = True
            elif f.severity == FindingSeverity.HIGH:
                has_high = True

            if f.code == "RULE_REVOKED":
                is_revoked = True
            elif f.code == "RULE_EXPIRED":
                is_expired = True
            elif f.code == "RULE_UNTRUSTED_ROOT":
                is_untrusted_root = True
            elif f.code == "RULE_HOSTNAME_MISMATCH":
                is_hostname_mismatch = True
            elif f.code == "RULE_INCOMPLETE_CHAIN":
                is_incomplete_chain = True

        raw_score = base_score - total_deduction
        final_score = max(0, min(100, raw_score))

        # Enforce Hard Invariant Caps
        if is_revoked:
            final_score = 0
            return CertificateVerdict.DISTRUSTED, final_score, 1.0

        if is_expired:
            final_score = min(final_score, 20)

        if is_hostname_mismatch:
            final_score = min(final_score, 25)

        if is_untrusted_root:
            final_score = min(final_score, 30)

        if is_incomplete_chain:
            final_score = min(final_score, 55)

        # Critical findings unconditionally cap score below WARNING threshold
        if has_critical and final_score >= cls.WARNING_THRESHOLD:
            final_score = min(final_score, 40)

        # Determine Verdict
        if final_score >= cls.TRUSTED_THRESHOLD and not has_critical and not has_high and not is_incomplete_chain:
            verdict = CertificateVerdict.TRUSTED
        elif final_score >= cls.WARNING_THRESHOLD and not has_critical:
            verdict = CertificateVerdict.WARNING
        else:
            verdict = CertificateVerdict.DISTRUSTED

        # Calculate Confidence (evidence completeness)
        confidence = 0.70  # Self-contained parsed certificate
        if features.is_chain_complete:
            confidence += 0.15
        if features.has_trusted_anchor:
            confidence += 0.10
        if features.matches_tested_hostname is not None:
            confidence += 0.05

        confidence = round(min(1.0, confidence), 2)

        return verdict, final_score, confidence
