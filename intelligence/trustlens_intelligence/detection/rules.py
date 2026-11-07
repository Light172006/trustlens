"""TrustLens Intelligence — Concrete Threat Detection Rules.

Implements all decisive and additive rules defined in PRD.md (FR-09) and ARCH.md.
"""

from typing import Any

from trustlens_intelligence.config.constants import (
    RULE_CERT_CHAIN_INVALID,
    RULE_CERT_EXPIRED,
    RULE_CERT_HOSTNAME_MISMATCH,
    RULE_COMMUNITY_CONFIRMED_MALICIOUS,
    RULE_COOKIE_HTTPONLY_MISSING,
    RULE_COOKIE_SAMESITE_MISSING,
    RULE_COOKIE_SECURE_MISSING,
    RULE_CSP_MISSING,
    RULE_DOMAIN_RECENTLY_REGISTERED,
    RULE_HSTS_MISSING,
    RULE_HTTP_NO_HTTPS_REDIRECT,
    RULE_OPENPHISH_URL_MATCH,
    RULE_PERMISSIONS_POLICY_MISSING,
    RULE_REFERRER_POLICY_MISSING,
    RULE_SUSPICIOUS_EXCESSIVE_REDIRECTS,
    RULE_SUSPICIOUS_HOMOGLYPH_PUNYCODE,
    RULE_SUSPICIOUS_IP_HOST,
    RULE_SUSPICIOUS_USERINFO,
    RULE_TLS_LEGACY_PROTOCOL,
    RULE_URL_HIGH_ENTROPY,
    RULE_URLHAUS_HISTORICAL_URL_MATCH,
    RULE_URLHAUS_ONLINE_URL_MATCH,
    RULE_X_CONTENT_TYPE_OPTIONS_MISSING,
    FindingCategory,
    FindingSeverity,
)
from trustlens_intelligence.detection.base_rule import DetectionRule
from trustlens_intelligence.schemas.evidence import ScanEvidence
from trustlens_intelligence.schemas.features import ExtractedFeatures
from trustlens_intelligence.schemas.findings import Finding

# ==============================================================================
# DECISIVE MALICIOUS RULES
# ==============================================================================


class OpenPhishMatchRule(DetectionRule):
    """Triggers when URL matches active OpenPhish community phishing feed."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_OPENPHISH_URL_MATCH,
            category=FindingCategory.THREAT_INTEL,
            severity=FindingSeverity.CRITICAL,
            points=100,
            title="Known phishing URL verified by OpenPhish",
            description_template="The submitted URL matches an active phishing indicator catalogued in the OpenPhish threat intelligence feed.",
            remediation="Do not visit, submit credentials, or interact with this URL. It is an active phishing threat.",
            is_decisive=True,
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.openphish_match:
            return self._build_finding(
                evidence={"provider": "openphish", "matched": True, "url": evidence.canonical_url or evidence.original_url}
            )
        return None


class URLhausOnlineMatchRule(DetectionRule):
    """Triggers when URL matches an online malware distribution URL in URLhaus."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_URLHAUS_ONLINE_URL_MATCH,
            category=FindingCategory.THREAT_INTEL,
            severity=FindingSeverity.CRITICAL,
            points=100,
            title="Active malware distribution URL verified by URLhaus",
            description_template="The URL is actively distributing malware payloads according to URLhaus threat intelligence.",
            remediation="Do not visit or download files from this URL. Active malware delivery detected.",
            is_decisive=True,
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.urlhaus_match and features.urlhaus_online:
            return self._build_finding(
                evidence={
                    "provider": "urlhaus",
                    "matched": True,
                    "url_status": "online",
                    "url": evidence.canonical_url or evidence.original_url,
                }
            )
        return None


class CommunityConfirmedMaliciousRule(DetectionRule):
    """Triggers when at least 2 distinct moderator-confirmed community reports identify URL as malicious."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_COMMUNITY_CONFIRMED_MALICIOUS,
            category=FindingCategory.COMMUNITY,
            severity=FindingSeverity.CRITICAL,
            points=90,
            title="Multiple moderator-confirmed community threat reports",
            description_template="At least two independent, moderator-confirmed community reports identify this URL as malicious.",
            remediation="Exercise extreme caution and avoid interacting with this site based on confirmed community intelligence.",
            is_decisive=True,
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if evidence.community_intelligence:
            confirmed = evidence.community_intelligence.confirmed_report_count
            distinct = evidence.community_intelligence.distinct_reporter_count
            if confirmed >= 2 and distinct >= 2:
                return self._build_finding(
                    evidence={
                        "confirmed_report_count": confirmed,
                        "distinct_reporter_count": distinct,
                    }
                )
        return None


# ==============================================================================
# ADDITIVE SECURITY & CERTIFICATE RULES
# ==============================================================================


class URLhausHistoricalMatchRule(DetectionRule):
    """Triggers when URL has historical malware record in URLhaus (offline or unknown)."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_URLHAUS_HISTORICAL_URL_MATCH,
            category=FindingCategory.THREAT_INTEL,
            severity=FindingSeverity.HIGH,
            points=25,
            title="Historical malware distribution URL (URLhaus)",
            description_template="The URL was previously catalogued as a malware distribution point in URLhaus (currently offline/historical).",
            remediation="Exercise caution. While not currently verified active, this URL has a history of malware distribution.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.urlhaus_match and not features.urlhaus_online:
            return self._build_finding(
                evidence={
                    "provider": "urlhaus",
                    "matched": True,
                    "url_status": "offline_or_unknown",
                    "url": evidence.canonical_url or evidence.original_url,
                }
            )
        return None


class CertChainInvalidRule(DetectionRule):
    """TLS certificate chain is untrusted or invalid."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_CERT_CHAIN_INVALID,
            category=FindingCategory.CERTIFICATE,
            severity=FindingSeverity.HIGH,
            points=25,
            title="TLS certificate chain is invalid or untrusted",
            description_template="The TLS certificate presented by the server does not chain to an operating system trusted root authority.",
            remediation="Verify whether the certificate was issued by an accredited Certificate Authority. Avoid submitting sensitive information.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.cert_chain_valid is False:
            issuer = evidence.tls.issuer if evidence.tls else "Unknown"
            return self._build_finding(evidence={"chain_valid": False, "issuer": issuer})
        return None


class CertHostnameMismatchRule(DetectionRule):
    """Certificate SAN or CN does not match requested target host."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_CERT_HOSTNAME_MISMATCH,
            category=FindingCategory.CERTIFICATE,
            severity=FindingSeverity.HIGH,
            points=25,
            title="TLS certificate hostname mismatch",
            description_template="The hostname in the certificate subject alternative names does not match the target domain.",
            remediation="Ensure the domain requested matches the certificate Subject Alternative Names (SAN).",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.cert_hostname_match is False:
            san_dns = evidence.tls.san_dns if evidence.tls else []
            return self._build_finding(
                evidence={
                    "hostname_match": False,
                    "target_host": evidence.host,
                    "certificate_san_dns": san_dns,
                }
            )
        return None


class CertExpiredRule(DetectionRule):
    """Certificate validity period has expired."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_CERT_EXPIRED,
            category=FindingCategory.CERTIFICATE,
            severity=FindingSeverity.HIGH,
            points=20,
            title="TLS certificate has expired",
            description_template="The website's TLS certificate expired and has not been renewed.",
            remediation="Renew the TLS certificate with a recognized Certificate Authority.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.cert_is_expired is True or (
            features.cert_days_until_expiry is not None and features.cert_days_until_expiry < 0
        ):
            days = features.cert_days_until_expiry if features.cert_days_until_expiry is not None else "unknown"
            return self._build_finding(evidence={"is_expired": True, "days_until_expiry": days})
        return None


class TlsLegacyProtocolRule(DetectionRule):
    """Server negotiated an obsolete TLS version (TLS 1.0, 1.1, or SSL 3.0)."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_TLS_LEGACY_PROTOCOL,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.MEDIUM,
            points=10,
            title="Deprecated TLS protocol in use",
            description_template="The server negotiated an obsolete TLS protocol ({protocol}), which lacks modern cryptographic protections.",
            remediation="Upgrade web server configuration to support TLS 1.2 or TLS 1.3 exclusively.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.is_legacy_tls is True and evidence.tls:
            proto = evidence.tls.protocol_version or "Legacy"
            return self._build_finding(
                evidence={"protocol_version": proto},
                description_kwargs={"protocol": proto},
            )
        return None


class HstsMissingRule(DetectionRule):
    """Missing Strict-Transport-Security header."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_HSTS_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=5,
            title="HTTP Strict Transport Security (HSTS) missing",
            description_template="The server does not send a Strict-Transport-Security response header, allowing potential protocol downgrade attacks.",
            remediation="Configure the Strict-Transport-Security header with max-age of at least 31536000 seconds.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if evidence.http is not None and not features.has_hsts:
            return self._build_finding(
                evidence={"header": "strict-transport-security", "observed": False}
            )
        return None


class CspMissingRule(DetectionRule):
    """Missing Content-Security-Policy header."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_CSP_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=4,
            title="Content Security Policy (CSP) missing",
            description_template="The server does not define a Content-Security-Policy header to restrict content and script execution.",
            remediation="Implement a Content Security Policy restricting script, object, frame, and other resource origins.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if evidence.http is not None and not features.has_csp:
            return self._build_finding(
                evidence={"header": "content-security-policy", "observed": False}
            )
        return None


class XContentTypeOptionsMissingRule(DetectionRule):
    """Missing X-Content-Type-Options: nosniff header."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_X_CONTENT_TYPE_OPTIONS_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=2,
            title="X-Content-Type-Options header missing or invalid",
            description_template="The response is missing 'X-Content-Type-Options: nosniff', which protects against MIME-type sniffing attacks.",
            remediation="Add the 'X-Content-Type-Options: nosniff' HTTP header to all server responses.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if evidence.http is not None and not features.has_x_content_type_options:
            return self._build_finding(
                evidence={"header": "x-content-type-options", "expected": "nosniff", "observed": False}
            )
        return None


class ReferrerPolicyMissingRule(DetectionRule):
    """Missing Referrer-Policy header."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_REFERRER_POLICY_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=1,
            title="Referrer-Policy header missing",
            description_template="The server does not specify a Referrer-Policy header to control referrer leakage.",
            remediation="Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if evidence.http is not None and not features.has_referrer_policy:
            return self._build_finding(evidence={"header": "referrer-policy", "observed": False})
        return None


class PermissionsPolicyMissingRule(DetectionRule):
    """Missing Permissions-Policy header."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_PERMISSIONS_POLICY_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=1,
            title="Permissions-Policy header missing",
            description_template="The server does not define a Permissions-Policy header to restrict sensitive browser APIs.",
            remediation="Add a Permissions-Policy header restricting sensitive browser features.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if evidence.http is not None and not features.has_permissions_policy:
            return self._build_finding(evidence={"header": "permissions-policy", "observed": False})
        return None


class CookieSecureMissingRule(DetectionRule):
    """Cookies missing the Secure flag."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_COOKIE_SECURE_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=3,  # Per cookie in scoring calculator, capped at 6
            title="Insecure cookie flags: Secure attribute missing",
            description_template="{count} cookie(s) were observed without the Secure attribute: {names}",
            remediation="Set the Secure attribute on all cookies transmitted over HTTPS.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.insecure_cookie_count > 0 and evidence.http:
            insecure_names = [c.name for c in evidence.http.cookies if not c.secure]
            # Point contribution: 3 per cookie, capped at 6
            pts = min(6, len(insecure_names) * 3)
            return self._build_finding(
                evidence={"affected_cookies": insecure_names, "count": len(insecure_names)},
                points=pts,
                description_kwargs={"count": len(insecure_names), "names": ", ".join(insecure_names[:3])},
            )
        return None


class CookieHttpOnlyMissingRule(DetectionRule):
    """Cookies missing the HttpOnly flag."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_COOKIE_HTTPONLY_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=2,  # Per cookie, capped at 4
            title="Insecure cookie flags: HttpOnly attribute missing",
            description_template="{count} cookie(s) were observed without the HttpOnly attribute: {names}",
            remediation="Set the HttpOnly attribute on sensitive cookies to mitigate XSS script access.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.missing_httponly_cookie_count > 0 and evidence.http:
            affected = [c.name for c in evidence.http.cookies if not c.httponly]
            pts = min(4, len(affected) * 2)
            return self._build_finding(
                evidence={"affected_cookies": affected, "count": len(affected)},
                points=pts,
                description_kwargs={"count": len(affected), "names": ", ".join(affected[:3])},
            )
        return None


class CookieSameSiteMissingRule(DetectionRule):
    """Cookies missing SameSite attribute."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_COOKIE_SAMESITE_MISSING,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=2,  # Per cookie, capped at 4
            title="Insecure cookie flags: SameSite attribute missing",
            description_template="{count} cookie(s) were observed without a SameSite attribute: {names}",
            remediation="Set SameSite=Lax or SameSite=Strict on all cookies to mitigate cross-site request forgery.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.missing_samesite_cookie_count > 0 and evidence.http:
            affected = [c.name for c in evidence.http.cookies if not c.samesite]
            pts = min(4, len(affected) * 2)
            return self._build_finding(
                evidence={"affected_cookies": affected, "count": len(affected)},
                points=pts,
                description_kwargs={"count": len(affected), "names": ", ".join(affected[:3])},
            )
        return None


class HttpNoHttpsRedirectRule(DetectionRule):
    """Initial HTTP request does not redirect to HTTPS."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_HTTP_NO_HTTPS_REDIRECT,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=5,
            title="Plain HTTP target does not redirect to HTTPS",
            description_template="The website serves content over unencrypted HTTP without redirecting to HTTPS.",
            remediation="Enforce an immediate HTTP 301 redirect to HTTPS for all web traffic.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if evidence.http is not None and evidence.scheme == "http" and not features.http_to_https_redirect:
            return self._build_finding(
                evidence={
                    "initial_scheme": "http",
                    "redirect_to_https": False,
                    "final_url": evidence.http.final_url if evidence.http else None,
                }
            )
        return None


# ==============================================================================
# DOMAIN & STRUCTURAL HEURISTIC RULES
# ==============================================================================


class DomainRecentlyRegisteredRule(DetectionRule):
    """Newly registered domain (<= 30 days old)."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_DOMAIN_RECENTLY_REGISTERED,
            category=FindingCategory.DOMAIN_INTELLIGENCE,
            severity=FindingSeverity.HIGH,
            points=15,
            title="Recently registered domain",
            description_template="The domain was registered {days} days ago. Newly registered domains are disproportionately leveraged for rapid phishing campaigns.",
            remediation="Verify the organization through independent channels before entering credentials or making payments.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.domain_age_days is not None and features.domain_age_days <= 30:
            return self._build_finding(
                evidence={"domain_age_days": features.domain_age_days},
                description_kwargs={"days": features.domain_age_days},
            )
        return None


class SuspiciousIpHostRule(DetectionRule):
    """Host is an IP address rather than a domain name."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_SUSPICIOUS_IP_HOST,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.HIGH,
            points=20,
            title="IP address used as hostname",
            description_template="The website URL uses a raw IP address ({host}) instead of a domain name, a common evasion tactic in malicious infrastructure.",
            remediation="Legitimate web services typically operate on registered domain names. Avoid submitting credentials to raw IP addresses.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.is_ip_host:
            return self._build_finding(
                evidence={"host": evidence.host, "is_ip": True},
                description_kwargs={"host": evidence.host or "IP address"},
            )
        return None


class SuspiciousUserinfoRule(DetectionRule):
    """URL contains embedded credentials/userinfo (e.g. user:pass@host)."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_SUSPICIOUS_USERINFO,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.HIGH,
            points=15,
            title="Embedded credentials or userinfo in URL",
            description_template="The URL contains embedded userinfo (credentials or user token) preceding an '@' symbol, a common deceptive tactic used to obscure the destination host.",
            remediation="Never trust links containing '@' symbols preceding the hostname, as they may deceive users about the actual destination.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.has_userinfo:
            return self._build_finding(
                evidence={"url": evidence.original_url, "has_userinfo": True},
            )
        return None


class SuspiciousHomoglyphPunycodeRule(DetectionRule):
    """Domain contains Punycode or confusable homoglyph characters."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_SUSPICIOUS_HOMOGLYPH_PUNYCODE,
            category=FindingCategory.DOMAIN_INTELLIGENCE,
            severity=FindingSeverity.HIGH,
            points=20,
            title="Deceptive domain: Punycode or homoglyph characters detected",
            description_template="The domain name ({host}) contains internationalized punycode or confusable characters that mimic familiar brands.",
            remediation="Carefully inspect the address bar for spoofed characters designed to look like legitimate domains.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.is_punycode or features.has_homoglyphs:
            return self._build_finding(
                evidence={
                    "host": evidence.host,
                    "is_punycode": features.is_punycode,
                    "has_homoglyphs": features.has_homoglyphs,
                },
                description_kwargs={"host": evidence.host or ""},
            )
        return None


class SuspiciousExcessiveRedirectsRule(DetectionRule):
    """URL traversed an excessive number of redirect hops (>= 3)."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_SUSPICIOUS_EXCESSIVE_REDIRECTS,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.MEDIUM,
            points=15,
            title="Excessive redirect chain detected",
            description_template="The URL traversed {count} redirects, which is frequently used to evade automated link scanners.",
            remediation="Review the full redirect chain to ensure the final landing page is trusted.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.redirect_count >= 3:
            return self._build_finding(
                evidence={"redirect_count": features.redirect_count},
                description_kwargs={"count": features.redirect_count},
            )
        return None


class UrlHighEntropyRule(DetectionRule):
    """High Shannon entropy indicating obfuscated or generated URL."""

    def __init__(self) -> None:
        super().__init__(
            code=RULE_URL_HIGH_ENTROPY,
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.LOW,
            points=10,
            title="High entropy URL detected",
            description_template="The URL exhibits an unusually high degree of character randomness ({entropy} bits/char), characteristic of obfuscation.",
            remediation="Ensure this URL was received from a verified sender and is not an encoded tracking or phishing payload.",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        if features.url_entropy >= 4.5 and features.url_length >= 50:
            return self._build_finding(
                evidence={"url_entropy": features.url_entropy, "url_length": features.url_length},
                description_kwargs={"entropy": features.url_entropy},
            )
        return None

