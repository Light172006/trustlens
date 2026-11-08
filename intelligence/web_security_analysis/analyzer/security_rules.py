"""
TrustLens Web Security Analyzer - Deterministic Security Rules Engine
Evaluates verifiable technical security controls and emits evidence-backed finding objects.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("security_rules")

BASE_DIR = Path(__file__).resolve().parent.parent


def evaluate_security_findings(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates all technical security controls against directly observed features.
    Returns list of structured finding objects with concrete evidence.
    """
    findings: List[Dict[str, Any]] = []

    def add_finding(
        fid: str,
        category: str,
        name: str,
        severity: str,
        status: str,
        evidence: str,
        guidance: str,
        recommendation: str,
    ):
        findings.append({
            "finding_id": fid,
            "category": category,
            "name": name,
            "severity": severity,
            "status": status,
            "evidence": evidence,
            "detection_method": "DETERMINISTIC_RULE_INSPECTION",
            "confidence": 1.0,
            "guidance": guidance,
            "recommendation": recommendation,
        })

    # 1. DNS Resolution
    if not features.get("domain_resolved", False):
        add_finding(
            "DNS-RESOLUTION-FAIL", "DNS_RESILIENCE", "Domain Resolution Inconclusive",
            "INFO", "UNKNOWN", f"Domain '{features.get('normalized_domain')}' failed DNS resolution for A/AAAA records.",
            "RFC 1035", "Verify domain registration and DNS zone nameserver records."
        )
    else:
        add_finding(
            "DNS-RESOLUTION-FAIL", "DNS_RESILIENCE", "Domain Resolution Succeeded",
            "INFO", "PASS", f"Resolved IP addresses: {features.get('dns_ipv4_addresses', [])}",
            "RFC 1035", "None."
        )

    # 2. HTTPS Availability
    if not features.get("https_available", False) and not features.get("tls_supported", False):
        if features.get("http_available", False):
            add_finding(
                "TLS-MISSING-HTTPS", "TLS_SECURITY", "Missing or Inaccessible HTTPS",
                "CRITICAL", "FAIL", "Plain HTTP is active on port 80, but HTTPS port 443 connection failed.",
                "RFC 2818", "Deploy a TLS certificate and enable HTTPS on port 443."
            )
        else:
            add_finding(
                "TLS-MISSING-HTTPS", "TLS_SECURITY", "HTTPS Inconclusive (Host Unreachable)",
                "INFO", "UNKNOWN", "Host unreachable on both port 80 and port 443; transport posture could not be verified.",
                "RFC 2818", "Ensure web server is accessible on public internet."
            )
    else:
        add_finding(
            "TLS-MISSING-HTTPS", "TLS_SECURITY", "HTTPS Accessible",
            "INFO", "PASS", "Port 443 TLS connection accepted.",
            "RFC 2818", "None."
        )

    # 3. TLS Protocol & Certificate
    if features.get("tls_supported", False):
        # Expiry
        if features.get("tls_cert_expired", False):
            add_finding(
                "TLS-CERT-EXPIRED", "TLS_SECURITY", "Expired TLS Certificate",
                "CRITICAL", "FAIL", f"Certificate expired at {features.get('tls_cert_not_after')} (remaining_days={features.get('tls_cert_remaining_days')}).",
                "RFC 5280", "Renew the TLS certificate immediately."
            )
        else:
            add_finding(
                "TLS-CERT-EXPIRED", "TLS_SECURITY", "Valid TLS Certificate Date",
                "INFO", "PASS", f"Certificate valid until {features.get('tls_cert_not_after')} ({features.get('tls_cert_remaining_days')} days remaining).",
                "RFC 5280", "None."
            )

        # Self-signed
        if features.get("tls_cert_is_self_signed", False):
            add_finding(
                "TLS-SELF-SIGNED", "TLS_SECURITY", "Self-Signed Certificate in Production",
                "HIGH", "FAIL", f"Subject equals Issuer: '{features.get('tls_cert_issuer')}'.",
                "CA/B Forum Baseline Requirements", "Replace self-signed certificate with one from an accredited public CA."
            )
        else:
            add_finding(
                "TLS-SELF-SIGNED", "TLS_SECURITY", "CA-Signed Certificate",
                "INFO", "PASS", f"Certificate issued by '{features.get('tls_cert_issuer')}'.",
                "CA/B Forum Baseline Requirements", "None."
            )

        # Hostname match
        if not features.get("tls_cert_hostname_match", False):
            add_finding(
                "TLS-HOSTNAME-MISMATCH", "TLS_SECURITY", "Certificate Hostname Mismatch",
                "HIGH", "FAIL", f"Requested domain '{features.get('normalized_domain')}' not matched in SANs: {features.get('tls_cert_sans', [])[:5]}.",
                "RFC 6125", "Reissue certificate including the requested domain in Subject Alternative Names."
            )
        else:
            add_finding(
                "TLS-HOSTNAME-MISMATCH", "TLS_SECURITY", "Certificate Hostname Matched",
                "INFO", "PASS", "Domain matched SANs list.",
                "RFC 6125", "None."
            )

        # Deprecated TLS version
        if features.get("tls_version") in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"):
            add_finding(
                "TLS-VERSION-DEPRECATED", "TLS_SECURITY", "Deprecated TLS Version Negotiated",
                "HIGH", "FAIL", f"Negotiated protocol is {features.get('tls_version')}, which is formally deprecated.",
                "RFC 8996", "Upgrade TLS configuration to enforce TLS 1.2 or TLS 1.3 minimum."
            )
        else:
            add_finding(
                "TLS-VERSION-DEPRECATED", "TLS_SECURITY", "Modern TLS Version Negotiated",
                "INFO", "PASS", f"Negotiated modern protocol {features.get('tls_version')}.",
                "RFC 8996", "None."
            )

        # Expiring soon
        rem_days = features.get("tls_cert_remaining_days")
        if rem_days is not None and 0 <= rem_days < 15 and not features.get("tls_cert_expired", False):
            add_finding(
                "TLS-EXPIRING-SOON", "TLS_SECURITY", "Certificate Expiring Within 15 Days",
                "LOW", "WARN", f"Certificate expires in {rem_days} days ({features.get('tls_cert_not_after')}).",
                "Operational Security Best Practices", "Ensure ACME/automated certificate renewal executes promptly."
            )
    else:
        add_finding(
            "TLS-CERT-EXPIRED", "TLS_SECURITY", "Certificate Expiration Check",
            "INFO", "NOT_APPLICABLE", "TLS handshake was not completed.",
            "RFC 5280", "Enable HTTPS to allow certificate evaluation."
        )

    # 4. HTTP Security Headers
    if features.get("https_available", False):
        if not features.get("header_hsts_present", False):
            add_finding(
                "SEC-HSTS-MISSING", "HTTP_HEADERS", "Missing HTTP Strict Transport Security (HSTS)",
                "MEDIUM", "FAIL", "Strict-Transport-Security response header is absent on HTTPS endpoint.",
                "RFC 6797", "Deploy 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
            )
        else:
            max_age = features.get("header_hsts_max_age")
            if max_age is not None and max_age < 10886400:
                add_finding(
                    "SEC-HSTS-MAX-AGE-LOW", "HTTP_HEADERS", "HSTS max-age Below Recommended Duration",
                    "LOW", "WARN", f"Configured max-age={max_age} seconds is less than the recommended 10,886,400s.",
                    "RFC 6797 Section 11.2", "Increase max-age to 31536000 seconds (1 year)."
                )
            else:
                add_finding(
                    "SEC-HSTS-MISSING", "HTTP_HEADERS", "HSTS Enabled",
                    "INFO", "PASS", f"Strict-Transport-Security present with max-age={max_age}.",
                    "RFC 6797", "None."
                )

    if features.get("https_available", False) or features.get("http_available", False):
        # CSP
        if not features.get("header_csp_present", False):
            add_finding(
                "SEC-CSP-MISSING", "HTTP_HEADERS", "Missing Content-Security-Policy (CSP)",
                "MEDIUM", "FAIL", "Content-Security-Policy header is absent.",
                "W3C CSP Level 3", "Configure a restrictive Content-Security-Policy header."
            )
        else:
            if features.get("header_csp_unsafe_inline", False) or features.get("header_csp_unsafe_eval", False):
                add_finding(
                    "SEC-CSP-UNSAFE-DIRECTIVE", "HTTP_HEADERS", "CSP Contains Unsafe Directives",
                    "LOW", "WARN", f"CSP specifies unsafe-inline={features.get('header_csp_unsafe_inline')} or unsafe-eval={features.get('header_csp_unsafe_eval')}.",
                    "W3C CSP Level 3 Section 7", "Migrate inline scripts to cryptographic nonces or hashes."
                )
            else:
                add_finding(
                    "SEC-CSP-MISSING", "HTTP_HEADERS", "Content-Security-Policy Deployed",
                    "INFO", "PASS", "CSP header present without detected unsafe keyword fallback.",
                    "W3C CSP Level 3", "None."
                )

        # XFO
        if not features.get("header_xfo_present", False) and not features.get("header_csp_present", False):
            add_finding(
                "SEC-XFO-MISSING", "HTTP_HEADERS", "Missing Clickjacking Protection (X-Frame-Options)",
                "LOW", "FAIL", "Neither X-Frame-Options nor CSP frame-ancestors was detected.",
                "RFC 7034", "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
            )
        else:
            add_finding(
                "SEC-XFO-MISSING", "HTTP_HEADERS", "Clickjacking Protection Configured",
                "INFO", "PASS", f"X-Frame-Options present ({features.get('header_xfo_value')}) or CSP active.",
                "RFC 7034", "None."
            )

        # XCTO
        if not features.get("header_xcto_present", False):
            add_finding(
                "SEC-XCTO-MISSING", "HTTP_HEADERS", "Missing MIME-Sniffing Protection",
                "LOW", "FAIL", "X-Content-Type-Options: nosniff header is missing.",
                "Fetch Living Standard", "Add 'X-Content-Type-Options: nosniff' header."
            )
        else:
            add_finding(
                "SEC-XCTO-MISSING", "HTTP_HEADERS", "MIME-Sniffing Protection Enabled",
                "INFO", "PASS", "X-Content-Type-Options: nosniff configured.",
                "Fetch Living Standard", "None."
            )

        # Referrer Policy
        if not features.get("header_referrer_policy_present", False):
            add_finding(
                "SEC-REFERRER-POLICY-MISSING", "HTTP_HEADERS", "Missing Referrer-Policy Header",
                "LOW", "WARN", "Referrer-Policy header is absent.",
                "W3C Referrer Policy", "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
            )
        else:
            add_finding(
                "SEC-REFERRER-POLICY-MISSING", "HTTP_HEADERS", "Referrer-Policy Configured",
                "INFO", "PASS", f"Referrer-Policy configured: {features.get('header_referrer_policy_value')}.",
                "W3C Referrer Policy", "None."
            )

    # 5. Cookie Security
    cookie_count = features.get("cookie_count", 0)
    if cookie_count > 0:
        sec_count = features.get("cookie_secure_count", 0)
        if not features.get("cookie_all_secure", False) and (features.get("https_available", False) or features.get("final_scheme") == "https"):
            add_finding(
                "COOKIE-MISSING-SECURE", "COOKIE_SECURITY", "Insecure Cookie Transmission",
                "MEDIUM", "FAIL", f"{cookie_count - sec_count} of {cookie_count} cookies lack the 'Secure' attribute.",
                "RFC 6265bis", "Add the 'Secure' attribute to all Set-Cookie headers."
            )
        else:
            add_finding(
                "COOKIE-MISSING-SECURE", "COOKIE_SECURITY", "All Cookies Secure",
                "INFO", "PASS", f"All {cookie_count} cookies include the 'Secure' attribute.",
                "RFC 6265bis", "None."
            )

        http_count = features.get("cookie_httponly_count", 0)
        if not features.get("cookie_all_httponly", False):
            add_finding(
                "COOKIE-MISSING-HTTPONLY", "COOKIE_SECURITY", "Cookies Missing HttpOnly Attribute",
                "LOW", "WARN", f"{cookie_count - http_count} of {cookie_count} cookies lack 'HttpOnly'.",
                "RFC 6265bis", "Ensure session and sensitive state cookies declare 'HttpOnly'."
            )

        samesite_total = features.get("cookie_samesite_strict_count", 0) + features.get("cookie_samesite_lax_count", 0)
        if samesite_total == 0:
            add_finding(
                "COOKIE-MISSING-SAMESITE", "COOKIE_SECURITY", "Cookies Missing SameSite Protection",
                "LOW", "WARN", f"None of the {cookie_count} cookies declare SameSite=Strict or SameSite=Lax.",
                "RFC 6265bis", "Set 'SameSite=Lax' by default on authentication cookies."
            )
    else:
        add_finding(
            "COOKIE-MISSING-SECURE", "COOKIE_SECURITY", "Cookie Security",
            "INFO", "NOT_APPLICABLE", "No Set-Cookie response headers observed.",
            "RFC 6265bis", "None."
        )

    # 6. Redirect & Downgrade
    if features.get("https_downgrade", False):
        add_finding(
            "REDIR-INSECURE-DOWNGRADE", "REDIRECT_INTEGRITY", "HTTPS-to-HTTP Insecure Downgrade",
            "CRITICAL", "FAIL", "Redirect sequence downgraded an initial HTTPS request to unencrypted HTTP.",
            "RFC 6797", "Eliminate plain HTTP destinations in redirect sequences."
        )
    elif features.get("http_available", False) and features.get("https_available", False):
        if not features.get("http_to_https_redirect", False):
            add_finding(
                "REDIR-HTTP-NO-REDIRECT", "REDIRECT_INTEGRITY", "Plain HTTP Does Not Redirect to HTTPS",
                "MEDIUM", "WARN", "Port 80 responds without redirecting incoming clients to HTTPS.",
                "NIST SP 800-52", "Configure a 301 Permanent Redirect on port 80 to https://{domain}."
            )
        else:
            add_finding(
                "REDIR-HTTP-NO-REDIRECT", "REDIRECT_INTEGRITY", "HTTP Correctly Redirects to HTTPS",
                "INFO", "PASS", "Cleartext HTTP requests redirect to HTTPS.",
                "NIST SP 800-52", "None."
            )

    # 7. Server Exposure
    if features.get("server_version_exposed", False):
        add_finding(
            "INFO-SERVER-VERSION-LEAK", "SERVER_EXPOSURE", "Server Header Version Disclosure",
            "LOW", "WARN", f"Server header banner exposes version details: '{features.get('server_header')}'.",
            "OWASP WSTG-INFO-02", "Configure web server to suppress granular version information."
        )

    if features.get("x_powered_by_present", False):
        add_finding(
            "INFO-X-POWERED-BY-PRESENT", "SERVER_EXPOSURE", "Framework Exposure via X-Powered-By",
            "LOW", "WARN", "X-Powered-By header is present disclosing backend technology.",
            "OWASP WSTG-INFO-08", "Disable X-Powered-By header in application runtime configuration."
        )

    return findings

