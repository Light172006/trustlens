"""
TrustLens Web Security Analyzer - Annotation & Scoring Engine
Evaluates technical security controls to produce structured findings, evidence, posture labels, and numerical scores.
"""

import argparse
import datetime
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("web_security_annotator")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_taxonomy() -> Dict[str, Any]:
    tax_path = BASE_DIR / "metadata" / "label_taxonomy.json"
    with open(tax_path, "r", encoding="utf-8") as f:
        return json.load(f)


def annotate_record(rec: Dict[str, Any], taxonomy: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    # Helper to add finding
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
            "detection_method": "RULE_BASED_INSPECTION",
            "confidence": 1.0,
            "guidance": guidance,
            "recommendation": recommendation,
        })

    # 1. DNS Resolution
    if not rec.get("domain_resolved", False):
        add_finding(
            "DNS-RESOLUTION-FAIL", "DNS_RESILIENCE", "Domain Resolution Inconclusive",
            "INFO", "UNKNOWN", f"Domain '{rec['normalized_domain']}' failed DNS resolution for A/AAAA records; posture indeterminable.",
            "RFC 1035", "Verify domain registration and DNS zone nameserver records."
        )
    else:
        add_finding(
            "DNS-RESOLUTION-FAIL", "DNS_RESILIENCE", "Domain Resolution Succeeded",
            "INFO", "PASS", f"Resolved IPv4 addresses: {rec.get('dns_ipv4_addresses', [])}",
            "RFC 1035", "None."
        )

    # 2. HTTPS Availability
    if not rec.get("https_available", False) and not rec.get("tls_supported", False):
        if rec.get("http_available", False):
            # Port 80 responds, but Port 443 is absent/unreachable: confirmed vulnerability
            add_finding(
                "TLS-MISSING-HTTPS", "TLS_SECURITY", "Missing or Inaccessible HTTPS",
                "CRITICAL", "FAIL", "Plain HTTP is active on port 80, but HTTPS port 443 connection failed.",
                "RFC 2818", "Deploy a TLS certificate and enable HTTPS on port 443."
            )
        else:
            # Neither HTTP nor HTTPS responded: collection failure / unreachable, not confirmed vulnerability
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
    if rec.get("tls_supported", False):
        # Expiry
        if rec.get("tls_cert_expired", False):
            add_finding(
                "TLS-CERT-EXPIRED", "TLS_SECURITY", "Expired TLS Certificate",
                "CRITICAL", "FAIL", f"Certificate expired at {rec.get('tls_cert_not_after')} (remaining_days={rec.get('tls_cert_remaining_days')}).",
                "RFC 5280", "Renew the TLS certificate immediately."
            )
        else:
            add_finding(
                "TLS-CERT-EXPIRED", "TLS_SECURITY", "Valid TLS Certificate Date",
                "INFO", "PASS", f"Certificate valid until {rec.get('tls_cert_not_after')} ({rec.get('tls_cert_remaining_days')} days remaining).",
                "RFC 5280", "None."
            )

        # Self-signed
        if rec.get("tls_cert_is_self_signed", False):
            add_finding(
                "TLS-SELF-SIGNED", "TLS_SECURITY", "Self-Signed Certificate in Production",
                "HIGH", "FAIL", f"Subject equals Issuer: '{rec.get('tls_cert_issuer')}'.",
                "CA/B Forum Baseline Requirements", "Replace self-signed certificate with one from an accredited public CA."
            )
        else:
            add_finding(
                "TLS-SELF-SIGNED", "TLS_SECURITY", "CA-Signed Certificate",
                "INFO", "PASS", f"Certificate issued by '{rec.get('tls_cert_issuer')}'.",
                "CA/B Forum Baseline Requirements", "None."
            )

        # Hostname match
        if not rec.get("tls_cert_hostname_match", False):
            add_finding(
                "TLS-HOSTNAME-MISMATCH", "TLS_SECURITY", "Certificate Hostname Mismatch",
                "HIGH", "FAIL", f"Requested domain '{rec['normalized_domain']}' not matched in SANs: {rec.get('tls_cert_sans', [])[:5]}.",
                "RFC 6125", "Reissue certificate including the requested domain in Subject Alternative Names."
            )
        else:
            add_finding(
                "TLS-HOSTNAME-MISMATCH", "TLS_SECURITY", "Certificate Hostname Matched",
                "INFO", "PASS", f"Domain matched SANs list.",
                "RFC 6125", "None."
            )

        # Deprecated TLS version
        if rec.get("tls_version") in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"):
            add_finding(
                "TLS-VERSION-DEPRECATED", "TLS_SECURITY", "Deprecated TLS Version Negotiated",
                "HIGH", "FAIL", f"Negotiated protocol is {rec.get('tls_version')}, which is formally deprecated.",
                "RFC 8996", "Upgrade TLS configuration to enforce TLS 1.2 or TLS 1.3 minimum."
            )
        else:
            add_finding(
                "TLS-VERSION-DEPRECATED", "TLS_SECURITY", "Modern TLS Version Negotiated",
                "INFO", "PASS", f"Negotiated modern protocol {rec.get('tls_version')}.",
                "RFC 8996", "None."
            )

        # Expiring soon
        rem_days = rec.get("tls_cert_remaining_days")
        if rem_days is not None and 0 <= rem_days < 15 and not rec.get("tls_cert_expired", False):
            add_finding(
                "TLS-EXPIRING-SOON", "TLS_SECURITY", "Certificate Expiring Within 15 Days",
                "LOW", "WARN", f"Certificate expires in {rem_days} days ({rec.get('tls_cert_not_after')}).",
                "Operational Security Best Practices", "Ensure ACME/automated certificate renewal executes promptly."
            )
    else:
        add_finding(
            "TLS-CERT-EXPIRED", "TLS_SECURITY", "Certificate Expiration Check",
            "INFO", "NOT_APPLICABLE", "TLS handshake was not completed.",
            "RFC 5280", "Enable HTTPS to allow certificate evaluation."
        )

    # 4. HTTP Security Headers
    if rec.get("https_available", False):
        if not rec.get("header_hsts_present", False):
            add_finding(
                "SEC-HSTS-MISSING", "HTTP_HEADERS", "Missing HTTP Strict Transport Security (HSTS)",
                "MEDIUM", "FAIL", "Strict-Transport-Security response header is absent on HTTPS endpoint.",
                "RFC 6797", "Deploy 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
            )
        else:
            max_age = rec.get("header_hsts_max_age")
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

    if rec.get("https_available", False) or rec.get("http_available", False):
        # CSP
        if not rec.get("header_csp_present", False):
            add_finding(
                "SEC-CSP-MISSING", "HTTP_HEADERS", "Missing Content-Security-Policy (CSP)",
                "MEDIUM", "FAIL", "Content-Security-Policy header is absent.",
                "W3C CSP Level 3", "Configure a restrictive Content-Security-Policy header."
            )
        else:
            if rec.get("header_csp_unsafe_inline", False) or rec.get("header_csp_unsafe_eval", False):
                add_finding(
                    "SEC-CSP-UNSAFE-DIRECTIVE", "HTTP_HEADERS", "CSP Contains Unsafe Directives",
                    "LOW", "WARN", f"CSP specifies unsafe-inline={rec.get('header_csp_unsafe_inline')} or unsafe-eval={rec.get('header_csp_unsafe_eval')}.",
                    "W3C CSP Level 3 Section 7", "Migrate inline scripts to cryptographic nonces or hashes."
                )
            else:
                add_finding(
                    "SEC-CSP-MISSING", "HTTP_HEADERS", "Content-Security-Policy Deployed",
                    "INFO", "PASS", "CSP header present without detected unsafe keyword fallback.",
                    "W3C CSP Level 3", "None."
                )

        # XFO
        if not rec.get("header_xfo_present", False) and not rec.get("header_csp_present", False):
            add_finding(
                "SEC-XFO-MISSING", "HTTP_HEADERS", "Missing Clickjacking Protection (X-Frame-Options)",
                "LOW", "FAIL", "Neither X-Frame-Options nor CSP frame-ancestors was detected.",
                "RFC 7034", "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
            )
        else:
            add_finding(
                "SEC-XFO-MISSING", "HTTP_HEADERS", "Clickjacking Protection Configured",
                "INFO", "PASS", f"X-Frame-Options present ({rec.get('header_xfo_value')}) or CSP active.",
                "RFC 7034", "None."
            )

        # XCTO
        if not rec.get("header_xcto_present", False):
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
        if not rec.get("header_referrer_policy_present", False):
            add_finding(
                "SEC-REFERRER-POLICY-MISSING", "HTTP_HEADERS", "Missing Referrer-Policy Header",
                "LOW", "WARN", "Referrer-Policy header is absent.",
                "W3C Referrer Policy", "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
            )
        else:
            add_finding(
                "SEC-REFERRER-POLICY-MISSING", "HTTP_HEADERS", "Referrer-Policy Configured",
                "INFO", "PASS", f"Referrer-Policy configured: {rec.get('header_referrer_policy_value')}.",
                "W3C Referrer Policy", "None."
            )

    # 5. Cookie Security
    cookie_count = rec.get("cookie_count", 0)
    if cookie_count > 0:
        sec_count = rec.get("cookie_secure_count", 0)
        if not rec.get("cookie_all_secure", False) and (rec.get("https_available", False) or rec.get("final_scheme") == "https"):
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

        http_count = rec.get("cookie_httponly_count", 0)
        if not rec.get("cookie_all_httponly", False):
            add_finding(
                "COOKIE-MISSING-HTTPONLY", "COOKIE_SECURITY", "Cookies Missing HttpOnly Attribute",
                "LOW", "WARN", f"{cookie_count - http_count} of {cookie_count} cookies lack 'HttpOnly'.",
                "RFC 6265bis", "Ensure session and sensitive state cookies declare 'HttpOnly'."
            )

        samesite_total = rec.get("cookie_samesite_strict_count", 0) + rec.get("cookie_samesite_lax_count", 0)
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
    if rec.get("https_downgrade", False):
        add_finding(
            "REDIR-INSECURE-DOWNGRADE", "REDIRECT_INTEGRITY", "HTTPS-to-HTTP Insecure Downgrade",
            "CRITICAL", "FAIL", "Redirect sequence downgraded an initial HTTPS request to unencrypted HTTP.",
            "RFC 6797", "Eliminate plain HTTP destinations in redirect sequences."
        )
    elif rec.get("http_available", False) and rec.get("https_available", False):
        if not rec.get("http_to_https_redirect", False):
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
    if rec.get("server_version_exposed", False):
        add_finding(
            "INFO-SERVER-VERSION-LEAK", "SERVER_EXPOSURE", "Server Header Version Disclosure",
            "LOW", "WARN", f"Server header banner exposes version details: '{rec.get('server_header')}'.",
            "OWASP WSTG-INFO-02", "Configure web server to suppress granular version information."
        )

    if rec.get("x_powered_by_present", False):
        add_finding(
            "INFO-X-POWERED-BY-PRESENT", "SERVER_EXPOSURE", "Framework Exposure via X-Powered-By",
            "LOW", "WARN", "X-Powered-By header is present disclosing backend technology.",
            "OWASP WSTG-INFO-08", "Disable X-Powered-By header in application runtime configuration."
        )

    # Compute Aggregate Score and Posture Label
    score = 100.0
    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0
    pass_count = 0

    finding_ids = []
    finding_categories = []
    finding_severities = []
    finding_statuses = []

    for f in findings:
        fid = f["finding_id"]
        sev = f["severity"]
        st = f["status"]
        cat = f["category"]

        finding_ids.append(fid)
        finding_categories.append(cat)
        finding_severities.append(sev)
        finding_statuses.append(st)

        if st == "FAIL":
            if sev == "CRITICAL":
                score -= 35.0
                crit_count += 1
            elif sev == "HIGH":
                score -= 20.0
                high_count += 1
            elif sev == "MEDIUM":
                score -= 10.0
                med_count += 1
            elif sev == "LOW":
                score -= 3.0
                low_count += 1
        elif st == "WARN":
            if sev == "MEDIUM":
                score -= 5.0
                med_count += 1
            elif sev == "LOW":
                score -= 2.0
                low_count += 1
        elif st == "PASS":
            pass_count += 1

    score = max(0.0, min(100.0, round(score, 1)))

    # Determine Website Posture Label
    if crit_count > 0 or (score < 50.0 and rec.get("domain_resolved", True) and rec.get("collection_status") not in ("UNREACHABLE", "DNS_FAILURE")):
        posture_label = "POOR"
    elif not rec.get("domain_resolved", False) or rec.get("collection_status") in ("UNREACHABLE", "DNS_FAILURE"):
        posture_label = "INSUFFICIENT_EVIDENCE"
        score = 0.0
    elif high_count > 0 or score < 80.0:
        posture_label = "MODERATE"
    else:
        posture_label = "GOOD"

    annotated = dict(rec)
    annotated["findings"] = json.dumps(findings)
    annotated["finding_ids"] = finding_ids
    annotated["critical_findings_count"] = crit_count
    annotated["high_findings_count"] = high_count
    annotated["medium_findings_count"] = med_count
    annotated["low_findings_count"] = low_count
    annotated["pass_findings_count"] = pass_count
    annotated["website_posture_label"] = posture_label
    annotated["website_posture_score"] = score
    annotated["annotation_method"] = "RULE_BASED_STANDARDS_V1"
    annotated["annotation_version"] = "1.0.0"

    return annotated


def annotate_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    taxonomy = load_taxonomy()
    annotated_list = []
    for rec in records:
        annotated_list.append(annotate_record(rec, taxonomy))
    logger.info(f"Annotated {len(annotated_list)} records with multi-label findings.")
    return annotated_list


def main():
    parser = argparse.ArgumentParser(description="TrustLens Annotation Engine")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    args = parser.parse_args()


if __name__ == "__main__":
    main()

