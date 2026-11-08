"""
TrustLens Web Security Analyzer - Safe Telemetry & Feature Extraction Engine
Performs safe, passive network observations with strict SSRF defense at every hop.
Extracts 50+ technical features conforming to the canonical Web Security schema.
"""

import asyncio
import datetime
import hashlib
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from ssrf_guard import SSRFSecurityException, resolve_and_validate_destination
from url_validator import normalize_target_url

logger = logging.getLogger("feature_extractor")


def parse_cookie_attributes(cookie_headers: List[str]) -> Dict[str, Any]:
    """Extracts security attributes without storing cookie values or sensitive names."""
    total = len(cookie_headers)
    secure_count = 0
    httponly_count = 0
    samesite_strict = 0
    samesite_lax = 0
    samesite_none = 0

    for c in cookie_headers:
        parts = [p.strip().lower() for p in c.split(";")]
        for p in parts[1:]:
            if p == "secure":
                secure_count += 1
            elif p == "httponly":
                httponly_count += 1
            elif p == "samesite=strict":
                samesite_strict += 1
            elif p == "samesite=lax":
                samesite_lax += 1
            elif p == "samesite=none":
                samesite_none += 1

    return {
        "cookie_count": total,
        "cookie_secure_count": secure_count,
        "cookie_httponly_count": httponly_count,
        "cookie_samesite_strict_count": samesite_strict,
        "cookie_samesite_lax_count": samesite_lax,
        "cookie_samesite_none_count": samesite_none,
        "cookie_all_secure": (secure_count == total and total > 0),
        "cookie_all_httponly": (httponly_count == total and total > 0),
    }


def parse_hsts_header(hsts_val: Optional[str]) -> Dict[str, Any]:
    if not hsts_val:
        return {
            "header_hsts_present": False,
            "header_hsts_max_age": None,
            "header_hsts_include_subdomains": False,
            "header_hsts_preload": False,
        }
    max_age = None
    m = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.IGNORECASE)
    if m:
        try:
            max_age = int(m.group(1))
        except ValueError:
            pass
    return {
        "header_hsts_present": True,
        "header_hsts_max_age": max_age,
        "header_hsts_include_subdomains": "includesubdomains" in hsts_val.lower(),
        "header_hsts_preload": "preload" in hsts_val.lower(),
    }


def parse_csp_header(csp_val: Optional[str]) -> Dict[str, Any]:
    if not csp_val:
        return {
            "header_csp_present": False,
            "header_csp_unsafe_inline": False,
            "header_csp_unsafe_eval": False,
        }
    val_lower = csp_val.lower()
    return {
        "header_csp_present": True,
        "header_csp_unsafe_inline": "unsafe-inline" in val_lower,
        "header_csp_unsafe_eval": "unsafe-eval" in val_lower,
    }


class SafeLiveFeatureExtractor:
    """
    Executes safe, non-intrusive live web security observation with comprehensive SSRF protection.
    """

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_redirects: int = 5,
        user_agent: str = "TrustLens-WebSecurity-Analyzer/1.0 (+https://trustlens.ai/analyzer)",
    ):
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.user_agent = user_agent

    async def extract_features(self, target_url: str) -> Dict[str, Any]:
        url_info = normalize_target_url(target_url)
        hostname = url_info["hostname"]
        reg_domain = url_info["registrable_domain"]
        scan_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sample_id = hashlib.sha256(f"{reg_domain}:{scan_time}".encode()).hexdigest()[:24]

        features: Dict[str, Any] = {
            "sample_id": sample_id,
            "scan_timestamp": scan_time,
            "source_name": "LIVE_OBSERVATION",
            "source_reference": url_info["normalized_url"],
            "collection_method": "PASSIVE_PROBE",
            "collection_status": "UNKNOWN",
            "dataset_version": "1.0.0",
            "normalized_domain": hostname,
            "registrable_domain": reg_domain,
            "url_scheme": url_info["scheme"],
            "url_length": len(url_info["normalized_url"]),
            "subdomain_count": max(0, len(hostname.split(".")) - len(reg_domain.split("."))),
            "is_idn": url_info["is_idn"],
            "is_ip_host": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)),
            "domain_resolved": False,
            "dns_has_ipv4": False,
            "dns_has_ipv6": False,
            "dns_ipv4_addresses": [],
            "dns_has_caa": False,
            "tls_supported": False,
            "tls_version": None,
            "tls_cipher": None,
            "tls_cert_valid": False,
            "tls_cert_expired": False,
            "tls_cert_not_before": None,
            "tls_cert_not_after": None,
            "tls_cert_remaining_days": None,
            "tls_cert_issuer": None,
            "tls_cert_subject": None,
            "tls_cert_san_count": 0,
            "tls_cert_sans": [],
            "tls_cert_is_self_signed": False,
            "tls_cert_hostname_match": False,
            "tls_cert_sig_alg": None,
            "tls_cert_key_size": None,
            "http_available": False,
            "https_available": False,
            "http_to_https_redirect": False,
            "redirect_count": 0,
            "final_status_code": None,
            "final_scheme": None,
            "https_downgrade": False,
            "header_hsts_present": False,
            "header_hsts_max_age": None,
            "header_hsts_include_subdomains": False,
            "header_hsts_preload": False,
            "header_csp_present": False,
            "header_csp_unsafe_inline": False,
            "header_csp_unsafe_eval": False,
            "header_xfo_present": False,
            "header_xfo_value": None,
            "header_xcto_present": False,
            "header_referrer_policy_present": False,
            "header_referrer_policy_value": None,
            "header_permissions_policy_present": False,
            "header_coop_present": False,
            "header_corp_present": False,
            "header_coep_present": False,
            "server_header": None,
            "server_version_exposed": False,
            "x_powered_by_present": False,
            "cookie_count": 0,
            "cookie_secure_count": 0,
            "cookie_httponly_count": 0,
            "cookie_samesite_strict_count": 0,
            "cookie_samesite_lax_count": 0,
            "cookie_samesite_none_count": 0,
            "cookie_all_secure": False,
            "cookie_all_httponly": False,
        }

        # 1. DNS Pre-Resolution & SSRF Validation
        resolved_ips = resolve_and_validate_destination(hostname)
        if not resolved_ips:
            features["collection_status"] = "DNS_FAILURE"
            return features

        features["domain_resolved"] = True
        ipv4s = [ip for ip in resolved_ips if ":" not in ip]
        ipv6s = [ip for ip in resolved_ips if ":" in ip]
        features["dns_has_ipv4"] = len(ipv4s) > 0
        features["dns_has_ipv6"] = len(ipv6s) > 0
        features["dns_ipv4_addresses"] = ipv4s[:5]

        # 2. Asynchronous Probing with Redirect Validation
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds, connect=2.5)
        connector = aiohttp.TCPConnector(ssl=False, ttl_dns_cache=300)

        headers_dict: Dict[str, str] = {}
        cookie_headers: List[str] = []

        async with aiohttp.ClientSession(connector=connector) as session:
            # Probe HTTPS
            try:
                current_url = f"https://{hostname}"
                redirect_hops = 0
                while redirect_hops <= self.max_redirects:
                    parsed_curr = urlparse(current_url)
                    resolve_and_validate_destination(parsed_curr.hostname or hostname)

                    async with session.get(
                        current_url,
                        timeout=timeout,
                        allow_redirects=False,
                        headers={"User-Agent": self.user_agent},
                    ) as resp:
                        features["https_available"] = True
                        features["final_status_code"] = resp.status
                        features["final_scheme"] = resp.url.scheme

                        # Extract TLS attributes
                        sslobj = resp.connection.transport.get_extra_info("ssl_object")
                        if sslobj and not features["tls_supported"]:
                            features["tls_supported"] = True
                            features["tls_version"] = sslobj.version()
                            cipher_info = sslobj.cipher()
                            if cipher_info:
                                features["tls_cipher"] = cipher_info[0]

                            der = sslobj.getpeercert(binary_form=True)
                            if der:
                                cert = x509.load_der_x509_certificate(der)
                                now = datetime.datetime.now(datetime.timezone.utc)
                                not_before = cert.not_valid_before_utc
                                not_after = cert.not_valid_after_utc

                                features["tls_cert_not_before"] = not_before.isoformat()
                                features["tls_cert_not_after"] = not_after.isoformat()
                                features["tls_cert_expired"] = now > not_after
                                features["tls_cert_valid"] = (not_before <= now <= not_after)
                                features["tls_cert_remaining_days"] = int((not_after - now).total_seconds() // 86400)

                                issuer_str = cert.issuer.rfc4514_string()
                                subject_str = cert.subject.rfc4514_string()
                                features["tls_cert_issuer"] = issuer_str
                                features["tls_cert_subject"] = subject_str
                                features["tls_cert_is_self_signed"] = (issuer_str == subject_str)
                                features["tls_cert_sig_alg"] = cert.signature_algorithm_oid._name

                                try:
                                    pk = cert.public_key()
                                    if hasattr(pk, "key_size"):
                                        features["tls_cert_key_size"] = pk.key_size
                                except Exception:
                                    pass

                                sans = []
                                try:
                                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                    for name in san_ext.value:
                                        sans.append(str(getattr(name, "value", name)).lower())
                                except Exception:
                                    pass
                                features["tls_cert_san_count"] = len(sans)
                                features["tls_cert_sans"] = sans[:20]

                                # Hostname matching
                                clean_host = hostname.lower()
                                match = False
                                for san in sans:
                                    if san == clean_host or (san.startswith("*.") and clean_host.endswith(san[1:])):
                                        match = True
                                        break
                                if not match and f"cn={clean_host}" in subject_str.lower():
                                    match = True
                                features["tls_cert_hostname_match"] = match

                        # Check for redirect
                        if resp.status in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                            loc = resp.headers["Location"].strip()
                            if loc.startswith("/"):
                                loc = f"{parsed_curr.scheme}://{parsed_curr.netloc}{loc}"
                            new_parsed = urlparse(loc)
                            if new_parsed.scheme == "http" and parsed_curr.scheme == "https":
                                features["https_downgrade"] = True

                            # SSRF validate new location before following
                            resolve_and_validate_destination(new_parsed.hostname or hostname)
                            current_url = loc
                            redirect_hops += 1
                        else:
                            # Final response
                            for k, v in resp.headers.items():
                                headers_dict[k.lower()] = v
                            cookie_headers.extend(resp.headers.getall("Set-Cookie", []))
                            features["redirect_count"] = redirect_hops
                            break
            except Exception as e:
                logger.debug(f"HTTPS probe failed: {e}")

            # Probe plain HTTP (port 80) to detect cleartext redirect policy
            try:
                resolve_and_validate_destination(hostname, port=80)
                async with session.get(
                    f"http://{hostname}",
                    timeout=aiohttp.ClientTimeout(total=2.5, connect=1.8),
                    allow_redirects=False,
                    headers={"User-Agent": self.user_agent},
                ) as resp_http:
                    features["http_available"] = True
                    if resp_http.status in (301, 302, 307, 308):
                        loc = resp_http.headers.get("Location", "").strip()
                        if loc.startswith("https://"):
                            features["http_to_https_redirect"] = True
            except Exception as e:
                logger.debug(f"HTTP probe failed: {e}")

        # Parse observed security headers
        if headers_dict:
            features.update(parse_hsts_header(headers_dict.get("strict-transport-security")))
            features.update(parse_csp_header(headers_dict.get("content-security-policy")))
            features.update(parse_cookie_attributes(cookie_headers))

            xfo = headers_dict.get("x-frame-options")
            xcto = headers_dict.get("x-content-type-options")
            referrer = headers_dict.get("referrer-policy")
            permissions = headers_dict.get("permissions-policy")
            coop = headers_dict.get("cross-origin-opener-policy")
            corp = headers_dict.get("cross-origin-resource-policy")
            coep = headers_dict.get("cross-origin-embedder-policy")
            server = headers_dict.get("server")
            x_powered = headers_dict.get("x-powered-by")

            server_ver_exposed = False
            if server:
                server_ver_exposed = bool(re.search(r"/\d+(\.\d+)*", server))

            features.update({
                "header_xfo_present": xfo is not None,
                "header_xfo_value": xfo[:50] if xfo else None,
                "header_xcto_present": (xcto is not None and "nosniff" in xcto.lower()),
                "header_referrer_policy_present": referrer is not None,
                "header_referrer_policy_value": referrer[:50] if referrer else None,
                "header_permissions_policy_present": permissions is not None,
                "header_coop_present": coop is not None,
                "header_corp_present": corp is not None,
                "header_coep_present": coep is not None,
                "server_header": server[:100] if server else None,
                "server_version_exposed": server_ver_exposed,
                "x_powered_by_present": x_powered is not None,
            })

        if features["https_available"] or features["http_available"]:
            features["collection_status"] = "SUCCESS"
        elif features["tls_supported"]:
            features["collection_status"] = "PARTIAL"
        elif not features["domain_resolved"]:
            features["collection_status"] = "DNS_FAILURE"
        else:
            features["collection_status"] = "UNREACHABLE"

        return features

