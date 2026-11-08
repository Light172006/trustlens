"""
TrustLens Web Security Analyzer - Domain & Telemetry Normalization Engine
Performs Public Suffix List parsing, IDN normalization, data hygiene, and exclusion auditing.
"""

import argparse
import datetime
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import idna
import pandas as pd
from tld import get_fld
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("web_security_normalizer")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(BASE_DIR / "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def is_valid_domain_syntax(domain: str) -> bool:
    """Validates domain name conforms to RFC 1035 / RFC 1123."""
    if not domain or len(domain) > 253:
        return False
    if domain.endswith("."):
        domain = domain[:-1]
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    for label in labels:
        if not pattern.match(label):
            return False
    return True


def normalize_record(raw: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Normalizes a single observation record.
    Returns (normalized_dict, None) or (None, exclusion_reason).
    """
    raw_domain = raw.get("normalized_domain", "").strip().lower()
    if not raw_domain:
        return None, "EMPTY_DOMAIN"

    # Strip scheme, trailing slash, path, query if present
    raw_domain = re.sub(r"^https?://", "", raw_domain)
    raw_domain = raw_domain.split("/")[0].split(":")[0].strip()

    # IDN / Punycode handling
    try:
        ascii_domain = idna.encode(raw_domain).decode("ascii")
    except Exception:
        ascii_domain = raw_domain

    if not is_valid_domain_syntax(ascii_domain):
        return None, f"INVALID_DOMAIN_SYNTAX: {raw_domain}"

    # Registrable domain extraction via Public Suffix List
    fld = get_fld(ascii_domain, fix_protocol=True, fail_silently=True)
    if not fld:
        # Fallback to last two parts if standard TLD
        parts = ascii_domain.split(".")
        if len(parts) >= 2:
            fld = ".".join(parts[-2:])
        else:
            return None, f"PSL_EXTRACTION_FAILED: {ascii_domain}"

    # Filter out collection failures if unreachable
    status = raw.get("collection_status", "UNKNOWN")
    if status in ("DNS_FAILURE", "UNREACHABLE") and not raw.get("tls_supported", False) and not raw.get("http_available", False):
        return None, f"UNREACHABLE_HOST: status={status}"

    norm = dict(raw)
    norm["normalized_domain"] = ascii_domain
    norm["registrable_domain"] = fld.lower()

    # Type casting and sanity checks
    norm["url_length"] = int(norm.get("url_length", len(ascii_domain) + 8))
    norm["subdomain_count"] = max(0, len(ascii_domain.split(".")) - len(fld.split(".")))
    norm["is_idn"] = ascii_domain.startswith("xn--") or (ascii_domain != raw_domain)
    norm["is_ip_host"] = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ascii_domain))

    # Clean strings and ensure nulls are not arbitrary strings
    for k in [
        "tls_version", "tls_cipher", "tls_cert_not_before", "tls_cert_not_after",
        "tls_cert_issuer", "tls_cert_subject", "tls_cert_sig_alg", "final_scheme",
        "header_xfo_value", "header_referrer_policy_value", "server_header"
    ]:
        val = norm.get(k)
        if val is not None:
            norm[k] = str(val).strip() if str(val).strip() != "" else None
        else:
            norm[k] = None

    # Redact sensitive parameters or credentials from server header or values
    if norm.get("server_header"):
        norm["server_header"] = re.sub(r"(token|secret|password|auth|bearer)=[^;\s]+", "[REDACTED]", norm["server_header"], flags=re.I)

    # Boolean sanity
    for bool_key in [
        "domain_resolved", "dns_has_ipv4", "dns_has_ipv6", "dns_has_caa",
        "tls_supported", "tls_cert_valid", "tls_cert_expired", "tls_cert_is_self_signed",
        "tls_cert_hostname_match", "http_available", "https_available", "http_to_https_redirect",
        "https_downgrade", "header_hsts_present", "header_hsts_include_subdomains", "header_hsts_preload",
        "header_csp_present", "header_csp_unsafe_inline", "header_csp_unsafe_eval",
        "header_xfo_present", "header_xcto_present", "header_referrer_policy_present",
        "header_permissions_policy_present", "header_coop_present", "header_corp_present",
        "header_coep_present", "cookie_all_secure", "cookie_all_httponly", "server_version_exposed",
        "x_powered_by_present"
    ]:
        norm[bool_key] = bool(norm.get(bool_key, False))

    # Integer sanity
    for int_key in [
        "tls_cert_san_count", "redirect_count", "cookie_count", "cookie_secure_count",
        "cookie_httponly_count", "cookie_samesite_strict_count", "cookie_samesite_lax_count",
        "cookie_samesite_none_count"
    ]:
        norm[int_key] = int(norm.get(int_key, 0))

    if norm.get("tls_cert_remaining_days") is not None:
        try:
            norm["tls_cert_remaining_days"] = int(norm["tls_cert_remaining_days"])
        except (ValueError, TypeError):
            norm["tls_cert_remaining_days"] = None

    if norm.get("header_hsts_max_age") is not None:
        try:
            norm["header_hsts_max_age"] = int(norm["header_hsts_max_age"])
        except (ValueError, TypeError):
            norm["header_hsts_max_age"] = None

    if norm.get("final_status_code") is not None:
        try:
            norm["final_status_code"] = int(norm["final_status_code"])
        except (ValueError, TypeError):
            norm["final_status_code"] = None

    return norm, None


def run_normalization(config_path: Optional[str] = None) -> List[Dict[str, Any]]:
    config = load_config(config_path)
    raw_file = BASE_DIR / config["paths"]["raw_dir"] / "raw_observations.jsonl"
    if not raw_file.exists():
        raise FileNotFoundError(f"Raw observations file not found: {raw_file}")

    normalized_records: List[Dict[str, Any]] = []
    exclusions: List[Dict[str, str]] = []

    logger.info(f"Reading raw observations from {raw_file}...")
    with open(raw_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw_data = json.loads(line)
                norm, reason = normalize_record(raw_data)
                if norm is not None:
                    normalized_records.append(norm)
                else:
                    exclusions.append({
                        "domain": raw_data.get("normalized_domain", "UNKNOWN"),
                        "reason": reason,
                        "line": line_num,
                    })
            except Exception as e:
                exclusions.append({
                    "domain": "MALFORMED_JSON",
                    "reason": f"JSON_PARSE_ERROR: {str(e)}",
                    "line": line_num,
                })

    logger.info(f"Normalization complete: {len(normalized_records)} accepted, {len(exclusions)} excluded.")

    # Save exclusion report
    excl_path = BASE_DIR / config["paths"]["metadata_dir"] / "exclusion_report.json"
    with open(excl_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_raw": len(normalized_records) + len(exclusions),
            "total_accepted": len(normalized_records),
            "total_excluded": len(exclusions),
            "reasons_breakdown": pd.Series([e["reason"].split(":")[0] for e in exclusions]).value_counts().to_dict(),
            "sample_exclusions": exclusions[:50],
        }, f, indent=2)
    logger.info(f"Wrote exclusion report to {excl_path}")

    return normalized_records


def main():
    parser = argparse.ArgumentParser(description="TrustLens Normalization Engine")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    args = parser.parse_args()
    run_normalization(config_path=args.config)


if __name__ == "__main__":
    main()

