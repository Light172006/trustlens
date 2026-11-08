"""
TrustLens Web Security Analyzer - High-Throughput Async Data Collection Engine
Non-intrusive, fully asynchronous web security telemetry collector for real-world domains.
"""

import argparse
import asyncio
import csv
import datetime
import hashlib
import io
import json
import logging
import re
import socket
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from tld import get_fld
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("web_security_collector")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(BASE_DIR / "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def download_tranco_domains(config: Dict[str, Any], pool_size: int = 20000) -> List[Tuple[int, str]]:
    raw_dir = BASE_DIR / config["paths"]["raw_dir"]
    raw_dir.mkdir(parents=True, exist_ok=True)
    cache_path = BASE_DIR / config["sources"]["tranco"]["cache_path"]

    if not cache_path.exists():
        url = config["sources"]["tranco"]["url"]
        logger.info(f"Downloading Tranco Top 1M list from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "TrustLens-Research/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read()
            with open(cache_path, "wb") as f:
                f.write(content)
        logger.info(f"Cached Tranco list at {cache_path} ({len(content)} bytes)")

    sampled_domains: List[Tuple[int, str]] = []
    seen_flds = set()

    with zipfile.ZipFile(cache_path, "r") as zf:
        csv_filename = zf.namelist()[0]
        with zf.open(csv_filename) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            for row in reader:
                if len(row) >= 2:
                    try:
                        rank = int(row[0])
                        domain = row[1].strip().lower()
                        fld = get_fld(domain, fix_protocol=True, fail_silently=True) or domain
                        if fld not in seen_flds:
                            seen_flds.add(fld)
                            sampled_domains.append((rank, domain))
                        if len(sampled_domains) >= pool_size:
                            break
                    except ValueError:
                        continue

    logger.info(f"Loaded {len(sampled_domains)} distinct candidate domains from Tranco pool.")
    return sampled_domains


def parse_cookie_attributes(cookie_headers: List[str]) -> Dict[str, Any]:
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


async def probe_domain(
    session: aiohttp.ClientSession,
    rank: int,
    domain: str,
    sem: asyncio.Semaphore,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    async with sem:
        scan_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        reg_domain = get_fld(domain, fix_protocol=True, fail_silently=True) or domain
        sample_id = hashlib.sha256(f"{reg_domain}:{scan_time}".encode()).hexdigest()[:24]

        record: Dict[str, Any] = {
            "sample_id": sample_id,
            "scan_timestamp": scan_time,
            "source_name": config["sources"]["tranco"]["name"],
            "source_reference": str(rank),
            "collection_method": "PASSIVE_PROBE",
            "collection_status": "UNKNOWN",
            "dataset_version": config["project"]["version"],
            "normalized_domain": domain,
            "registrable_domain": reg_domain,
            "url_scheme": "https",
            "url_length": len(domain) + 8,
            "subdomain_count": max(0, len(domain.split(".")) - len(reg_domain.split("."))),
            "is_idn": domain.startswith("xn--") or any(ord(c) > 127 for c in domain),
            "is_ip_host": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)),
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

        headers_dict: Dict[str, str] = {}
        cookie_headers: List[str] = []
        timeout = aiohttp.ClientTimeout(total=2.5, connect=1.8)

        # 1. Probe HTTPS
        try:
            async with session.get(
                f"https://{domain}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": config["collection"]["user_agent"]},
            ) as resp:
                record["https_available"] = True
                record["domain_resolved"] = True
                record["final_status_code"] = resp.status
                record["final_scheme"] = resp.url.scheme
                record["redirect_count"] = len(resp.history)

                # Peer address
                try:
                    peer = resp.connection.transport.get_extra_info("peername")
                    if peer:
                        ip = peer[0]
                        if ":" in ip:
                            record["dns_has_ipv6"] = True
                        else:
                            record["dns_has_ipv4"] = True
                            record["dns_ipv4_addresses"] = [ip]
                except Exception:
                    pass

                # SSL Object
                try:
                    sslobj = resp.connection.transport.get_extra_info("ssl_object")
                    if sslobj:
                        record["tls_supported"] = True
                        record["tls_version"] = sslobj.version()
                        cipher_info = sslobj.cipher()
                        if cipher_info:
                            record["tls_cipher"] = cipher_info[0]

                        der = sslobj.getpeercert(binary_form=True)
                        if der:
                            cert = x509.load_der_x509_certificate(der)
                            now = datetime.datetime.now(datetime.timezone.utc)
                            not_before = cert.not_valid_before_utc
                            not_after = cert.not_valid_after_utc

                            record["tls_cert_not_before"] = not_before.isoformat()
                            record["tls_cert_not_after"] = not_after.isoformat()
                            record["tls_cert_expired"] = now > not_after
                            record["tls_cert_valid"] = (not_before <= now <= not_after)
                            record["tls_cert_remaining_days"] = int((not_after - now).total_seconds() // 86400)

                            issuer_str = cert.issuer.rfc4514_string()
                            subject_str = cert.subject.rfc4514_string()
                            record["tls_cert_issuer"] = issuer_str
                            record["tls_cert_subject"] = subject_str
                            record["tls_cert_is_self_signed"] = (issuer_str == subject_str)
                            record["tls_cert_sig_alg"] = cert.signature_algorithm_oid._name

                            try:
                                pk = cert.public_key()
                                if hasattr(pk, "key_size"):
                                    record["tls_cert_key_size"] = pk.key_size
                            except Exception:
                                pass

                            sans = []
                            try:
                                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                for name in san_ext.value:
                                    val = getattr(name, "value", str(name))
                                    sans.append(str(val).lower())
                            except Exception:
                                pass
                            record["tls_cert_san_count"] = len(sans)
                            record["tls_cert_sans"] = sans[:20]

                            # Hostname match check
                            match = False
                            clean_host = domain.lower()
                            for san in sans:
                                if san == clean_host:
                                    match = True
                                    break
                                if san.startswith("*.") and clean_host.endswith(san[1:]):
                                    match = True
                                    break
                            if not match and f"cn={clean_host}" in subject_str.lower():
                                match = True
                            record["tls_cert_hostname_match"] = match
                except Exception:
                    pass

                # Check downgrade
                for h in resp.history:
                    if h.url.scheme == "https" and resp.url.scheme == "http":
                        record["https_downgrade"] = True

                for k, v in resp.headers.items():
                    headers_dict[k.lower()] = v
                cookie_headers = resp.headers.getall("Set-Cookie", [])
        except Exception:
            pass

        # 2. Probe HTTP (for redirect behavior)
        try:
            async with session.get(
                f"http://{domain}",
                timeout=aiohttp.ClientTimeout(total=2.0, connect=1.5),
                allow_redirects=False,
                headers={"User-Agent": config["collection"]["user_agent"]},
            ) as resp_http:
                record["http_available"] = True
                record["domain_resolved"] = True
                if resp_http.status in (301, 302, 307, 308):
                    loc = resp_http.headers.get("Location", "")
                    if loc.startswith("https://"):
                        record["http_to_https_redirect"] = True
        except Exception:
            pass

        # Parse headers and cookies
        if headers_dict:
            record.update(parse_hsts_header(headers_dict.get("strict-transport-security")))
            record.update(parse_csp_header(headers_dict.get("content-security-policy")))
            record.update(parse_cookie_attributes(cookie_headers))

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

            record.update({
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

        if record["https_available"] or record["http_available"]:
            record["collection_status"] = "SUCCESS"
        elif record["tls_supported"]:
            record["collection_status"] = "PARTIAL"
        elif not record["domain_resolved"]:
            record["collection_status"] = "DNS_FAILURE"
        else:
            record["collection_status"] = "UNREACHABLE"

        return record


async def run_collector(
    target_count: int = 10600,
    concurrency: int = 150,
    config_path: Optional[str] = None,
) -> None:
    config = load_config(config_path)
    raw_dir = BASE_DIR / config["paths"]["raw_dir"]
    raw_dir.mkdir(parents=True, exist_ok=True)

    pool_size = max(target_count + 6000, 20000)
    domains_pool = download_tranco_domains(config, pool_size=pool_size)

    checkpoint_file = raw_dir / "raw_observations.jsonl"
    existing_domains = set()
    total_valid = 0

    if checkpoint_file.exists():
        with open(checkpoint_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        row = json.loads(line)
                        existing_domains.add(row.get("normalized_domain"))
                        if row.get("collection_status") == "SUCCESS":
                            total_valid += 1
                    except Exception:
                        pass
        logger.info(f"Resume: Found {len(existing_domains)} records ({total_valid} valid).")

    remaining_pool = [d for d in domains_pool if d[1] not in existing_domains]
    logger.info(f"Remaining candidates to process: {len(remaining_pool)} | Target valid: {target_count}")

    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(
        limit=concurrency + 50,
        ssl=False,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )

    t0 = time.time()
    total_processed = len(existing_domains)
    checkpoint_fp = open(checkpoint_file, "a", encoding="utf-8")
    batch_size = 300

    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(remaining_pool), batch_size):
            batch = remaining_pool[i : i + batch_size]
            t_batch_0 = time.time()
            tasks = [probe_domain(session, r, d, sem, config) for r, d in batch]
            results = await asyncio.gather(*tasks)

            for rec in results:
                checkpoint_fp.write(json.dumps(rec) + "\n")
                if rec["collection_status"] == "SUCCESS":
                    total_valid += 1

            checkpoint_fp.flush()
            total_processed += len(results)
            b_elapsed = time.time() - t_batch_0
            total_elapsed = time.time() - t0
            b_rate = len(results) / (b_elapsed + 0.001)

            logger.info(
                f"Batch {i//batch_size + 1}: {len(results)} dom in {b_elapsed:.1f}s ({b_rate:.1f} dom/s) | "
                f"Total Processed: {total_processed} | Valid: {total_valid}/{target_count} | Total Time: {total_elapsed:.1f}s"
            )

            if total_valid >= target_count:
                logger.info(f"Target of {target_count} valid domains achieved! Finishing collection.")
                break

    checkpoint_fp.close()
    elapsed_total = time.time() - t0
    logger.info(f"Collection complete: {total_processed} processed, {total_valid} valid in {elapsed_total:.2f}s.")

    report = {
        "report_version": "1.0.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_attempted": total_processed,
        "total_successful": total_valid,
        "elapsed_seconds": round(elapsed_total, 2),
        "concurrency": concurrency,
        "output_file": str(checkpoint_file),
    }
    report_path = BASE_DIR / config["paths"]["collection_report_json"]
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Wrote collection report to {report_path}")


def main():
    parser = argparse.ArgumentParser(description="TrustLens Web Security Collector")
    parser.add_argument("--target", type=int, default=10600, help="Target valid domains")
    parser.add_argument("--concurrency", type=int, default=150, help="Concurrency limit")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    args = parser.parse_args()

    asyncio.run(run_collector(target_count=args.target, concurrency=args.concurrency, config_path=args.config))


if __name__ == "__main__":
    main()
