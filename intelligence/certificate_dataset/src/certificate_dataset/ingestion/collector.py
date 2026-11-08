"""Comprehensive ingestion engine for CT logs, Root Stores, TLS endpoints, and revocation."""

from __future__ import annotations

import base64
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import re
import socket
import ssl
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.request
import uuid

import sys

# Ensure isolated .deps is available
_DEPS_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

import certifi
from cryptography import x509

from certificate_dataset.chains.builder import ChainBuilder
from certificate_dataset.labeling.labeler import CertificateLabeler
from certificate_dataset.normalization.canonicalizer import Canonicalizer
from certificate_dataset.parsing.parser import X509CertificateParser
from certificate_dataset.revocation.collector import RevocationCollector
from certificate_dataset.revocation.network_guard import NetworkSafetyGuard
from certificate_dataset.storage.store import DatasetStorage
from certificate_dataset.trust_stores.root_store import TrustStoreManager


class CertificateDatasetIngestionEngine:
    """Orchestrates genuine data ingestion across CT, Root Stores, and TLS Endpoints."""

    DEFAULT_ALLOWED_ENDPOINTS = [
        {"hostname": "google.com", "port": 443, "expected_ca": "Google Trust Services"},
        {"hostname": "cloudflare.com", "port": 443, "expected_ca": "Cloudflare / DigiCert"},
        {"hostname": "github.com", "port": 443, "expected_ca": "DigiCert"},
        {"hostname": "wikipedia.org", "port": 443, "expected_ca": "Let's Encrypt"},
        {"hostname": "microsoft.com", "port": 443, "expected_ca": "Microsoft Corporation"},
        {"hostname": "apple.com", "port": 443, "expected_ca": "Apple Inc."},
        {"hostname": "amazon.com", "port": 443, "expected_ca": "Amazon Trust Services"},
        {"hostname": "mozilla.org", "port": 443, "expected_ca": "Let's Encrypt"},
    ]

    def __init__(self, base_data_dir: Optional[Path] = None):
        self.storage = DatasetStorage(base_data_dir)
        self.trust_store = TrustStoreManager(self.storage.trust_stores_dir)
        self.chain_builder = ChainBuilder(self.trust_store)
        self.labeler = CertificateLabeler()

        # Ingest trust store roots into trust store manager and storage
        self.root_records: List[Dict[str, Any]] = []
        self._init_trust_store()

    def _init_trust_store(self) -> None:
        """Initializes Mozilla root store records."""
        self.root_records = self.trust_store.load_from_certifi()
        for r in self.root_records:
            der_bytes = base64.b64decode(r["der_base64"])
            self.chain_builder.register_der_bytes(der_bytes)

    def ingest_mozilla_root_store(self) -> List[Dict[str, Any]]:
        """Parses and normalizes Mozilla CCADB root store certificates into canonical records."""
        records: List[Dict[str, Any]] = []
        now_utc = datetime.now(timezone.utc).isoformat()

        bundle_path = certifi.where()
        with open(bundle_path, "r", encoding="utf-8") as f:
            text = f.read()

        pem_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            text,
            re.DOTALL,
        )

        for pem in pem_blocks:
            try:
                rec = X509CertificateParser.parse(
                    cert_bytes=pem.encode("ascii"),
                    source_name="mozilla_ccadb_root_store",
                    observation_timestamp=now_utc,
                    data_origin="REAL_WORLD_PRODUCTION",
                )
                rec = Canonicalizer.normalize_record(rec)
                records.append(rec)
                # Persist raw DER blob
                der_bytes = base64.b64decode(rec["der_base64"])
                self.storage.save_raw_der(der_bytes, rec["sha256_fingerprint"])
            except Exception:
                continue

        return records

    def ingest_ct_log(
        self,
        log_url: str = "https://ct.googleapis.com/logs/us1/argon2026h2/",
        source_id: str = "google_ct_argon_2026",
        start_index: int = 0,
        count: int = 20,
    ) -> List[Dict[str, Any]]:
        """Ingests entries from an RFC 6962 CT log and extracts valid certificates/precertificates."""
        url = f"{log_url.rstrip('/')}/ct/v1/get-entries?start={start_index}&end={start_index + count - 1}"
        records: List[Dict[str, Any]] = []

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TrustLens-PKI-Ingest/1.0"})
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception:
            # If network error or rate limit, return empty list gracefully
            return records

        entries = data.get("entries", [])

        for idx, entry in enumerate(entries):
            try:
                leaf_b64 = entry.get("leaf_input")
                extra_b64 = entry.get("extra_data")
                if not leaf_b64:
                    continue

                leaf_bytes = base64.b64decode(leaf_b64)
                # Parse MerkleTreeLeaf header (RFC 6962 Section 3.4)
                # v(1), leaf_type(1), timestamp(8), entry_type(2)
                if len(leaf_bytes) < 12:
                    continue
                ts = struct.unpack(">Q", leaf_bytes[2:10])[0]
                entry_type = struct.unpack(">H", leaf_bytes[10:12])[0]
                sct_time = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc).isoformat()

                cert_der = None
                is_precert = (entry_type == 1)

                if entry_type == 0:  # x509_entry
                    cert_len = struct.unpack(">I", b"\x00" + leaf_bytes[12:15])[0]
                    cert_der = leaf_bytes[15 : 15 + cert_len]
                elif entry_type == 1 and extra_b64:  # precert_entry
                    extra_bytes = base64.b64decode(extra_b64)
                    if len(extra_bytes) > 3:
                        cert_len = struct.unpack(">I", b"\x00" + extra_bytes[:3])[0]
                        cert_der = extra_bytes[3 : 3 + cert_len]

                if cert_der:
                    rec = X509CertificateParser.parse(
                        cert_bytes=cert_der,
                        source_name=source_id,
                        source_record_id=f"{start_index + idx}",
                        observation_timestamp=sct_time,
                        data_origin="REAL_WORLD_PRODUCTION",
                        is_precertificate=is_precert,
                    )
                    rec["transparency"]["ct_log_id"] = source_id
                    rec["transparency"]["ct_entry_index"] = start_index + idx
                    rec["transparency"]["sct_timestamp"] = sct_time
                    rec["transparency"]["entry_type"] = "PRECERTIFICATE" if is_precert else "CERTIFICATE"

                    rec = Canonicalizer.normalize_record(rec)
                    records.append(rec)
                    self.storage.save_raw_der(cert_der, rec["sha256_fingerprint"])
            except Exception as ex:
                self.storage.quarantine_failed_record(
                    raw_input=base64.b64decode(entry.get("leaf_input", "")),
                    error_message=str(ex),
                    identifier=f"ct_{source_id}_{start_index + idx}",
                )

        return records

    def ingest_ct_corpus_distributed(
        self,
        target_leaf_count: int = 10050,
        max_workers: int = 12,
        progress_interval: int = 1000,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Collects 10,000+ authentic leaf certificates from diverse RFC 6962 CT logs.

        Returns:
            Tuple of (leaf_records, intermediate_records, precertificate_records)
        """
        print(f"      [Ingest] Initiating distributed CT crawl targeting {target_leaf_count:,} unique leaf certificates...")
        t_start = time.time()

        log_configs = [
            {
                "source_id": "sectigo_elephant_2026",
                "base_url": "https://elephant2026h2.ct.sectigo.com/ct/v1/get-entries",
                "offsets": [0, 2000, 5000, 10000, 20000, 40000, 70000, 120000, 200000, 350000, 550000, 800000, 1200000, 1800000, 2500000],
                "batches_per_window": 30,
            },
            {
                "source_id": "digicert_wyvern_2026",
                "base_url": "https://wyvern.ct.digicert.com/2026h2/ct/v1/get-entries",
                "offsets": [0, 2000, 5000, 15000, 35000, 80000, 150000, 300000, 500000, 800000, 1200000, 1800000],
                "batches_per_window": 25,
            },
            {
                "source_id": "digicert_sphinx_2026",
                "base_url": "https://sphinx.ct.digicert.com/2026h2/ct/v1/get-entries",
                "offsets": [0, 2000, 5000, 15000, 35000, 80000, 150000, 300000, 500000, 800000, 1200000],
                "batches_per_window": 25,
            },
            {
                "source_id": "google_ct_xenon_2026",
                "base_url": "https://ct.googleapis.com/logs/eu1/xenon2026h2/ct/v1/get-entries",
                "offsets": [0, 2000, 5000, 15000, 35000, 80000, 150000, 300000, 500000, 800000, 1200000],
                "batches_per_window": 20,
            },
            {
                "source_id": "google_ct_argon_2026",
                "base_url": "https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1/get-entries",
                "offsets": [0, 2000, 5000, 15000, 35000, 80000, 150000, 300000, 500000, 800000, 1200000],
                "batches_per_window": 20,
            },
            {
                "source_id": "cloudflare_ct_nimbus_2026",
                "base_url": "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-entries",
                "offsets": [0, 5000, 25000, 100000, 300000, 600000, 1000000],
                "batches_per_window": 15,
            },
        ]

        # Flatten and interleave batch tasks across sources
        source_task_queues: Dict[str, List[Tuple[str, str, int]]] = {}
        for cfg in log_configs:
            s_id = cfg["source_id"]
            b_url = cfg["base_url"]
            source_task_queues[s_id] = []
            for base_off in cfg["offsets"]:
                for i in range(cfg["batches_per_window"]):
                    start = base_off + i * 32
                    source_task_queues[s_id].append((s_id, f"{b_url}?start={start}&end={start+31}", start))

        batch_tasks: List[Tuple[str, str, int]] = []
        idx = 0
        while any(idx < len(q) for q in source_task_queues.values()):
            for s_id, q in source_task_queues.items():
                if idx < len(q):
                    batch_tasks.append(q[idx])
            idx += 1

        leaf_records: List[Dict[str, Any]] = []
        intermediate_records: List[Dict[str, Any]] = []
        precert_records: List[Dict[str, Any]] = []
        seen_fingerprints: Set[str] = set()
        seen_intermediates: Set[str] = set()
        seen_precerts: Set[str] = set()

        def fetch_batch_with_retry(task: Tuple[str, str, int]) -> Tuple[str, int, List[Dict[str, Any]]]:
            src_id, url, start_idx = task
            req = urllib.request.Request(url, headers={"User-Agent": "TrustLens-PKI-Ingest/1.0"})
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=12.0) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        return src_id, start_idx, data.get("entries", [])
                except urllib.error.HTTPError as he:
                    if he.code == 429:
                        time.sleep(1.0 + random.uniform(0.5, 1.5))
                    else:
                        break
                except Exception:
                    time.sleep(0.5)
            return src_id, start_idx, []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {
                executor.submit(fetch_batch_with_retry, task): task
                for task in batch_tasks[: max_workers * 2]
            }
            task_idx = max_workers * 2

            while future_to_task:
                done, _ = concurrent.futures.wait(
                    future_to_task.keys(),
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )

                for fut in done:
                    src_id, start_idx, entries = fut.result()
                    del future_to_task[fut]

                    if len(leaf_records) < target_leaf_count and task_idx < len(batch_tasks):
                        next_task = batch_tasks[task_idx]
                        task_idx += 1
                        future_to_task[executor.submit(fetch_batch_with_retry, next_task)] = next_task

                    for idx, entry in enumerate(entries):
                        try:
                            leaf_b64 = entry.get("leaf_input")
                            extra_b64 = entry.get("extra_data")
                            if not leaf_b64:
                                continue
                            leaf_bytes = base64.b64decode(leaf_b64)
                            if len(leaf_bytes) < 12:
                                continue
                            ts = struct.unpack(">Q", leaf_bytes[2:10])[0]
                            entry_type = struct.unpack(">H", leaf_bytes[10:12])[0]
                            sct_time = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc).isoformat()

                            if entry_type == 0:  # x509_entry (Final leaf certificate)
                                cert_len = struct.unpack(">I", b"\x00" + leaf_bytes[12:15])[0]
                                cert_der = leaf_bytes[15 : 15 + cert_len]
                                fp = hashlib.sha256(cert_der).hexdigest()
                                if fp not in seen_fingerprints:
                                    seen_fingerprints.add(fp)
                                    rec = X509CertificateParser.parse(
                                        cert_bytes=cert_der,
                                        source_name=src_id,
                                        source_record_id=f"{start_idx + idx}",
                                        observation_timestamp=sct_time,
                                        data_origin="REAL_WORLD_PRODUCTION",
                                        is_precertificate=False,
                                    )
                                    rec["transparency"]["ct_log_id"] = src_id
                                    rec["transparency"]["ct_entry_index"] = start_idx + idx
                                    rec["transparency"]["sct_timestamp"] = sct_time
                                    rec["transparency"]["entry_type"] = "CERTIFICATE"
                                    rec = Canonicalizer.normalize_record(rec)

                                    if rec.get("certificate_type") == "LEAF" or not rec.get("is_ca", False):
                                        leaf_records.append(rec)
                                        self.storage.save_raw_der(cert_der, fp)
                                        if len(leaf_records) % progress_interval == 0:
                                            elapsed = time.time() - t_start
                                            rate = len(leaf_records) / elapsed if elapsed > 0 else 0
                                            print(f"      [Ingest Progress] {len(leaf_records):,}/{target_leaf_count:,} unique leaves | Rate: {rate:.1f} leaves/sec | Intermediates: {len(intermediate_records)}")
                                    else:
                                        if fp not in seen_intermediates:
                                            seen_intermediates.add(fp)
                                            intermediate_records.append(rec)
                                            self.storage.save_raw_der(cert_der, fp)
                                            self.chain_builder.register_der_bytes(cert_der)

                            elif entry_type == 1 and extra_b64:  # Precertificate entry
                                extra_bytes = base64.b64decode(extra_b64)
                                if len(extra_bytes) > 3:
                                    cert_len = struct.unpack(">I", b"\x00" + extra_bytes[:3])[0]
                                    cert_der = extra_bytes[3 : 3 + cert_len]
                                    fp = hashlib.sha256(cert_der).hexdigest()
                                    if fp not in seen_precerts and fp not in seen_fingerprints:
                                        seen_precerts.add(fp)
                                        rec = X509CertificateParser.parse(
                                            cert_bytes=cert_der,
                                            source_name=src_id,
                                            source_record_id=f"{start_idx + idx}",
                                            observation_timestamp=sct_time,
                                            data_origin="REAL_WORLD_PRODUCTION",
                                            is_precertificate=True,
                                        )
                                        rec["transparency"]["ct_log_id"] = src_id
                                        rec["transparency"]["ct_entry_index"] = start_idx + idx
                                        rec["transparency"]["sct_timestamp"] = sct_time
                                        rec["transparency"]["entry_type"] = "PRECERTIFICATE"
                                        rec = Canonicalizer.normalize_record(rec)
                                        precert_records.append(rec)
                                        self.storage.save_raw_der(cert_der, fp)

                            # Extract intermediate chain from extra_data
                            if extra_b64:
                                extra_raw = base64.b64decode(extra_b64)
                                if len(extra_raw) > 3:
                                    offset = 3 if entry_type == 0 else 3 + struct.unpack(">I", b"\x00" + extra_raw[:3])[0]
                                    while offset < len(extra_raw):
                                        if offset + 3 > len(extra_raw):
                                            break
                                        clen = struct.unpack(">I", b"\x00" + extra_raw[offset : offset + 3])[0]
                                        offset += 3
                                        if offset + clen > len(extra_raw):
                                            break
                                        inter_der = extra_raw[offset : offset + clen]
                                        offset += clen
                                        inter_fp = hashlib.sha256(inter_der).hexdigest()
                                        if inter_fp not in seen_intermediates and inter_fp not in seen_fingerprints:
                                            seen_intermediates.add(inter_fp)
                                            try:
                                                inter_rec = X509CertificateParser.parse(
                                                    cert_bytes=inter_der,
                                                    source_name=f"{src_id}_intermediate",
                                                    observation_timestamp=sct_time,
                                                    data_origin="REAL_WORLD_PRODUCTION",
                                                )
                                                inter_rec = Canonicalizer.normalize_record(inter_rec)
                                                intermediate_records.append(inter_rec)
                                                self.storage.save_raw_der(inter_der, inter_fp)
                                                self.chain_builder.register_der_bytes(inter_der)
                                            except Exception:
                                                pass
                        except Exception:
                            pass

                if len(leaf_records) >= target_leaf_count:
                    for f in future_to_task:
                        f.cancel()
                    break

        dur = time.time() - t_start
        print(f"      [Ingest Complete] Collected {len(leaf_records):,} unique leaf certificates, {len(intermediate_records):,} intermediates, {len(precert_records):,} precertificates in {dur:.2f}s ({len(leaf_records)/dur:.1f} leaves/sec)")
        return leaf_records, intermediate_records, precert_records

    def ingest_endpoint_tls_observations(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Collects genuine TLS endpoint observations, parses certs, builds chains, and labels."""
        if endpoints is None:
            endpoints = self.DEFAULT_ALLOWED_ENDPOINTS

        cert_records: List[Dict[str, Any]] = []
        obs_records: List[Dict[str, Any]] = []
        chain_records: List[Dict[str, Any]] = []
        label_records: List[Dict[str, Any]] = []

        now_utc = datetime.now(timezone.utc)
        now_utc_str = now_utc.isoformat()

        for ep in endpoints:
            hostname = ep["hostname"]
            port = ep.get("port", 443)

            obs_id = str(uuid.uuid4())
            try:
                # Validate hostname and destination IP
                _, resolved_ips = NetworkSafetyGuard.validate_url(f"https://{hostname}:{port}")

                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
                s.settimeout(5.0)
                s.connect((hostname, port))

                peer_der = s.getpeercert(binary_form=True)
                tls_version = s.version() or "TLSv1.3"
                cipher_info = s.cipher()
                cipher_suite = cipher_info[0] if cipher_info else "UNKNOWN"
                alpn = s.selected_alpn_protocol()

                s.close()

                # Parse leaf certificate
                leaf_rec = X509CertificateParser.parse(
                    cert_bytes=peer_der,
                    source_name=f"tls_endpoint_observation_{hostname}",
                    source_record_id=obs_id,
                    observation_timestamp=now_utc_str,
                    data_origin="REAL_WORLD_PRODUCTION",
                )
                leaf_rec = Canonicalizer.normalize_record(leaf_rec)
                cert_records.append(leaf_rec)
                self.storage.save_raw_der(peer_der, leaf_rec["sha256_fingerprint"])

                # Build chain
                leaf_cert_obj = x509.load_der_x509_certificate(peer_der)
                # Try fetching intermediate via AIA caIssuers if available
                intermediate_fps: List[str] = []
                ca_issuers_urls = leaf_rec.get("extensions", {}).get("authority_information_access", {}).get("ca_issuers_urls", [])
                for aia_url in ca_issuers_urls:
                    try:
                        NetworkSafetyGuard.validate_url(aia_url)
                        req = urllib.request.Request(aia_url, headers={"User-Agent": "TrustLens-PKI-Ingest/1.0"})
                        with urllib.request.urlopen(req, timeout=5.0) as resp:
                            inter_der = resp.read()
                            inter_rec = X509CertificateParser.parse(
                                cert_bytes=inter_der,
                                source_name=f"aia_intermediate_{hostname}",
                                observation_timestamp=now_utc_str,
                                data_origin="REAL_WORLD_PRODUCTION",
                            )
                            inter_rec = Canonicalizer.normalize_record(inter_rec)
                            cert_records.append(inter_rec)
                            self.storage.save_raw_der(inter_der, inter_rec["sha256_fingerprint"])
                            self.chain_builder.register_der_bytes(inter_der)
                            intermediate_fps.append(inter_rec["sha256_fingerprint"])
                    except Exception:
                        pass

                chain_result = self.chain_builder.build_chain(
                    leaf_cert=leaf_cert_obj,
                    reference_time=now_utc,
                    store_name="MOZILLA",
                )
                chain_records.append(chain_result)

                # Check hostname match
                host_clean, _ = Canonicalizer.normalize_domain(hostname)
                sans = leaf_rec.get("domain_identity", {}).get("subject_alternative_names", [])
                matched_host = any(CertificateLabeler._match_hostname(host_clean, san) for san in sans)
                host_val_res = "MATCH" if matched_host else "MISMATCH"

                # Map chain verification to endpoint status
                chain_val_status = "VALID_TRUSTED" if chain_result["validation_result"] == "VALID_TRUSTED" else "UNTRUSTED_ROOT"
                if chain_result["validation_result"] == "INCOMPLETE_CHAIN":
                    chain_val_status = "INCOMPLETE_CHAIN"

                obs: Dict[str, Any] = {
                    "observation_id": obs_id,
                    "hostname": hostname,
                    "port": port,
                    "sni_hostname": hostname,
                    "observation_timestamp": now_utc_str,
                    "leaf_certificate_fingerprint": leaf_rec["sha256_fingerprint"],
                    "presented_intermediate_fingerprints": intermediate_fps,
                    "tls_protocol_version": tls_version,
                    "negotiated_cipher_suite": cipher_suite,
                    "alpn_protocol": alpn,
                    "hostname_verification_result": host_val_res,
                    "chain_verification_result": chain_val_status,
                    "verification_error_codes": chain_result.get("validation_errors", []),
                    "trust_store_identifier": "MOZILLA",
                    "trust_store_version": self.trust_store.DEFAULT_STORE_VERSION,
                    "verification_library_and_version": f"Python ssl OpenSSL/{ssl.OPENSSL_VERSION}",
                    "handshake_status": "SUCCESS",
                    "observation_source": "controlled_endpoint_tls_handshake",
                    "collection_method": "TLS_SOCKET_CONNECT_AND_PEERCERT",
                }
                obs_records.append(obs)

                # Generate label evaluation
                rev_obs = RevocationCollector.create_not_checked_observation(
                    certificate_fp=leaf_rec["sha256_fingerprint"],
                    serial_number=leaf_rec["serial_number"],
                    issuer_dn=leaf_rec["issuer_dn"],
                )
                label_res = self.labeler.evaluate(
                    cert_record=leaf_rec,
                    reference_time=now_utc,
                    target_hostname=hostname,
                    chain_record=chain_result,
                    revocation_record=rev_obs,
                )
                label_records.append(label_res)

            except Exception as e:
                # Record failed handshake observation
                obs_fail: Dict[str, Any] = {
                    "observation_id": obs_id,
                    "hostname": hostname,
                    "port": port,
                    "sni_hostname": hostname,
                    "observation_timestamp": now_utc_str,
                    "leaf_certificate_fingerprint": "0" * 64,
                    "presented_intermediate_fingerprints": [],
                    "tls_protocol_version": "UNKNOWN",
                    "negotiated_cipher_suite": "NONE",
                    "alpn_protocol": None,
                    "hostname_verification_result": "ERROR",
                    "chain_verification_result": "ERROR",
                    "verification_error_codes": [str(e)],
                    "trust_store_identifier": "MOZILLA",
                    "trust_store_version": self.trust_store.DEFAULT_STORE_VERSION,
                    "verification_library_and_version": f"Python ssl OpenSSL/{ssl.OPENSSL_VERSION}",
                    "handshake_status": "FAILED_HANDSHAKE",
                    "observation_source": "controlled_endpoint_tls_handshake",
                    "collection_method": "TLS_SOCKET_CONNECT_AND_PEERCERT",
                }
                obs_records.append(obs_fail)

        return cert_records, obs_records, chain_records, label_records

