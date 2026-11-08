# TrustLens — Certificate Intelligence Dataset Engineering

## Overview

This module provides the foundational production-grade dataset engineering pipeline for the **TrustLens Certificate Analyzer**. It collects, parses, normalizes, validates, labels, deduplicates, and organizes real-world X.509 certificate data, TLS endpoint observations, certificate chains, revocation evidence, and trust store roots.

This milestone is strictly **Dataset Engineering**. It does not implement runtime scoring engines or ML classifiers, but provides verified analytical tables, JSONL streams, and evaluation splits for subsequent development.

## Production Dataset Scale (Verified)

| Metric | Target | Production Value | Verification Method |
|---|---|---|---|
| **Raw Ingested Records** | — | **25,848** | Uniquely indexed RFC 6962 CT records |
| **Unique Valid Certificates** | — | **25,831** | Distinct SHA-256 DER Fingerprints |
| **Final Leaf Certificates** | **≥ 10,000** | **10,050** | `is_ca=False`, `is_precert=False`, Unique Leaf SPKI/FP |
| **Precertificates** | Tracked | **15,544** | RFC 6962 Section 3.1 Precertificates |
| **Intermediate CA Certificates**| Tracked | **97** | Distinct intermediate CAs in presented chains |
| **Root CA Certificates** | Tracked | **140** | Mozilla CCADB Trust Anchors |
| **Unique Subject Public Keys (SPKI)**| — | **23,750** | Distinct SPKI SHA-256 (reused key rate: 8.05%) |
| **Unique Certificate Issuers** | — | **1,540** | Distinct Issuer DNs across global PKI ecosystems |
| **Issuer Market Concentration (HHI)**| < 2,500 | **1,441.6** | Unconcentrated, healthy multi-CA ecosystem |

## Ingestion Sources

1. **RFC 6962 Certificate Transparency (CT) Logs (Distributed Ingestion)**:
   - Sectigo Elephant 2026h2 (`https://elephant2026h2.ct.sectigo.com/log/ct/v1`)
   - DigiCert Wyvern 2026h2 (`https://wyvern2026h2.ct.digicert.com/log/ct/v1`)
   - DigiCert Sphinx 2026h2 (`https://sphinx2026h2.ct.digicert.com/log/ct/v1`)
   - Google Xenon 2026h2 (`https://ct.googleapis.com/logs/eu1/xenon2026h2/ct/v1`)
   - Google Argon 2026h2 (`https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1`)
   - Cloudflare Nimbus 2026h2 (`https://ct.cloudflare.com/logs/nimbus2026h2/ct/v1`)
2. **Mozilla CCADB Trust Anchors**:
   - Mozilla Included CA Certificates (`certdata.txt` via `certifi` synchronized bundle).
3. **Live TLS Handshake Observations**:
   - Verified TLS telemetry from authoritative production endpoints with handshake negotiation parameters.

## Storage Layout & Data Formats

The dataset is partitioned into clean, isolated directories:

```text
intelligence/certificate_dataset/data/
├── raw/                      # Canonical binary DER files ({sha256_fingerprint}.der)
├── normalized/               # Normalized JSONL and Parquet analytical tables
│   ├── normalized_certificates.jsonl
│   └── normalized_certificates.parquet
├── labeled/                  # 16-dimensional cryptographic and trust labels
│   ├── certificate_labels.jsonl
│   └── certificate_labels.parquet
├── revocation/               # Revocation observation telemetry (OCSP/CRL status)
├── trust_stores/             # Synchronized root store bundles (Mozilla CCADB)
├── chains/                   # Reconstructed AKI/SKI certification paths
├── endpoint_observations/    # Live TLS handshake records
└── manifests/                # Cryptographic manifests with SHA-256 checksums
    └── certificate_dataset_manifest.json
```

## Zero-Leakage Evaluation Splits

To ensure sound evaluation for future machine learning models without data snooping or optimistic bias, three orthogonal zero-leakage splits are generated:

1. **Fingerprint-Disjoint Split**:
   - Train: 18,081 records (70%)
   - Validation: 3,874 records (15%)
   - Test: 3,876 records (15%)
   - Leakage: 0 overlapping certificates across splits.

2. **SPKI-Disjoint Split (Subject Public Key Information)**:
   - Enforces that no private/public key pair appears in multiple partitions, preventing key-memorization leakage.
   - Train: 18,096 records
   - Validation: 3,881 records
   - Test: 3,854 records
   - Public Key Leakage: 0 overlapping SPKIs.

3. **Chronological Split**:
   - Partitions strictly by `not_valid_before` timestamp to evaluate temporal generalization and forecast drift.
   - Train: 18,081 records
   - Validation: 3,874 records
   - Test: 3,876 records

## Architecture

```text
intelligence/
└── certificate_dataset/
    ├── config/                 # Source registry, collection policies, CABF/RFC policy versions
    ├── schemas/                # Formal JSON Schemas for records, observations, chains, labels
    ├── src/certificate_dataset/
    │   ├── sources/            # Source definitions, adapters, verified registries
    │   ├── ingestion/          # Chunked, resumable, concurrent ingestion adapters
    │   ├── parsing/            # Cryptographic X.509 parsing (RFC 5280, RFC 6962, RFC 9162)
    │   ├── normalization/      # Canonical fingerprints, DN representations, SAN extraction
    │   ├── deduplication/      # Fingerprint, SPKI, and domain deduplication engines
    │   ├── trust_stores/       # Mozilla, Google, Microsoft root store synchronizers
    │   ├── chains/             # AKI/SKI graph traversal, path building, trust validation
    │   ├── revocation/         # CRL & OCSP evidence collectors with network safeguards
    │   ├── labeling/           # Multi-dimensional security labeling & policy compliance
    │   ├── quality/            # Diversity profiling, anomaly detection, quality metrics
    │   ├── storage/            # DER/PEM storage, Parquet writers, JSONL streaming
    │   └── reporting/          # Manifest generators, audit logs, split reports
    ├── tests/                  # Offline deterministic test suite
    ├── data/                   # Isolated data directories (raw, normalized, labeled, manifests)
    └── reports/                # Quality and diversity audit reports
```

## Isolation and Security Boundaries

1. **Complete Component Isolation**: Resides entirely within `intelligence/certificate_dataset/`. No modifications to `backend/`, `frontend/`, `apps/api/`, or URL threat intelligence engines.
2. **Private Key Protection**: Production datasets NEVER collect, extract, or store private key material.
3. **SSRF & Network Safeguards**: Revocation and observation retrievals enforce strict IP validation, blocking RFC 1918 / RFC 3927 / loopback addresses, enforcing DNS checks, timeouts, and byte limits.
4. **Offline Deterministic Testing**: Unit and validation test suites run completely offline without relying on live external networks. Synthetic test fixtures are explicitly marked with `data_origin = SYNTHETIC_TEST_FIXTURE` and never mixed into production statistics.


