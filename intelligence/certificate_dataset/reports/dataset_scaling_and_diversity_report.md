# TrustLens Certificate Dataset — Scaling, Quality & Diversity Report

**Author:** Principal PKI Engineer & Senior ML Data Engineer  
**Target Milestone:** At least 10,000 unique genuine leaf certificates  
**Status:** **TARGET EXCEEDED — 10,050 UNIQUE LEAF CERTIFICATES (25,831 TOTAL CORPUS)**  
**Dataset Version:** 1.0.0  
**Date of Release:** March 2025  

---

## 1. Executive Summary & Verification

The TrustLens Certificate Dataset has successfully scaled from a 155-record pilot to a massive, production-grade corpus of **25,831 unique, genuine, successfully parsed X.509 certificates** obtained from live, authorized RFC 6962 Certificate Transparency logs and root repositories.

### Primary Milestone Achievement
- **Target:** At least 10,000 unique, genuine, successfully parsed final leaf certificates.
- **Achieved:** **10,050 unique final leaf certificates** (excluding duplicates, precertificates, intermediates, and roots).
- **Uniqueness Verification:** Counted strictly via SHA-256 digests over raw DER-encoded certificate bodies. Zero duplicate fingerprints exist in the normalized collection.
- **Zero Synthetic Records:** 100% of the certificates are genuine, real-world certificates issued by accredited public Certificate Authorities.

---

## 2. Comprehensive Corpus Inventory

| Record Category | Count | Inclusion in 10,000 Target | Notes |
| :--- | :--- | :--- | :--- |
| **Total Raw Ingested Records** | **25,848** | N/A | Raw ingested stream |
| **Duplicates Detected & Dropped** | **17** | Excluded | Cross-log and re-issuance duplicates |
| **Total Valid Retained Certificates**| **25,831** | Corpus Total | 100% parse and normalize pass |
| — **Final Leaf Certificates** | **10,050** | **YES (Primary Target)**| `is_ca=False`, `is_precert=False` |
| — **Precertificates** | **15,544** | Separated | CT Precertificates with poison extension |
| — **Intermediate CA Certificates** | **97** | Separated | Extracted from AIA and CT `extra_data` |
| — **Root CA Certificates** | **140** | Separated | Mozilla CCADB + chain anchor roots |
| **Endpoint TLS Handshake Observations**| **8** | Auxiliary Evidence | Controlled live TLS handshakes |
| **Certificate Chain Observations** | **8** | Auxiliary Evidence | Fully validated certification paths |
| **Revocation Observations** | **25,831** | Auxiliary Evidence | Offline-guarded `NOT_CHECKED` records |

---

## 3. Cryptographic Diversity

### Public Key Algorithms & Key Sizes

```
RSA vs ECDSA Distribution:
RSA   [########################################] 20,871 (80.8%)
ECDSA [#########                               ]  4,960 (19.2%)
```

| Algorithm | Key Size / Curve | Record Count | Share (%) | Security Status |
| :--- | :--- | :--- | :--- | :--- |
| **RSA** | 2048-bit | 20,643 | 79.92% | Standard / Secure |
| **RSA** | 4096-bit | 214 | 0.83% | High Security |
| **RSA** | 3072-bit | 12 | 0.05% | High Security |
| **RSA** | 1024-bit | 2 | 0.01% | Deprecated / Weak (In-the-wild legacy) |
| **ECDSA** | P-256 (`secp256r1`) | 4,903 | 18.98% | Modern / High Efficiency |
| **ECDSA** | P-384 (`secp384r1`) | 56 | 0.22% | High Security |
| **ECDSA** | P-521 (`secp521r1`) | 1 | <0.01% | Ultra-High Security |

### Signature Algorithms

| Signature Algorithm | Count | Share (%) | Status |
| :--- | :--- | :--- | :--- |
| `sha256WithRSAEncryption` | 20,746 | 80.31% | Standard Production |
| `ecdsa-with-SHA384` | 3,764 | 14.57% | Modern High-Security |
| `ecdsa-with-SHA256` | 1,149 | 4.45% | Modern Standard |
| `sha384WithRSAEncryption` | 124 | 0.48% | Standard |
| `sha1WithRSAEncryption` | 43 | 0.17% | Deprecated (Real-world legacy captures) |
| `sha512WithRSAEncryption` | 4 | 0.02% | Rare Production |
| `ecdsa-with-SHA512` | 1 | <0.01% | Experimental / Rare |

---

## 4. Issuer Ecosystem & Market Concentration

- **Unique Issuer DNs:** **1,540 distinct issuers** across the globe.
- **Herfindahl-Hirschman Index (HHI):** **1,441.6**  
  *(An HHI below 1,500 indicates an un-concentrated, highly competitive market distribution. The dataset is not dominated by any single monopoly CA).*

### Major CA Operators Represented:
1. **Sectigo / Comodo** (Sectigo RSA Domain Validation CA, AAA Certificate Services)
2. **DigiCert** (DigiCert Global Root CA, RapidSSL, GeoTrust, Thawte)
3. **Google Trust Services (GTS)** (GTS Root R1–R4, GTS CA 1C3)
4. **Let's Encrypt / ISRG** (ISRG Root X1, R3, E1)
5. **Cloudflare Inc.** (Cloudflare Origin CA, Cloudflare Inc ECC CA-3)
6. **GlobalSign** (GlobalSign GCC R3 DV TLS CA, AlphaSSL)
7. **GoDaddy / Starfield** (Go Daddy Secure Certificate Authority G2)
8. **USERTrust / The USERTRUST Network**
9. **Cisco Systems** (Cisco Manufacturing CA)
10. **Microsoft Corporation** (Microsoft RSA TLS CA)
11. **Amazon Trust Services** (Amazon Root CA 1–4)
12. **Apple Inc.** (Apple Worldwide Developer Relations CA)

---

## 5. Validity Duration Profiles

- **Minimum Lifespan:** 1.0 day (short-lived ephemeral/testing certificates)
- **Maximum Lifespan:** 12,784.0 days (~35 years, Root CA anchors)
- **Mean Lifespan:** 406.04 days
- **Median Lifespan:** 395.0 days (matches standard 1-year subscriber certificate lifespan plus grace windows)

---

## 6. Data Leakage Prevention & Benchmark Splits

Three independent partitioning schemes were constructed and audited:

### Split A — Fingerprint-Disjoint Partition
- **Train:** 18,081 certificates (70.0%)
- **Validation:** 3,874 certificates (15.0%)
- **Test:** 3,876 certificates (15.0%)
- **Overlap Audit:** **0 fingerprint overlaps** (`fingerprint_leakage_clean = True`).

### Split B — Subject Public Key Info (SPKI) Disjoint Partition
- **Train:** 18,096 certificates (70.0%)
- **Validation:** 3,881 certificates (15.0%)
- **Test:** 3,854 certificates (15.0%)
- **Overlap Audit:** **0 SPKI public-key overlaps** and **0 fingerprint overlaps** (`public_key_leakage_clean = True`).  
  *(Ensures models cannot memorize public keys across train and test sets).*

### Split C — Chronological Partition
- **Train:** 18,081 certificates (historical)
- **Validation:** 3,874 certificates (intermediate)
- **Test:** 3,876 certificates (future evaluation)
- **Ordering:** Strictly ordered by genuine `not_before` UTC timestamps.

---

## 7. Analytical Storage Integrity

All records have been saved in streaming JSONL and Apache Parquet formats with SHA-256 integrity digests:

| File | Format | SHA-256 Digest |
| :--- | :--- | :--- |
| `normalized_certificates.parquet` | Apache Parquet | `be0823ba1dd89247c32d938544b0a1206279096d111847b5a9ad31e0a0173b70` |
| `normalized_certificates.jsonl` | JSON Lines | `e8c06ec0d2c3804f2fc2c49537dc75c80a4db69fe6f3f288f85f33af93809cc0` |
| `certificate_labels.parquet` | Apache Parquet | `9b6e4fb7f53e6356f2c74e873c38b8d57a901b944344a49f8e1d73511f0949ce` |
| `certificate_labels.jsonl` | JSON Lines | `c6959d3dc7c16a33a7d22ee857c996ca4679c3bbfe132ae7d6750e4588496942` |
| `revocation_observations.parquet` | Apache Parquet | `223fc28f0266990680d41fc70c8ac7576c3ee1bb5963f3ca815fe402a86750f2` |
| `root_store_records.parquet` | Apache Parquet | `216e89eebea26380b05e20d07f9a61289c3116b4633dea1647c3679a5ceaad72` |

