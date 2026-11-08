# TrustLens — Certificate Analyzer

## Overview

The **Certificate Analyzer** is an independent, production-grade digital trust intelligence component of the TrustLens platform. It performs deep, multi-dimensional security assessments of X.509 certificates and TLS endpoints without coupling to the URL threat checker.

## Core Capabilities & Standards Compliance

1. **RFC 9525 Modern TLS Server Identity Verification**:
   - Strictly enforces Subject Alternative Name (`dNSName` and `iPAddress`).
   - Deprecates legacy Common Name fallback in compliance with RFC 9525 Section 6.
   - Restricts wildcard matching to the single left-most label (`*.example.com` matches `foo.example.com`, but never `foo.bar.example.com` or apex `example.com`).
   - Rejects partial wildcard labels (`sub*.example.com`, `*sub.example.com`).
   - Fully supports IDNA 2008 Punycode normalization (`xn--...`).
2. **RFC 5280 Certification Path Validation**:
   - Traverses Authority Key Identifier (AKI) to Subject Key Identifier (SKI) graphs.
   - Enforces Basic Constraints (`is_ca=True` on parent nodes, `path_length` constraints).
   - Validates cryptographic digital signatures along the entire path up to trusted Mozilla CCADB trust anchors.
   - Detects circular issuer loops and self-signed certificates without crashing.
   - Distinguishes missing intermediates from invalid cryptographic signatures.
3. **RFC 6960 / RFC 5280 Revocation Verification**:
   - Validates OCSP Responses and Certificate Revocation Lists (CRLs).
   - Enforces the absolute invariant: A confirmed revoked certificate unconditionally yields a `trust_score = 0` and `verdict = DISTRUSTED`.
   - Never promotes unknown revocation status to good.
   - Checks OCSP `thisUpdate` and `nextUpdate` freshness intervals.
4. **RFC 6962 / RFC 9162 Certificate Transparency (CT)**:
   - Audits embedded Signed Certificate Timestamps (SCTs) via OID `1.3.6.1.4.1.11129.2.4.2`.
   - Decodes RFC 6962 binary serialized SCT bodies (version, Log ID, timestamp, cryptographic signature algorithm).
   - Transparently distinguishes SCT presence promises from Merkle tree inclusion proofs.
5. **CA/Browser Forum Baseline Requirements (v2.0.8)**:
   - Enforces maximum validity durations: 398 days for modern certificates (with legacy exemptions for historical certificates).
   - Flag deprecation of SHA-1, MD5, and weak RSA key sizes (< 2048-bit).
   - Verifies Key Usage and Extended Key Usage consistency (`serverAuth`).
6. **Deterministic Trust Scoring**:
   - Base score of 100 with calibrated, additive risk penalties and deductions.
   - Strict scoring invariants preventing contradictory verdicts.
   - Categorical verdicts: `TRUSTED` (80-100), `WARNING` (50-79), `DISTRUSTED` (0-49), `INCONCLUSIVE` (unverifiable).
   - Score and confidence metrics are strictly decoupled.

## Public Interfaces

### `analyze_certificate(cert_input, hostname=None, reference_time=None) -> CertificateAssessment`
Accepts `cryptography.x509.Certificate`, binary DER bytes, or ASCII PEM string. Extracts features, validates RFC 9525 identity, reconstructs certification path, audits CT, checks revocation, and computes deterministic score.

### `analyze_pem(pem_str, hostname=None, reference_time=None) -> CertificateAssessment`
Accepts a single certificate or a PEM bundle containing multiple certificates (leaf + intermediates), automatically identifying the leaf and building the chain.

### `analyze_endpoint_tls(hostname, port=443, certificate_der=None, negotiated_protocol=None, cipher_suite=None, ...) -> CertificateAssessment`
Evaluates complete TLS endpoint posture, synthesizing certificate trust with TLS protocol version (e.g. TLS 1.3/1.2 vs deprecated TLS 1.0/1.1) and cipher suite security.

## Architecture

```text
intelligence/
└── certificate_analyzer/
    ├── src/certificate_analyzer/
    │   ├── api.py                    # Public interface entrypoints
    │   ├── parsing/                  # Resilient DER/PEM parsers and bundle extractors
    │   ├── features/                 # Cryptographic and X.509 extension feature extractor
    │   ├── rules/
    │   │   ├── cryptographic.py      # RSA/ECC key size and digest strength rules
    │   │   ├── temporal.py           # Validity, expiration, and leap-year rules
    │   │   ├── identity.py           # RFC 9525 SAN matching engine
    │   │   ├── hierarchy.py          # Basic constraints and chain structure rules
    │   │   ├── path_validator.py     # RFC 5280 path building and signature verification
    │   │   ├── revocation_verifier.py# RFC 6960 OCSP / RFC 5280 CRL verifiers
    │   │   ├── ct_verifier.py        # RFC 6962 / RFC 9162 SCT audit engine
    │   │   └── policy.py             # CA/B Forum BR baseline compliance rules
    │   ├── scoring/
    │   │   └── engine.py             # Deterministic trust scoring and finding aggregation
    │   └── schemas/                  # Structured Pydantic assessment and context models
    └── tests/                        # 75 passing offline tests and stress benchmarks
```

## Isolation and Integrity Boundaries

- Resides strictly in `intelligence/certificate_analyzer/`.
- Zero modifications to backend endpoints, URL threat intelligence, or database schemas.
- High-throughput, production-optimized with in-memory parsed root store caching (< 0.4ms evaluation latency per certificate).


