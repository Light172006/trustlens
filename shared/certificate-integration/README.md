# TrustLens — Certificate Analyzer Integration Guide

## Overview

Welcome to the **TrustLens Certificate Analyzer Integration Documentation**. This package is designed to provide the **Backend Engineer** and **UI/UX Engineer** with everything needed to integrate, query, interpret, and display certificate trust intelligence without needing to dive into internal PKI parsing or cryptographic verification mechanics.

---

## Architecture & Ownership Boundaries

```text
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTLENS ARCHITECTURE                   │
└─────────────────────────────────────────────────────────────┘
               │
               ├── URL & Threat Analyzer (Independent)
               │
               ├── Web Security Analyzer (Future Component)
               │
               ├── Certificate Analyzer (Current Component)
               │     ├── AI/ML Engineer: Dataset, Rules, Scoring, ML Advisory (Complete)
               │     ├── Backend Engineer: TLS Scanning, Handshake Ingestion, FastAPI Integration
               │     └── UI/UX Engineer: React Dashboard, Trust Badges, Finding Details
               │
               └── Collaborative Threat Intelligence (Independent)
```

---

## Documentation Navigation

| Documentation File | Target Audience | Description |
|:---|:---|:---|
| [`BACKEND_INTEGRATION.md`](BACKEND_INTEGRATION.md) | Backend Engineer | Complete guide for calling `analyze_certificate()` and `analyze_endpoint_tls()`, input parameters, bundle leaf resolution, error handling, and PostgreSQL persistence. |
| [`FRONTEND_INTEGRATION.md`](FRONTEND_INTEGRATION.md) | UI/UX Engineer | Specification for displaying Trust Scores, categorical verdicts, certificate details, CA/B Forum status badges, and ML advisories. |
| [`POLICY_VERSIONS.md`](POLICY_VERSIONS.md) | All Teammates | CA/Browser Forum Baseline Requirements v2.3.1 documentation, tiered validity reduction schedule (398d → 200d → 100d → 47d), and CA applicability rules. |
| [`CONFIGURATION.md`](CONFIGURATION.md) | DevOps & Backend | Engine configuration, cache tuning, DoS resource limits (10 MB, 50 certs, 10k SANs), root store options, and environment variables. |
| [`FINDING_CODES.md`](FINDING_CODES.md) | All Teammates | Complete catalog of all 30 deterministic finding codes, severities, deductions, and actionable remediation advice. |
| [`ERROR_HANDLING.md`](ERROR_HANDLING.md) | Backend Engineer | Strategy for handling malformed certificates, empty inputs, resource limit violations, ambiguous bundles, untrusted roots, and network outages. |
| [`MODEL_CARD.md`](MODEL_CARD.md) | Data / ML / Sec | Rigorous ML model card covering training data, feature schema, metrics, calibration, and auxiliary advisory constraints. |
| [`PRODUCTION_READINESS_REPORT.md`](PRODUCTION_READINESS_REPORT.md) | Leadership & Team | Comprehensive engineering readiness certification, standards compliance matrix, and performance benchmark audit. |
| [`CERTIFICATE_INPUT.example.json`](CERTIFICATE_INPUT.example.json) | Backend Engineer | Example JSON payload passed from the TLS handshake scanner into the analyzer. |
| [`CERTIFICATE_OUTPUT.example.json`](CERTIFICATE_OUTPUT.example.json) | Backend & Frontend | Full JSON schema output from `CertificateAssessment.model_dump()`. |
| [`ML_ADVISORY.example.json`](ML_ADVISORY.example.json) | Backend & Frontend | Example JSON output from the advisory `CertificateAssessment.ml_advisory`. |
