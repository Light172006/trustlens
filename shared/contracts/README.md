# TrustLens Shared Data Contracts

[![Schema Standard](https://img.shields.io/badge/JSON%20Schema-Draft%202020--12-blue)](https://json-schema.org/draft/2020-12/schema)
[![Scoring Version](https://img.shields.io/badge/Scoring%20Version-trustlens--1.0-green)](https://github.com/trustlens)
[![Contract Version](https://img.shields.io/badge/Contract%20Version-1.0.0-purple)](schemas/)

This directory defines the formal, machine-readable data contracts establishing the boundary between the **TrustLens Backend Scanning Infrastructure** and the **AI/ML Threat Intelligence Engine**.

---

## 1. Contract Ownership Matrix

| Contract | Schema File | Owner | Responsibility |
|---|---|---|---|
| **Scanner Evidence Schema** | `schemas/scanner-evidence.schema.json` | **Joint Ownership** (Backend & AI/ML) | Defines the normalized technical observations collected and supplied by the backend scanner. |
| **AI Engine Input Schema** | `schemas/ai-engine-input.schema.json` | **AI/ML Engineer** | Defines the exact input structure accepted by the intelligence engine for feature extraction and scoring. |
| **AI Engine Output Schema** | `schemas/ai-engine-output.schema.json` | **AI/ML Engineer** | Defines the authoritative assessment, verdict, score, confidence, and structured findings returned by the engine. |

### Ownership & Review Rules

1. **Scanner Evidence Schema (Joint Ownership):**
   * The backend engineer and AI engineer must agree on any additions or modifications to the scanner observations.
   * This schema defines what the backend scanner must produce.
   * The current schema represents the proposed, technically validated contract aligned with the intelligence engine's actual requirements and database tables in `API.md` and `ARCH.md`. Formal approval by the backend engineer is pending their implementation review.

2. **AI Engine Input Schema (AI Ownership):**
   * Owned exclusively by the AI/ML engineer.
   * Directly models the engine's public input interface (`ScanEvidence`).
   * Reuses the scanner evidence schema via JSON Schema `$ref` to guarantee consistency without duplication.

3. **AI Engine Output Schema (AI Ownership):**
   * Owned exclusively by the AI/ML engineer.
   * Governs the threat assessment report, risk score, confidence, and detection findings.
   * Backend services must persist and serialize these fields without altering verdicts or calculating scores independently.

---

## 2. Directory Layout

```text
shared/contracts/
├── README.md                              # This specification and architecture overview
├── BACKEND_INTEGRATION.md                 # Practical implementation guide for backend engineers
│
├── schemas/                               # Machine-readable Draft 2020-12 JSON Schemas
│   ├── scanner-evidence.schema.json       # Joint scanner evidence contract
│   ├── ai-engine-input.schema.json        # AI engine invocation & input contract
│   └── ai-engine-output.schema.json       # AI engine assessment output contract
│
└── examples/                              # Validated JSON example payloads
    ├── scanner-evidence.example.json      # Scenario 1: Normal clean website scan
    ├── ai-engine-input.example.json       # Scenario 1: AI engine input envelope
    ├── ai-engine-output.example.json      # Scenario 1: Evaluated threat assessment
    │
    └── scenarios/                         # Edge-case and failure fixtures
        ├── scanner-evidence.missing-tls.json
        ├── ai-engine-input.missing-tls.json
        ├── ai-engine-output.missing-tls.json
        │
        ├── scanner-evidence.threat-match.json
        ├── ai-engine-input.threat-match.json
        ├── ai-engine-output.threat-match.json
        │
        ├── scanner-evidence.provider-unavailable.json
        ├── ai-engine-input.provider-unavailable.json
        ├── ai-engine-output.provider-unavailable.json
        │
        ├── scanner-evidence.sensitive-url.json
        ├── ai-engine-input.sensitive-url.json
        └── ai-engine-output.sensitive-url.json
```

---

## 3. Core Contract Principles

### 3.1 Separation of Concerns
* **The scanner collects facts, not verdicts:** The backend worker observes raw technical data (HTTP status codes, headers, TLS handshake details, DNS resolution, threat feed lookup results). It must **never** calculate the final risk score or verdict.
* **The engine interprets facts:** The intelligence engine evaluates detection rules, computes deterministic scores (`trustlens-1.0`), enforces explainability invariants, and assigns verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `INCONCLUSIVE`).

### 3.2 Explicit Missing Evidence Semantics
* **Never use `false` to represent unobserved or unavailable checks.**
* **Distinct states:**
  * `hostname_match: false` means the TLS handshake was performed and the certificate CN/SAN **did not match** the target host (triggers `CERT_HOSTNAME_MISMATCH`).
  * `hostname_match: null` means TLS was not checked or the check was unavailable.
  * `openphish_status: "no_match"` means OpenPhish was queried and no match was found.
  * `openphish_status: "unavailable"` means the provider could not be reached (prevents a `SAFE` verdict).

### 3.3 Sensitive URL Privacy Policy
* URLs containing query parameters that may hold secrets (e.g., reset tokens, session keys) or flagged by users with `is_sensitive: true` must **never** be transmitted to external third-party lookup APIs (such as URLhaus).
* In such cases, external lookups are skipped, recording `result_status: "skipped_sensitive_url"`.
* The intelligence engine records incomplete coverage, preventing a false `SAFE` verdict.

---

## 4. Contract Versioning Policy

All schemas follow Semantic Versioning (`MAJOR.MINOR.PATCH`):

1. **PATCH changes (e.g. 1.0.0 → 1.0.1):**
   * Documentation updates, clarified descriptions, or broadened regex comments that do not alter schema validation.
2. **MINOR changes (e.g. 1.0.0 → 1.1.0):**
   * Backward-compatible additions: adding optional fields with defaults, adding non-breaking enum members, or relaxing constraints.
3. **MAJOR changes (e.g. 1.0.0 → 2.0.0):**
   * Breaking changes: removing fields, renaming fields, altering field data types, adding required fields, or changing verdict/scoring enum semantics.

---

## 5. Schema Validation

Schemas and example fixtures are validated using standard JSON Schema Draft 2020-12 tools and verified against the intelligence engine's native Pydantic models.

Run the contract test suite:

```bash
pytest intelligence/tests/test_shared_contracts.py
```

