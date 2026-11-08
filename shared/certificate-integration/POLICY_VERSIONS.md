# CA/Browser Forum TLS Baseline Requirements Versioning & Policy Guide

## Overview

The **TrustLens Certificate Analyzer** includes an integrated, deterministic policy evaluation engine (`CABFPolicyEvaluator`) that assesses certificates against the **CA/Browser Forum Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates**.

This document details the policy versioning, validity reduction schedules, applicability profiles, and compliance evaluation outputs used by the engine.

---

## 1. Supported Policy Versions

| Policy Identifier | Standard Name | Effective Date Range | Key Validity Rule |
|:---|:---|:---|:---|
| `CABF_BR_V2_3_1` | CA/Browser Forum TLS Baseline Requirements v2.3.1 | Active / Current | Dynamic issuance-date tiered validity reduction (398d → 200d → 100d → 47d) |
| `CABF_BR_HISTORICAL` | Historical CA/B Forum BRs (v1.x - v2.2) | Deprecated | Fixed 398-day limit (pre-2026 issuance) |

---

## 2. Tiered Validity Reduction Schedule (v2.3.1)

Under CA/Browser Forum Baseline Requirements v2.3.1 (Ballot SC-063 / Google Chrome 90-day transition timeline), maximum permissible validity periods for subscriber TLS certificates decrease on exact UTC boundary dates:

| Issuance Date Range (UTC) | Rule Identifier | Max Allowed Validity (Days) | Grace Period Cap | Notes |
|:---|:---|:---:|:---:|:---|
| **Before 2026-03-15** | `CABF_PRE_2026_398D` | **398 days** | 399 days | Traditional 398-day maximum validity established in 2020. |
| **2026-03-15 to 2027-03-14** | `CABF_2026_200D` | **200 days** | 201 days | First reduction tier (200-day ceiling). |
| **2027-03-15 to 2029-03-14** | `CABF_2027_100D` | **100 days** | 101 days | Second reduction tier (~3 months ceiling). |
| **2029-03-15 and Later** | `CABF_2029_47D` | **47 days** | 48 days | Final reduction tier (~6 weeks ceiling) aligning with automated ACME issuance. |

### Grace Period Rules
- The CA/B Forum allows up to 24 hours (1 day) of grace period for clock skew and leap-second adjustments during issuance.
- A certificate issued on `2026-06-01` with a validity of 201 days is evaluated as compliant; a certificate with 202 days triggers `RULE_VALIDITY_PERIOD_EXCEEDED` (-25 score deduction).

---

## 3. Profile Applicability Matrix

Not all certificates in a TLS connection are subject to subscriber validity duration caps. The evaluator strictly categorizes certificates into one of three profiles:

| Certificate Profile | Detection Criteria | Policy Applicability | Evaluation Behavior |
|:---|:---|:---:|:---|
| `TLS_SUBSCRIBER` | `is_ca == False` | **`APPLICABLE`** | Evaluates issuance timestamp against the tiered validity schedule above. Enforces key sizes (RSA ≥ 2048, ECC ≥ 256), signature digests (no SHA-1/MD5), and SAN presence. |
| `INTERMEDIATE_CA` | `is_ca == True` and `is_self_signed == False` | **`NOT_APPLICABLE`** | Subscriber validity caps do NOT apply. Intermediate CAs typically operate with 3 to 10 year validity. Emits `applicable_rule_id = "CABF_NOT_APPLICABLE_CA"`. |
| `ROOT_CA` | `is_ca == True` and `is_self_signed == True` | **`NOT_APPLICABLE`** | Subscriber validity caps do NOT apply. Root CAs typically operate with 15 to 25 year validity. Governed by root store policies (e.g. Mozilla Root Store Policy). |

> [!IMPORTANT]
> Intermediate and Root CAs will **never** receive score deductions or findings for exceeding the 398-day or 200-day subscriber validity limit.

---

## 4. Policy Evaluation Schema Output

The evaluation result is accessible on `CertificateAssessment.policy_evaluation`:

```json
{
  "policy_name": "CA/Browser Forum Baseline Requirements for TLS Server Certificates",
  "policy_version": "2.3.1",
  "certificate_profile": "TLS_SUBSCRIBER",
  "applicability": "APPLICABLE",
  "applicable_rule_id": "CABF_2026_200D",
  "certificate_issuance_date": "2026-06-15T00:00:00+00:00",
  "evaluation_date": "2026-11-08T12:00:00+00:00",
  "max_validity_days_allowed": 200,
  "actual_validity_days": 180.0,
  "validity_compliant": true,
  "cryptographic_compliant": true,
  "overall_compliant": true,
  "evaluation_notes": "Certificate validity (180.0 days) complies with CA/B Forum v2.3.1 tier CABF_2026_200D (max 200 days)."
}
```

### Field Definitions:

- `policy_name` (`str`): Official policy document title.
- `policy_version` (`str`): Engine rule version (`"2.3.1"`).
- `certificate_profile` (`str`): `"TLS_SUBSCRIBER"`, `"INTERMEDIATE_CA"`, or `"ROOT_CA"`.
- `applicability` (`str`): `"APPLICABLE"` or `"NOT_APPLICABLE"`.
- `applicable_rule_id` (`str`): Identifier of the active rule tier (`"CABF_PRE_2026_398D"`, `"CABF_2026_200D"`, `"CABF_2027_100D"`, `"CABF_2029_47D"`, or `"CABF_NOT_APPLICABLE_CA"`).
- `certificate_issuance_date` (`str` ISO 8601): Certificate `notBefore` timestamp.
- `evaluation_date` (`str` ISO 8601): Time when the evaluation was executed.
- `max_validity_days_allowed` (`int` or `null`): Upper limit permitted for this certificate based on its issuance date. `null` for CAs.
- `actual_validity_days` (`float`): Measured span between `notBefore` and `notAfter`.
- `validity_compliant` (`bool` or `null`): `true` if within limit, `false` if exceeded, `null` if not applicable.
- `cryptographic_compliant` (`bool`): `true` if key algorithm/size and signature hash meet modern cryptographic standards.
- `overall_compliant` (`bool` or `null`): True if both validity and cryptographic checks pass.

---

## 5. Finding Codes Associated with Policy

When a subscriber certificate fails CA/B Forum requirements, the following finding is generated:

- **Finding Code**: `RULE_VALIDITY_PERIOD_EXCEEDED`
- **Severity**: `MEDIUM`
- **Score Deduction**: `-25`
- **Evidence Attached**:
  ```json
  {
    "actual_days": 395.0,
    "max_allowed_days": 200,
    "rule_tier": "CABF_2026_200D",
    "issued_after": "2026-03-15T00:00:00+00:00"
  }
  ```
- **Remediation**: Reissue certificate using an automated ACME provider conforming to the current validity tier.

