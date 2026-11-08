# Frontend Integration Guide — Certificate Intelligence UI

## Audience: UI/UX Engineer (React, TypeScript, Tailwind CSS, Shadcn UI)

This document specifies how to visually render certificate trust intelligence, badges, scoring breakdowns, CA/B Forum policy compliance, and machine learning advisories on the TrustLens web dashboard.

---

## 1. Core Verdict Badges & Visual Semantics

The analyzer produces four categorical verdicts (`assessment.verdict`):

| Verdict | Meaning | Score Range | Color Scheme (Tailwind) | Icon (Lucide) |
|:---|:---|:---:|:---|:---|
| `TRUSTED` | Certificate is structurally valid, signed by a trusted root, unrevoked, unexpired, and matches target domain. | 80 – 100 | `bg-emerald-500/10 text-emerald-400 border-emerald-500/30` | `ShieldCheck` |
| `WARNING` | Certificate is functional but has policy deviations (e.g. expiring in <30 days, weak cipher negotiation, or long validity). | 50 – 79 | `bg-amber-500/10 text-amber-400 border-amber-500/30` | `AlertTriangle` |
| `DISTRUSTED` | Certificate possesses critical security flaws: expired, revoked, untrusted root, self-signed, or hostname mismatch. | 0 – 49 | `bg-rose-500/10 text-rose-400 border-rose-500/30` | `ShieldAlert` |
| `INCONCLUSIVE` | Input was malformed, corrupted, exceeded limits, or had ambiguous leaf certificates. | N/A (0) | `bg-slate-500/10 text-slate-400 border-slate-500/30` | `HelpCircle` |

> [!CAUTION]
> **Strict UX Rule**: Never display an `INCONCLUSIVE` or `UNKNOWN` state as a green/safe badge! If revocation is `UNKNOWN` or `NOT_CHECKED`, render it with a neutral slate pill (`bg-slate-500/10 text-slate-400`), never an emerald badge.

---

## 2. Dashboard Component Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│  CERTIFICATE TRUST INTELLIGENCE CARD                                   │
├──────────────────────────────────────┬─────────────────────────────────┤
│  [Score Gauge: 95/100]               │  VERDICT: [ TRUSTED ]           │
│  Confidence: 100% (High Evidence)    │  Target: api.trustlens.io       │
├──────────────────────────────────────┴─────────────────────────────────┤
│  LIFECYCLE & IDENTITY OVERVIEW                                         │
│  • Status: Active (Expires in 84 days)                                 │
│  • Validity: Nov 1, 2024 → Feb 1, 2025 (90 days)                       │
│  • Issuer: Google Trust Services LLC (GTS CA 1P5)                      │
│  • Key: ECDSA (secp256r1, 256-bit) • Signature: ecdsa-with-SHA256      │
│  • Subject Alternative Names (2): api.trustlens.io, trustlens.io       │
├────────────────────────────────────────────────────────────────────────┤
│  POLICY COMPLIANCE (CA/Browser Forum Baseline Requirements v2.3.1)    │
│  • Tier: CABF_2026_200D (Allowed: <= 200 days • Actual: 90 days)       │
│  • Status: [ COMPLIANT ] • Profile: TLS_SUBSCRIBER                     │
├────────────────────────────────────────────────────────────────────────┤
│  CERTIFICATION PATH & TRANSPARENCY                                     │
│  • Chain Status: Complete (Anchored to 'GTS Root R1' in Mozilla Trust) │
│  • Certificate Transparency: 3 Embedded SCTs Verified (RFC 6962)      │
│  • Revocation: OCSP Status Verified Good                               │
├────────────────────────────────────────────────────────────────────────┤
│  SECURITY FINDINGS (Ranked by Severity)                                │
│  [INFO] Service Identity Authenticated for 'api.trustlens.io'          │
│  [INFO] Certificate Transparency Present (3 embedded SCTs)             │
│  [INFO] Valid Certification Path Anchored to Trusted Root              │
├────────────────────────────────────────────────────────────────────────┤
│  MACHINE LEARNING ADVISORY (Auxiliary Intelligence Drawer)            │
│  • Predicted Profile: POLICY_COMPLIANT (99.9% probability)             │
│  • Anomaly Assessment: Normal Profile (Score: +0.1245)                 │
│  • Notice: [ Advisory Only - Does not supersede cryptographic rules ]  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. TypeScript Interfaces

```typescript
export interface CertificateAssessment {
  certificate_sha256: string;
  subject_dn: string;
  issuer_dn: string;
  verdict: "TRUSTED" | "WARNING" | "DISTRUSTED" | "INCONCLUSIVE";
  trust_score: number;
  confidence: number;
  scoring_version: string;
  checks_completed: number;
  findings: CertificateFinding[];
  features: CertificateFeatures;
  policy_evaluation?: PolicyEvaluation | null;
  ml_advisory?: MLAdvisory | null;
  recommendations: string[];
  summary: string;
  evaluated_at: string;
}

export interface PolicyEvaluation {
  policy_name: string;
  policy_version: string;
  certificate_profile: "TLS_SUBSCRIBER" | "INTERMEDIATE_CA" | "ROOT_CA";
  applicability: "APPLICABLE" | "NOT_APPLICABLE";
  applicable_rule_id: string;
  certificate_issuance_date: string;
  evaluation_date: string;
  max_validity_days_allowed: number | null;
  actual_validity_days: number;
  validity_compliant: boolean | null;
  cryptographic_compliant: boolean;
  overall_compliant: boolean | null;
  evaluation_notes: string;
}

export interface MLAdvisory {
  predicted_class: "POLICY_COMPLIANT" | "NON_COMPLIANT";
  compliance_probability: number;
  is_anomaly: boolean;
  anomaly_score: number;
  confidence: number;
  advisory_notes: string;
  model_version: string;
  is_advisory: boolean;
}

export interface CertificateFinding {
  code: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  evidence?: Record<string, any> | null;
  recommendation?: string | null;
  score_deduction: number;
}

export interface CertificateFeatures {
  public_key_algorithm: string;
  key_size_bits: number;
  is_rsa: boolean;
  is_ecdsa: boolean;
  is_ed25519: boolean;
  is_weak_key: boolean;
  signature_algorithm: string;
  is_sha1_signature: boolean;
  is_md5_signature: boolean;
  is_secure_signature: boolean;
  validity_duration_days: number;
  days_since_issuance: number;
  days_until_expiry: number;
  is_expired: boolean;
  is_not_yet_valid: boolean;
  is_short_lived: boolean;
  has_san: boolean;
  san_count: number;
  has_wildcard_san: boolean;
  has_ip_san: boolean;
  matches_tested_hostname?: boolean | null;
  is_ca: boolean;
  is_self_signed: boolean;
  chain_length: number;
  is_chain_complete: boolean;
  has_trusted_anchor: boolean;
  has_crl_distribution_points: boolean;
  has_ocsp_aia: boolean;
  has_scts: boolean;
  sct_count: number;
  is_cabf_validity_compliant: boolean;
  cabf_max_allowed_validity_days?: number | null;
  policy_applicability?: string;
  is_ca_constraint_compliant: boolean;
  is_eku_compliant: boolean;
}
```

---

## 4. UI Rendering Guidelines for ML Advisory & Policy

### 4.1 ML Advisory Card:
- **Visual Separation**: Always place the ML advisory inside a visually distinct section or expandable drawer.
- **Mandatory Badge**: Display a neutral badge with text: `Advisory Signal Only`.
- **Tooltips**: Explain to the analyst: *"This statistical probability is calculated by an auxiliary machine learning model trained on Web PKI distributions. It does not replace or override cryptographic X.509 path validation."*
- **Anomaly Highlight**: If `is_anomaly === true`, render an informational badge: `Atypical Structural Profile` with tooltip: *"Certificate features (e.g. key length, extension count, or duration) deviate from standard commercial Web PKI baselines."*

### 4.2 CA/B Forum Policy Tier Card:
- If `policy_evaluation.applicability === "NOT_APPLICABLE"`:
  - Render a gray pill: `CA Anchor (Exempt from Subscriber Limits)`.
- If `policy_evaluation.validity_compliant === true`:
  - Render an emerald pill: `CA/B Forum v2.3.1 Compliant (${policy_evaluation.max_validity_days_allowed}d limit)`.
- If `policy_evaluation.validity_compliant === false`:
  - Render an amber pill: `Validity Exceeds CA/B Forum Limit (${policy_evaluation.actual_validity_days.toFixed(0)}d vs ${policy_evaluation.max_validity_days_allowed}d allowed)`.
