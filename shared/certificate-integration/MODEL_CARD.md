# Model Card — TrustLens Certificate Policy & Anomaly Advisor

## Model Details
- **Model Name**: `TrustLens-Certificate-Policy-Classifier`
- **Model Version**: `1.0.0`
- **Model Type**: Regularized Logistic Regression Pipeline + Auxiliary Isolation Forest Anomaly Detector
- **Framework**: `scikit-learn` 1.9.1 / `joblib`
- **Author**: TrustLens AI/ML Engineering Team
- **Date**: March 2025 / Active Release
- **License**: Proprietary / TrustLens Platform

---

## Intended Use & Operational Role

> [!IMPORTANT]
> **Strict Advisory Role**: This ML model is strictly an **Advisory Auxiliary Signal**. It is designed to rapidly score structural policy compliance and flag anomalous certificate profiles (e.g. C2 or non-standard self-signed implants).
> 
> **It MUST NEVER override deterministic PKI validation outcomes** (such as certificate expiration, cryptographic signature failure, untrusted root anchors, or confirmed revocation).

---

## Zero-Leakage Training & Evaluation Data

The model was trained and evaluated on the **TrustLens Production-Grade Certificate Dataset** partitioned via **SPKI-Disjoint Split** (ensuring zero public key and zero fingerprint leakage):

| Split Partition | Record Count | Compliant (1) | Non-Compliant (0) | SPKI Leakage | Fingerprint Leakage |
|:---|:---|:---|:---|:---|:---|
| **Training Set** | 18,096 | 15,158 (83.8%) | 2,938 (16.2%) | 0.0% (16,625 unique keys) | 0.0% |
| **Validation Set** | 3,881 | 3,262 (84.1%) | 619 (15.9%) | 0.0% (3,562 unique keys) | 0.0% |
| **Locked Test Set** | 3,854 | 3,242 (84.1%) | 612 (15.9%) | 0.0% (3,563 unique keys) | 0.0% |

---

## Feature Schema (Zero Target Leakage)

Features are extracted strictly from raw X.509 ASN.1 structural parameters. **No rule output codes, deduction scores, or finding flags are permitted.**

### Numeric Features (12):
1. `key_size_bits`: Public key modulus size in bits (e.g., 2048, 4096, 256).
2. `validity_duration_days`: Certificate lifespan between notBefore and notAfter.
3. `san_count`: Number of Subject Alternative Names.
4. `is_wildcard`: Binary indicator (1 if domain starts with `*`).
5. `has_scts`: Binary indicator of embedded RFC 6962 SCT extension.
6. `sct_count`: Number of embedded Signed Certificate Timestamps.
7. `extension_count`: Total count of active X.509 extensions.
8. `key_usage_count`: Number of asserted Key Usage bits.
9. `extended_key_usage_count`: Number of asserted Extended Key Usage OIDs.
10. `is_ca`: Binary indicator of CA Basic Constraint.
11. `is_self_signed`: Binary indicator of self-signed status.
12. `subject_dn_length`: Character length of the RFC 4514 Subject DN string.

### Categorical Features (3):
1. `key_algorithm`: Key type (`RSA`, `ECDSA`, `Ed25519`).
2. `ec_curve`: Curve name (`secp256r1`, `secp384r1`, `none`).
3. `signature_algorithm`: Signature digest algorithm (`sha256WithRSAEncryption`, `ecdsa-with-SHA384`, etc.).

---

## Performance Metrics (Locked SPKI-Disjoint Test Set)

```text
Accuracy:       99.9741%
Precision:      99.9692%
Recall:         100.0000%
Macro F1:       0.999514
Weighted F1:    0.999740
ROC-AUC:        0.999999
PR-AUC:         0.999999
Brier Score:    0.000218 (High Probability Calibration)

Confusion Matrix:
               Predicted Non-Compliant    Predicted Compliant
Actual Non-Compliant        611 (TN)                   1 (FP)
Actual Compliant              0 (FN)                3242 (TP)
```

### Forensic Analysis of Single False Positive:
- **Fingerprint**: `e83c3c4db04c1e483d9895534268a3b97374133a61e599acfd4cb891c0017490`
- **Validity Duration**: 1,826.02 days (5-year legacy leaf certificate).
- **Public Key**: RSA 2048-bit with `sha256WithRSAEncryption`, 7 extensions, 3 key usages.
- **Root Cause**: The linear combination of standard RSA 2048 and positive key usage coefficients slightly offset the negative validity duration logit. Tree-based models (HistGradientBoosting / RandomForest) correctly threshold this sample via `validity_duration_days <= 398.0`, achieving 100.00% accuracy.

---

## Independent Audit Findings & Theoretical Categorization

An independent 11-phase machine learning audit conducted in March 2025 established the following:

### 1. Classification: Category B (Deterministic Rule Distillation Surrogate)
The near-perfect performance does **not** represent data leakage or invalid memorization:
- SPKI and fingerprint overlap between partitions are mathematically **0.0%**.
- The ground truth target `POLICY_COMPLIANT` is deterministically governed by CA/Browser Forum Baseline Requirements v2.0.8 rules (`duration <= 398 days`, `key_size >= 2048` if RSA, and no SHA-1/MD5).
- Because raw structural features (`validity_duration_days`, `key_size_bits`, `key_algorithm`, `signature_algorithm`) contain the necessary inputs to evaluate these hyperplanes, the classifier acts as a **smooth linear distillation surrogate** of the deterministic rule engine.
- Exact agreement with the deterministic rule baseline is **99.9741%** (3,853 / 3,854) with a Cohen's Kappa of **0.999028**.

### 2. Cross-Validation Stability (5-Fold StratifiedGroupKFold on SPKI)
Evaluated across 15 total folds using random seeds 42, 123, and 2026:
- **Fold Accuracy**: 1.000000 +/- 0.000000 across all folds.
- **Macro F1**: 1.000000 +/- 0.000000.
- **Brier Score**: ~0.000007.

### 3. Issuer-Held-Out Generalization (GroupKFold on issuer_dn)
Evaluated across 1,123 unique Certificate Authorities:
- Folds 2, 3, and 5 generalized with **100.00% accuracy** to hundreds of unseen global CAs.
- When synthetic/monitoring test intermediate CAs with fixed extension counts (e.g. Google CT Merge Delay Intermediate 1) were held out, the model exhibited sensitivity to extension-count clustering. This proves the model learns CA profile conventions alongside PKI rules.

### 4. Calibration & Sharpness
- **Brier Score Loss**: 2.1765e-04.
- **Expected Calibration Error (ECE)**: 0.0539% (0.000539).
- **Decision Sharpness**: 99.95% of test samples produce extreme probabilities ($P < 0.05$ or $P > 0.95$).

### 5. Isolation Forest Anomaly Detection Stress Test
- Contamination parameter: 5.0% (empirically flags 5.37% of compliant Web PKI baseline).
- **Legitimate Rare Profiles**: Accurately flags structural outliers such as high-SAN CDN certificates (SAN > 50), NIST P-384 curves, and multi-purpose enterprise EKUs as atypical relative to modal Web PKI distributions, confirming its utility as an anomaly detector.

---

## Architectural Comparison Matrix

| Architecture | Test Macro-F1 | Test Accuracy | Brier Score | 1-Sample Latency | Batch Latency (3.8k) | Artifact Size |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Logistic Regression (Champion)** | **0.9995** | **99.97%** | **2.18e-04** | **3.25 ms** | **5.64 ms** | **4.8 KB** |
| HistGradientBoosting (Candidate) | 1.0000 | 100.00% | 4.80e-10 | 4.52 ms | 7.20 ms | 69.0 KB |
| Random Forest (Candidate) | 1.0000 | 100.00% | 2.52e-06 | 21.08 ms | 33.62 ms | 289.7 KB |

---

## Limitations & Operational Boundaries

1. **Advisory Invariant**: The classifier is an auxiliary risk filter. In production, deterministic checks (RFC 5280 path validation, revocation checks, hostname identity matching) retain absolute authority.
2. **Policy Drift**: Ground truth labels reflect CA/Browser Forum Baseline Requirements v2.0.8. When industry rules change (e.g., transition to 90-day lifespans), models must be retrained.
3. **Intent Blindness**: The model verifies structural X.509 compliance, not threat intent. Phishing websites with valid Let's Encrypt certificates will be scored as `POLICY_COMPLIANT`. Threat classification is performed separately by the TrustLens URL & Threat Analyzer.
