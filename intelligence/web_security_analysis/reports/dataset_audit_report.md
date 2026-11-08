# TrustLens Web Security Dataset Audit Report

**Audited At**: 2026-11-08T14:59:40.384810+00:00  
**Overall Status**: **PASS**

## Audit Summary

- **Total Records**: 10,708
- **Unique Registrable Domains**: 10,708 (Threshold: ≥ 10,000)
- **Duplicate Domains Count**: 0 (Requirement: strictly 0)
- **PSL Normalization Verification**: 100% Valid
- **Split Proportions**: Train: 7,495 (70.0%), Val: 1,604 (15.0%), Test: 1,609 (15.0%)
- **Zero-Leakage Domain Isolation**: Verified ($	ext{Train} \cap 	ext{Val} \cap 	ext{Test} = \emptyset$)
- **Posture Distribution**:
  - `POOR`: 5,643 (52.7%)
  - `GOOD`: 2,832 (26.4%)
  - `MODERATE`: 2,233 (20.9%)
- **Candidate ML Inference Features**: 57 verified observable attributes.
- **Privacy & Token Leakage**: Zero raw cookie values or sensitive authentication tokens stored.
- **Synthetic Lab Isolation**: Controlled benchmark cases isolated in `dataset/synthetic/lab_dataset.parquet`.
