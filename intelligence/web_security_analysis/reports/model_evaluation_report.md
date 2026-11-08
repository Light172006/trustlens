# TrustLens Web Security Analyzer - Model Evaluation Report

**Model Name**: TrustLens-WebSecurity-HistGradientBoosting  
**Version**: 1.0.0  
**Evaluated At**: 2026-11-08T15:02:49.527913+00:00  
**Selected Algorithm**: `HistGradientBoosting` with `sigmoid` probability calibration  

## Candidate Models Validation Comparison

| Model | Accuracy | Macro F1 | Weighted F1 | Balanced Acc | False GOOD on POOR | Train Time |
|---|---|---|---|---|---|---|
| **LogisticRegression** | 0.9719 | 0.9615 | 0.9720 | 0.9623 | 0 (0.0%) | 0.164s |
| **RandomForest** | 0.9763 | 0.9676 | 0.9764 | 0.9688 | 0 (0.0%) | 0.363s |
| **ExtraTrees** | 0.9676 | 0.9550 | 0.9677 | 0.9559 | 0 (0.0%) | 0.316s |
| **HistGradientBoosting** | 0.9906 | 0.9879 | 0.9907 | 0.9897 | 0 (0.0%) | 1.901s |

## Final Held-Out Test Evaluation (Zero-Leakage Unseen Domains)

- **Test Samples**: 1,609 distinct registrable domains
- **Test Accuracy**: **0.9944**
- **Test Balanced Accuracy**: **0.9929**
- **Test Macro F1**: **0.9928**
- **Test Weighted F1**: **0.9944**
- **Macro ROC-AUC**: **0.9999**
- **Log Loss**: **0.0192**

### Per-Class Test Performance

| Posture Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **GOOD** | 0.9816 | 1.0000 | 0.9907 | 426 |
| **MODERATE** | 0.9970 | 0.9821 | 0.9895 | 336 |
| **POOR** | 1.0000 | 0.9965 | 0.9982 | 847 |

### Confusion Matrix (Test Split)

```text
Classes: ['GOOD', 'MODERATE', 'POOR']
[[426   0   0]
 [  6 330   0]
 [  2   1 844]]
```

### Security Penalty Metrics
- **False GOOD on POOR**: 2 domains (0.24%)
- **False POOR on GOOD**: 0 domains (0.0%)
