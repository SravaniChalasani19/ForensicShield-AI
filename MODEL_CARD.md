# Model Card: ForensicShield AI Random Forest NLP Pipeline

**Project:** 218 – Final Year B.Tech Academic Project

**Model Version:** fs-rf-v1.0

**Architecture:** TF-IDF Vectorizer and Random Forest Classifier

**Explainability Engine:** SHAP TreeExplainer

**Evaluation Date:** 25 November 2026

**Target Domain:** Anti-forensic Technique Detection in Forensic Text and Logs for Ransomware Incident Post-attack Investigation

**Evaluation Status:** PRELIMINARY_SYNTHETIC_EVALUATION

**Independent External Validation:** NOT_EVALUATED

---

## 1. Model Description

ForensicShield AI employs a Natural Language Processing pipeline to identify potential anti-forensic indicators within forensic system and event logs.

The primary model performs binary classification:

- Normal
- Suspicious

The machine learning predictions are supplemented by independent heuristic detection rules.

The system is designed as an investigative decision-support tool rather than an autonomous forensic decision-making system.

---

## 2. Model Architecture

### Text Preprocessing

Forensic text is processed using lowercase conversion, whitespace normalization and removal of unnecessary control characters.

### Feature Extraction

TF-IDF converts normalized forensic text into numerical feature vectors.

The vectorizer is fitted using the cleaned training partition.

The final fitted vocabulary contains 155 features.

### Classification Engine

The Random Forest classifier uses balanced class weighting to support binary classification.

The trained model produces suspicious-class scores and classification labels.

### Rule-Based Detection

Independent heuristic rules identify predefined anti-forensic indicators.

Rule matches and machine learning predictions are presented separately to support investigator interpretation.

### Explainability

SHAP provides local feature attribution values explaining the statistical contributions of individual features to model predictions.

---

## 3. Intended Use

The primary intended uses include:

- Digital forensic log analysis.
- Identification of candidate anti-forensic indicators.
- Investigation prioritization.
- Post-attack ransomware investigation support.
- Explainable machine learning predictions.
- Academic research and controlled forensic demonstrations.

### Out-of-Scope Uses

- Autonomous legal decision-making.
- Conclusive identification of criminal activity without corroborating evidence.
- Unvalidated production deployment.
- Guaranteed ransomware detection.
- Claims of independently verified technique-level classification.
- Guaranteed legal admissibility of generated reports.

---

## 4. Training Data Provenance

The primary model was trained using controlled synthetic forensic log records.

The original corpus contained 5,400 records.

Dataset quality assessment identified substantial duplication, requiring preprocessing and reconstruction of the training and testing partitions.

| Dataset Parameter | Result |
|---|---:|
| Original synthetic records | 5,400 |
| Duplicate records removed | 5,257 |
| Unique records retained | 143 |
| Training records | 114 |
| Testing records | 29 |
| Exact train-test overlap | 0 |

The cleaned dataset contains benign records and eight anti-forensic technique categories.

These categories represent synthetic dataset annotations rather than independently verified real-world events.

The primary model performs binary classification. Technique-level classification performance has not been independently evaluated.

### Dataset Locations

- Training: `data/synthetic/cleaned/train_logs_clean.json`
- Testing: `data/synthetic/cleaned/test_logs_clean.json`
- Quality report: `data/synthetic/cleaned/dataset_quality_report.json`

---

## 5. Data Leakage Prevention

The dataset preparation procedure includes:

1. Normalization of forensic text.
2. Removal of exact duplicate normalized texts.
3. Identification of conflicting label groups.
4. Construction of separate training and testing partitions.
5. Verification of exact train-test text overlap.
6. Fitting the TF-IDF vectorizer on training records only.
7. Transformation of testing records using the fitted vectorizer.

The cleaned dataset has zero exact normalized text overlap between training and testing partitions.

### Similarity Assessment

| Parameter | Result |
|---|---:|
| Test records examined | 29 |
| Records with similarity of at least 85% | 5 |
| Records with similarity of at least 90% | 3 |
| Maximum observed similarity | 95.56% |

Exact duplicate leakage has been eliminated from the cleaned partitions.

However, similar-template leakage risk remains. Complete independence between synthetic template families has not been established.

---

## 6. Verified Evaluation Metrics

The trained primary model was evaluated using 29 cleaned held-out synthetic records.

| Metric | Measured Value |
|---|---:|
| Accuracy | 93.10% |
| Precision (Suspicious Class) | 100.00% |
| Recall (Suspicious Class) | 91.30% |
| F1-Score (Suspicious Class) | 95.45% |
| False Positive Rate | 0.00% |
| Vocabulary size | 155 |
| Training records | 114 |
| Testing records | 29 |

The reported F1-score is calculated for the suspicious class rather than macro-averaged across both classes.

These results apply exclusively to the cleaned synthetic testing partition.

---

## 7. Confusion Matrix

| Actual Class | Predicted Normal | Predicted Suspicious |
|---|---:|---:|
| Actual Normal | 6 | 0 |
| Actual Suspicious | 2 | 21 |

### Classification Results

- True Negatives: 6
- False Positives: 0
- False Negatives: 2
- True Positives: 21
- Correct classifications: 27
- Total test records: 29

Two suspicious records were incorrectly classified as normal.

The absence of false positives in this small testing partition does not establish a zero false positive rate in real-world forensic investigations.

The updated confusion matrix visualization is available at:

`reports/evaluation/confusion_matrix.svg`

---

## 8. Model Artifact and Integrity

**Model Version:** fs-rf-v1.0

**Serialized Pipeline:**

`models/forensicshield_rf_pipeline.joblib`

**Model Metadata:**

`models/model_metadata.json`

**Verified Pipeline SHA-256:**

`14cd1670c79f600649b19eeea9214a8b3d9a03aabf47e6437df8cc1b4d517bad`

SHA-256 verification supports detection of changes to the serialized model artifact.

Automatic retraining through the application dashboard is disabled to reduce accidental replacement of the evaluated model.

Controlled retraining is available through the designated training script.

Retraining may change the serialized model digest and requires renewed evaluation and documentation.

---

## 9. External Dataset Analysis and Validation

| Dataset | Records | Current Status |
|---|---:|---|
| HackTheBox LogJammer | 4,252 | Source checksum matched; external inference completed |
| DFRWS 2008 | 51 | Published investigator annotations analyzed |
| SILRAD | 196,840 | Supporting ransomware telemetry acquired |

### External Analysis Results

HackTheBox:
- Total records: 4,252.
- ML-only candidates: 2,361.
- ML and rule candidates: 16.
- No indicator, unverified: 1,727.
- Insufficient vocabulary: 148.
- Successful candidate SHAP explanations: 2,377.

DFRWS:
- Total annotations: 51.
- ML candidates: 11.
- Insufficient vocabulary: 40.
- Successful candidate SHAP explanations: 11.

The HackTheBox archive checksum matched the published
reference checksum. DFRWS records are investigator
annotations, not original raw system logs.

A 50-record independent review sample has been prepared:
30 HackTheBox records and 20 DFRWS annotations.

Independent reviewer labels remain pending.
Independent anti-forensic accuracy, precision, recall
and F1-score remain NOT_EVALUATED.

### Supporting SILRAD Evaluation

The downloaded dataset contains 36 input features
and one class column. Its numeric feature representation
is incompatible with the primary text classifier.

A separate Random Forest model was evaluated after
duplicate, conflicting-label and exact overlap removal.

| Metric | Result |
|---|---:|
| Cleaned training records | 32,312 |
| Cleaned testing records | 140,964 |
| Accuracy | 96.56% |
| Precision | 96.71% |
| Recall | 66.78% |
| F1-score | 79.01% |
| False positive rate | 0.24% |

This evaluates ransomware versus goodware classification,
not anti-forensic technique classification.

SHAP analysis and identifier-feature ablation were
completed. The cleaned reduced-feature experiment
achieved 95.14% accuracy and 60.40% F1-score.

The ablation uses a different cleaned test population.
Direct causal comparison and ransomware-family-independent
generalization have not been established.

Dataset redistribution permissions remain to be verified.

---

## 10. Explainable AI

SHAP TreeExplainer supports interpretation of Random Forest predictions through local feature attribution values.

The explanation interface presents:

- Features contributing towards suspicious predictions.
- Features contributing towards normal predictions.
- Feature contribution values.
- Prediction rationale.
- Investigator interpretation notices.

SHAP functionality was demonstrated successfully through the application dashboard and generated forensic PDF reports.

Independent mathematical consistency testing and systematic explanation-quality evaluation remain pending.

### Explanation Caveat

SHAP attribution values represent statistical contributions to model predictions.

They do not establish attacker intent, malicious causation, criminal responsibility or legal guilt.

---

## 11. Application-Level Functional Verification

The trained model was demonstrated using the controlled investigation case:

`CASE-218-FINAL-DEMO`

| Parameter | Result |
|---|---|
| Evidence type | Controlled synthetic smoke-test logs |
| Parsed events | 12 |
| Candidate findings | 9 |
| Machine learning inference | Passed |
| Rule-based detection | Passed |
| SHAP explanation | Passed |
| Investigation timeline | Passed |
| Forensic PDF generation | Passed |
| Audit chain verification | Passed |

The updated forensic report includes event-wise entries for all nine candidate findings, as verified by the user.

**Report Identifier:** REP-A4C2B790

These results demonstrate integrated application functionality.

The nine candidate findings are not nine independently confirmed malicious events.

---

## 12. Known Failure Modes and Limitations

### 12.1 Limited Dataset Size

The cleaned dataset contains only 143 unique records, limiting the diversity of available training examples.

### 12.2 Small Testing Partition

The testing partition contains only 29 records. Performance estimates may not generalize to larger datasets.

### 12.3 Similar-Template Leakage Risk

Exact duplicates were removed, but similarities between synthetic training and testing examples remain.

### 12.4 Limited Temporal Understanding

TF-IDF does not directly capture long-range temporal relationships between separate log events.

The investigation timeline provides supplementary contextual information.

### 12.5 Unseen Log Patterns

Previously unseen terminology, log formats and complex text variations may reduce classification reliability.

### 12.6 Legitimate Administrative Activity

Normal administrative operations may resemble suspicious activity and require contextual investigator review.

### 12.7 False Negatives

Two suspicious synthetic test records were incorrectly classified as normal.

### 12.8 Feature Representation Differences

Differences between training text representation and canonical application input may affect prediction consistency.

### 12.9 Explainability Limitations

SHAP explains statistical model behavior rather than independently establishing the factual correctness of a prediction.

### 12.10 External Validation Limitations

Independent real-world performance and cross-environment generalization have not been established.

---

## 13. Model Reproducibility

The following commands are executed from the project root directory.

### Dataset Preparation

```cmd
python scripts/prepare_clean_datasets.py
```

### Controlled Model Training

```cmd
python scripts/train_full_model.py
```

### Synthetic Evaluation

```cmd
python scripts/run_evaluation.py --clean-synthetic
```

### Dataset Feasibility Audit

```cmd
python scripts/check_datasets.py
```

### External Evaluation Status

```cmd
python scripts/run_evaluation.py
```

### Application Launch

```cmd
python app.py
```

The existing trained model can be used directly for normal application demonstrations without retraining.

---

## 14. Future Model Improvements

- Increase dataset diversity and sample size.
- Expand authorized external datasets and obtain independent expert annotations.
- Establish independent expert ground-truth annotations.
- Implement template-family-separated evaluation.
- Improve consistency between training and inference feature representations.
- Evaluate technique-level classification independently.
- Conduct systematic SHAP explanation-quality assessment.
- Assess performance across different forensic environments.

Exploratory transformer and multi-label approaches are not part of the verified primary model evaluation.

---

## 15. Supporting Evaluation Files

- `reports/evaluation/evaluation_report.md`
- `reports/evaluation/evaluation_summary.json`
- `reports/evaluation/confusion_matrix.svg`
- `data/synthetic/cleaned/dataset_quality_report.json`
- `data/source_manifest.csv`

---

## 16. Final Model Assessment

The ForensicShield AI primary model successfully demonstrates NLP-based binary classification and integration with heuristic detection, SHAP explainability and forensic investigation workflows.

The model achieved 93.10% accuracy and a suspicious-class F1-score of 95.45% on 29 cleaned held-out synthetic records.

The current results demonstrate preliminary synthetic benchmark performance and application functionality.

Independent external validation remains pending.

**Model Status:** TRAINED AND FUNCTIONALLY DEMONSTRATED

**Evaluation Status:** PRELIMINARY_SYNTHETIC_EVALUATION

**Independent External Validation:** NOT_EVALUATED

**Legal Notice:** Model predictions and heuristic findings require qualified human investigator review. The system does not guarantee legal admissibility or establish criminal culpability.

---

## Additional Comparative Evaluation

| Metric | Rule-only | NLP-only | Hybrid |
|---|---:|---:|---:|
| Accuracy | 89.66% | 93.10% | 100% |
| Precision | 100% | 100% | 100% |
| Recall | 86.96% | 91.30% | 100% |
| F1-score | 93.02% | 95.45% | 100% |
| False positive rate | 0% | 0% | 0% |

All three methods were evaluated using the same
29 cleaned synthetic test records.

Hybrid detection combines the rule and ML decisions
using an OR operation.

Category-wise binary detection was evaluated across
nine synthetic categories, including benign records.

The hybrid result does not establish real-world
100% detection accuracy. The benchmark is small,
previously examined and subject to template similarity.

## Additional Functional Verification

- Preprocessing verification: 8/8 checks passed.
- External candidate SHAP explanations: 2,388/2,388.
- HackTheBox explanations: 2,377.
- DFRWS explanations: 11.
- Controlled investigation events: 12.
- Candidate findings: 9.
- Contextual groups: 9.
- Logging gaps: 0.
- Timeline processing time: 7.741 milliseconds.
- Latest report: REP-A4C2B790.
- Event-wise report entries: 9/9, user verified.

Event-wise coverage does not imply successful SHAP
attribution for every finding. Rule rationale and
explicit explanation limitations are reported separately.

Temporal proximity does not establish causation.
Manual investigation time savings are NOT_EVALUATED.

## Additional Evaluation Artifacts

- reports/evaluation/comparison/detection_comparison.json
- reports/evaluation/comparison/technique_wise_evaluation.json
- reports/evaluation/comparison/preprocessing_verification.json
- reports/evaluation/comparison/investigation_verification.json
- reports/evaluation/external/external_combined_summary.json
- reports/evaluation/external/shap_coverage_verification.json
- reports/evaluation/silrad/silrad_evaluation_summary.json
- reports/evaluation/silrad/silrad_ablation_summary.json
- reports/evaluation/independent_review/independent_validation_status.json
