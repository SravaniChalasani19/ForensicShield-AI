# ForensicShield AI: Model Evaluation & Performance Report

**Project:** 218 – Final Year B.Tech Academic Project

**Model Identifier:** fs-rf-v1.0

**Project Title:** Anti-forensic Technique Detection via Natural Language Processing for Forensic Text/Log Analysis, Applied to Ransomware Incident Post-attack Investigation.

**Primary Methodology:** TF-IDF, Random Forest Classification, Rule-Based Detection and SHAP Explainability.

**Evaluation Date:** 25 November 2026

**Evaluation Status:** Preliminary Synthetic Evaluation Completed

**Independent External Validation:** NOT EVALUATED

---

## 1. Executive Summary

ForensicShield AI is an integrated digital forensic investigation support system designed to identify potential anti-forensic activities in system and event logs.

The system combines Natural Language Processing, machine learning, heuristic detection, explainable AI, evidence integrity verification, timeline analysis and automated forensic reporting.

The primary machine learning model was trained and evaluated using a cleaned synthetic dataset. Duplicate records were removed before constructing separate training and testing partitions.

The evaluation demonstrates the preliminary functionality of the proposed methodology. It does not establish real-world ransomware detection performance or independent external benchmark accuracy.

---

## 2. Dataset Preparation and Quality Assessment

The original synthetic corpus contained 5,400 records. Quality assessment identified substantial duplication in the original dataset.

A preprocessing procedure was implemented to remove duplicate normalized texts and construct separate training and testing datasets.

| Dataset Quality Parameter | Result |
|---|---:|
| Original synthetic records | 5,400 |
| Duplicate records removed | 5,257 |
| Conflicting label groups | 0 |
| Invalid label records identified | 0 |
| Empty text records | 0 |
| Unique records retained | 143 |
| Training records | 114 |
| Testing records | 29 |
| Exact train-test text overlap | 0 |

### Dataset Locations

- Original dataset: `data/synthetic/`
- Cleaned training dataset: `data/synthetic/cleaned/train_logs_clean.json`
- Cleaned testing dataset: `data/synthetic/cleaned/test_logs_clean.json`
- Dataset quality report: `data/synthetic/cleaned/dataset_quality_report.json`
- Dataset preparation script: `scripts/prepare_clean_datasets.py`

The original dataset is retained separately for traceability.

---

## 3. Dataset Category Distribution

The cleaned dataset contains benign records and eight anti-forensic technique categories.

| Category | Training | Testing |
|---|---:|---:|
| Benign | 21 | 6 |
| Windows event log clearing | 14 | 3 |
| Linux log clearing | 14 | 4 |
| Timestomping | 8 | 2 |
| Security tool disabling | 17 | 4 |
| Shell history clearing | 13 | 3 |
| Shadow copy deletion | 10 | 2 |
| Command obfuscation | 7 | 2 |
| File deletion | 10 | 3 |
| Total | 114 | 29 |

These categories describe the synthetic dataset annotations.

The primary machine learning model performs binary classification as Normal or Suspicious. Independent technique-level classification accuracy has not been established.

---

## 4. Train-Test Leakage Assessment

The cleaned training and testing datasets were checked for exact normalized text duplication.

- Exact train-test overlap: 0
- Unique training texts: 114
- Unique testing texts: 29

A supplementary text similarity assessment was performed using SequenceMatcher.

| Similarity Parameter | Result |
|---|---:|
| Test records examined | 29 |
| Records with maximum similarity of at least 85% | 5 |
| Records with maximum similarity of at least 90% | 3 |
| Maximum observed similarity | 95.56% |

Exact duplicate leakage was eliminated in the cleaned partitions. However, similar-template leakage risk remains.

Therefore, the results are classified as preliminary synthetic evaluation rather than independent real-world validation.

---

## 5. Primary Model Architecture

### 5.1 Text Preprocessing

Forensic text is normalized through whitespace normalization, lowercase conversion and removal of unnecessary control characters.

### 5.2 Feature Extraction

TF-IDF converts normalized forensic text into numerical feature vectors.

The vectorizer is fitted using the cleaned training partition.

### 5.3 Classification

A Random Forest classifier performs binary classification:

- Normal
- Suspicious

The trained model contains a vocabulary of 155 features.

### 5.4 Rule-Based Detection

Heuristic detection rules identify predefined suspicious indicators independently of machine learning predictions.

Rule-based findings and machine learning findings are presented as candidate indicators requiring investigator review.

### 5.5 Explainable AI

SHAP provides local feature attribution explanations for model predictions.

These explanations support interpretation of statistical model behavior.

### 5.6 Model Integrity

The trained model pipeline is stored as a serialized model artifact with SHA-256 integrity information.

**Model pipeline SHA-256:**

`14cd1670c79f600649b19eeea9214a8b3d9a03aabf47e6437df8cc1b4d517bad`

Automatic retraining through the application interface is disabled to reduce accidental model replacement.

---

## 6. Verified Model Evaluation Results

The primary model was evaluated using 29 cleaned held-out synthetic records.

| Evaluation Metric | Measured Result |
|---|---:|
| Total test records | 29 |
| Normal test records | 6 |
| Suspicious test records | 23 |
| Accuracy | 93.10% |
| Precision (Suspicious Class) | 100.00% |
| Recall (Suspicious Class) | 91.30% |
| F1-Score (Suspicious Class) | 95.45% |
| False Positive Rate | 0.00% |
| Vocabulary size | 155 |

The reported F1-score represents the suspicious class and is not a macro-averaged F1-score.

These metrics apply only to the cleaned synthetic test partition.

---

## 7. Confusion Matrix

| Actual Class | Predicted Normal | Predicted Suspicious |
|---|---:|---:|
| Actual Normal | 6 | 0 |
| Actual Suspicious | 2 | 21 |

- True Positives: 21
- True Negatives: 6
- False Positives: 0
- False Negatives: 2

The model correctly classified 27 out of 29 synthetic test records.

Two suspicious records were incorrectly classified as normal. These false negatives demonstrate the need for supplementary heuristic detection and human investigation.

The absence of false positives in this small test partition does not establish a zero false positive rate in real-world environments.

---

## 8. External Dataset Analysis and Validation

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

## 9. Explainable AI Functional Verification

The SHAP explanation functionality was demonstrated successfully through the application interface and generated forensic PDF reports.

The system presents:

- Local feature contribution values.
- Features contributing towards suspicious predictions.
- Features contributing towards normal predictions.
- Statistical prediction explanations.
- Investigator interpretation disclaimers.

SHAP explains the behavior of the trained model. It does not establish attacker intent, malicious causation or legal guilt.

Independent mathematical consistency testing and systematic explanation-quality evaluation remain pending.

---

## 10. End-to-End Application Verification

A controlled demonstration was performed using case identifier `CASE-218-FINAL-DEMO`.

| Application Component | Verification Status |
|---|---|
| Case creation | Passed |
| Evidence upload | Passed |
| Log parsing | Passed |
| SHA-256 evidence integrity verification | Passed |
| Machine learning inference | Passed |
| Rule-based detection | Passed |
| Log explorer | Passed |
| SHAP explanation generation | Passed |
| Investigation timeline | Passed |
| PDF report generation | Passed |
| PDF report download | Passed |
| Audit chain verification | Passed |
| Dataset manifest download | Passed |
| Synthetic evaluation dashboard | Passed |

### Demonstration Results

- Evidence source: Controlled synthetic smoke-test logs.
- Total parsed events: 12.
- Candidate findings: 9.
- Event-wise report entries: 9/9 (user verified).
- Audit verification was demonstrated previously.
- Audit chain verification status: VALID.
- Updated report identifier: REP-A4C2B790.

These results demonstrate application functionality and do not represent nine independently confirmed malicious events.

---

## 11. Evidence Integrity and Chain of Custody

The application calculates SHA-256 digests for ingested evidence and generated forensic reports.

Hash-linked audit records support verification of recorded investigation actions.

The demonstrated audit verification confirms consistency of the checked cryptographic links.

Hashing and hash-linked records do not independently establish source authenticity, prevent all possible tampering or guarantee legal admissibility.

---

## 12. Live Monitoring and Replay Functionality

The application supports monitoring of an authorized local log directory and controlled replay of forensic log records.

Live directory monitoring, replay, pause, resume and stop functionality were demonstrated.

Simulated replay is distinguished from local directory ingestion.

This functionality does not establish that the application has been validated against an active real-world ransomware attack.

---

## 13. Research Limitations

1. The cleaned synthetic dataset contains only 143 unique records.

2. The held-out testing partition contains only 29 records.

3. Similar-template leakage risk remains despite exact duplicate removal.

4. Independent anti-forensic ground truth remains unavailable despite external source acquisition.

5. The primary model performs binary classification rather than independently validated technique-level classification.

6. False negatives remain present in the synthetic evaluation.

7. Training text representation and canonical application input representation may differ.

8. SHAP explanations represent statistical feature contributions and require investigator interpretation.

9. Real-world generalization, cross-environment robustness and large-scale operational performance have not been established.

10. Cryptographic integrity verification does not guarantee source authenticity or courtroom admissibility.

---

## 14. Reproducibility and Execution

The following commands are executed from the project root directory.

### Prepare Cleaned Synthetic Dataset

`python scripts/prepare_clean_datasets.py`

### Train Primary Model

`python scripts/train_full_model.py`

### Evaluate Cleaned Synthetic Test Dataset

`python scripts/run_evaluation.py --clean-synthetic`

### Check External Dataset Status

`python scripts/check_datasets.py`

### Check Default External Evaluation Status

`python scripts/run_evaluation.py`

### Launch Application

`python app.py`

Application address: `http://127.0.0.1:5000`

The existing trained model does not require retraining for normal application demonstration.

---

## 15. Future Research and Validation

Future work should include:

- Expansion of external datasets and further independent provenance verification.
- Independent expert annotation of anti-forensic log records.
- Template-family-separated evaluation.
- Larger and more diverse testing datasets.
- Consistent training and inference feature representation.
- Independent technique-level classification experiments.
- Systematic SHAP explanation-quality assessment.
- Real-world forensic investigation validation under authorized conditions.

Exploratory transformer and multi-label approaches are not included in the verified primary evaluation results.

---

## 16. Conclusion

ForensicShield AI demonstrates an integrated approach to anti-forensic indicator detection using Natural Language Processing, Random Forest classification, heuristic rules, SHAP explainability, timeline investigation, SHA-256 evidence verification and forensic PDF reporting.

The primary model achieved 93.10% accuracy and a suspicious-class F1-score of 95.45% on 29 cleaned held-out synthetic records.

The application successfully completed the controlled end-to-end forensic investigation demonstration.

The results establish preliminary implementation functionality and synthetic benchmark performance. Independent external validation and real-world generalization remain pending.

**Final Evaluation Status: PRELIMINARY_SYNTHETIC_EVALUATION**

**Independent External Benchmark Status: NOT_EVALUATED**

**Legal Notice:** All findings are intended to support qualified investigator review. Legal admissibility depends on applicable law, evidence handling procedures and judicial evaluation.

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
