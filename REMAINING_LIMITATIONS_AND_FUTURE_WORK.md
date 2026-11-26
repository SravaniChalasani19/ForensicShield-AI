# ForensicShield AI — Remaining Limitations, Legal Boundaries and Future Work

**Project ID:** 218

**Project Title:** Anti-forensic Technique Detection via Natural Language Processing for Forensic Text/Log Analysis, Applied to Ransomware Incident Post-attack Investigation.

**Extension:** Explainable AI Reporting to Support Evidence Review and Legal Admissibility Procedures, with Proposed Validation on CTF-Style Forensic Challenge Datasets (DFRWS and HackTheBox Forensics).

**Last Updated:** 25 November 2026

**Implementation Status:** Integrated Application Functionally Demonstrated

**Evaluation Status:** PRELIMINARY_SYNTHETIC_EVALUATION

**Independent External Validation:** NOT_EVALUATED

---

## 1. Executive Summary

ForensicShield AI was developed as an integrated digital forensic investigation support application combining Natural Language Processing, machine learning, heuristic detection, Explainable AI, contextual investigation, evidence integrity verification and automated forensic reporting.

The primary application workflow has been successfully demonstrated using controlled synthetic forensic logs.

However, successful application execution does not establish complete scientific validation or real-world forensic reliability.

This document describes the completed research contributions, remaining technical limitations, external dataset constraints, legal boundaries and future research requirements.

---

## 2. Research Limitations Addressed by the Proposed System

| Identified Research Limitation | Proposed Implementation | Current Achievement |
|---|---|---|
| Time-consuming manual forensic log analysis | Automated ingestion and normalization | Functionally demonstrated |
| Limited automated anti-forensic detection | TF-IDF, Random Forest and heuristic rules | Binary detection implemented |
| Limitations of keyword-only detection | NLP-based machine learning classification | Preliminary synthetic evaluation completed |
| Limited explainability | SHAP feature attribution | Functionally demonstrated |
| Limited investigation context | Contextual timeline and logging gap analysis | Functionally demonstrated |
| Evidence integrity and traceability concerns | SHA-256 hashing and hash-linked audit records | Integrity verification demonstrated |
| Limited integrated forensic reporting | Automated ReportLab PDF generation | Functionally demonstrated |
| Limited independent external validation | External inference and independent review preparation | Partially addressed; independent metrics pending |

The proposed system addresses several functional research gaps.

These gaps have not been completely resolved at the level of independent scientific validation.

---

## 3. Completed Implementation

The following components are available in the current application:

- Flask-based forensic investigation dashboard.
- Investigation case creation and management.
- Forensic evidence ingestion.
- SHA-256 evidence integrity verification.
- Canonical forensic log normalization.
- TF-IDF feature extraction.
- Random Forest binary classification.
- Independent heuristic detection rules.
- SHAP-based local explanations.
- Contextual investigation timeline.
- Logging gap analysis.
- Authorized local directory monitoring.
- Controlled simulated replay.
- Investigator-ready forensic PDF generation.
- Hash-linked investigation audit records.
- Dataset feasibility and provenance manifest.
- Preliminary synthetic model evaluation.

The integrated workflow was demonstrated using controlled synthetic evidence.

---

## 4. Remaining Dataset Limitations

### 4.1 Limited Unique Dataset Size

The original synthetic corpus contained 5,400 records.

Dataset quality analysis identified substantial duplication.

| Dataset Parameter | Result |
|---|---:|
| Original synthetic records | 5,400 |
| Duplicate records removed | 5,257 |
| Unique records retained | 143 |
| Training records | 114 |
| Testing records | 29 |
| Exact train-test overlap | 0 |

Although duplicate removal improved dataset quality, the remaining corpus is relatively small.

The model may not generalize reliably to previously unseen forensic environments.

### 4.2 Similar-Template Leakage Risk

Exact normalized text overlap between the cleaned training and testing partitions was eliminated.

However, supplementary similarity analysis identified:

- Five test records with similarity of at least 85%.
- Three test records with similarity of at least 90%.
- Maximum observed similarity of 95.56%.

Consequently, similar-template leakage risk has not been fully eliminated.

Future evaluation should separate records according to template families and original evidence sources.

### 4.3 Limited Testing Partition

The current evaluation contains only 29 synthetic testing records.

The resulting performance estimates must be interpreted cautiously.

Larger and more diverse independent testing datasets are required.

### 4.4 Class Imbalance

The cleaned dataset contains 27 normal records and 116 suspicious records.

Balanced class weighting is used in the Random Forest classifier.

Nevertheless, the limited number of normal examples may affect the reliability of false positive rate estimates.

---

## 5. External Dataset Validation Constraints

| Dataset | Records | Research Status |
|---|---:|---|
| HackTheBox LogJammer | 4,252 | Source checksum matched; inference completed |
| DFRWS 2008 | 51 | Published investigator annotations analyzed |
| SILRAD | 196,840 | Supporting ransomware dataset evaluated |
| Cleaned synthetic corpus | 143 | Preliminary synthetic evaluation completed |

### HackTheBox

- Parsed records: 4,252.
- ML-only candidates: 2,361.
- Combined ML and rule candidates: 16.
- No indicator, unverified: 1,727.
- Insufficient vocabulary: 148.
- Successful candidate SHAP explanations: 2,377.

The original archive checksum matched the official
reference checksum.

One official reference event was matched.
Complete independent record-level ground truth
remains unavailable.

The challenge is not a confirmed ransomware incident.

### DFRWS

- Published investigator annotations: 51.
- ML candidates: 11.
- Insufficient vocabulary: 40.
- Successful candidate SHAP explanations: 11.

These records are investigator annotations,
not original raw system logs.

### SILRAD

The downloaded dataset contains 36 numeric input
features and one class column.

The primary NLP model is incompatible with this
numeric representation.

A separate Random Forest classifier was evaluated
after duplicate, conflicting-label and exact overlap
removal.

- Cleaned training records: 32,312.
- Cleaned testing records: 140,964.
- Accuracy: 96.56%.
- Precision: 96.71%.
- Recall: 66.78%.
- F1-score: 79.01%.
- False positive rate: 0.24%.

Supporting SHAP analysis and identifier-feature
ablation were completed.

The cleaned reduced-feature experiment achieved
95.14% accuracy and 60.40% F1-score on a different
cleaned test population.

These results evaluate ransomware versus goodware,
not anti-forensic technique classification.

Published feature-schema correspondence and
ransomware-family-independent generalization
remain unverified.

### Independent Review

A 50-record independent review sample was prepared:

- HackTheBox: 30.
- DFRWS: 20.
- Reviewed records: 0.
- Status: AWAITING_INDEPENDENT_REVIEW.

Independent external anti-forensic accuracy,
precision, recall and F1-score remain NOT_EVALUATED.

Dataset redistribution permissions require verification.

---

## 6. Machine Learning Performance Limitations

The primary TF-IDF and Random Forest model was evaluated on 29 cleaned synthetic testing records.

| Metric | Result |
|---|---:|
| Accuracy | 93.10% |
| Precision (Suspicious) | 100.00% |
| Recall (Suspicious) | 91.30% |
| F1-Score (Suspicious) | 95.45% |
| False Positive Rate | 0.00% |

### Confusion Matrix

| Actual Class | Predicted Normal | Predicted Suspicious |
|---|---:|---:|
| Normal | 6 | 0 |
| Suspicious | 2 | 21 |

The evaluation identified two false negatives.

Therefore, the model does not detect every suspicious record.

The absence of false positives among six normal test records does not establish a zero false positive rate in practical forensic investigations.

These results represent preliminary synthetic performance only.

---

## 7. NLP and Classification Limitations

### 7.1 Limited Temporal Understanding

TF-IDF represents textual feature occurrence and importance.

It does not directly model long-range temporal relationships between separate forensic events.

The investigation timeline provides supplementary context but is not a replacement for a validated temporal learning model.

### 7.2 Unseen Forensic Patterns

Previously unseen terminology, log formats and complex text variations may reduce classification reliability.

### 7.3 Legitimate Administrative Activity

Normal system administration may produce records resembling suspicious anti-forensic indicators.

Such findings require contextual investigation and independent corroboration.

### 7.4 Training and Inference Representation

The training pipeline and application-level canonical event representation may contain different combinations of textual fields.

These differences may affect prediction consistency.

A unified feature preparation methodology should be implemented and evaluated in future work.

### 7.5 Out-of-Vocabulary Inputs

Records containing little or no recognized vocabulary may receive unreliable classifications.

External batch analysis now identifies insufficient vocabulary explicitly. Consistent handling across all application inference paths requires further testing.

### 7.6 Technique-Level Classification

The synthetic dataset contains eight anti-forensic technique categories.

However, the verified primary machine learning model performs binary classification:

- Normal
- Suspicious

Independent multi-class or multi-label technique classification performance has not been established.

---

## 8. Explainable AI Limitations

SHAP TreeExplainer provides local statistical feature attributions for Random Forest predictions.

The explanation interface and PDF attribution highlights were successfully demonstrated.

However:

- SHAP does not independently verify prediction correctness.
- Feature importance does not establish malicious intent.
- Statistical associations do not establish causation.
- Explanations may emphasize generic or weakly informative tokens.
- Independent mathematical consistency testing remains pending.
- Systematic explanation-quality evaluation remains pending.
- The updated PDF includes event-wise entries for all flagged events, with explicit limitations where explanations are unavailable.

Future research should assess explanation stability, relevance and usefulness through independent expert review.

---

## 9. Investigation Timeline Limitations

The application provides contextual event review and logging gap analysis.

These features assist investigators in identifying potentially relevant surrounding events.

However:

- Temporal proximity does not establish causation.
- Missing records may result from ordinary system inactivity.
- Logging gaps may arise from technical or administrative reasons.
- Incomplete evidence can limit investigation reconstruction.
- The current timeline is not a validated automated attack reconstruction system.

All timeline findings require investigator interpretation.

---

## 10. Evidence Integrity and Chain-of-Custody Boundaries

The application implements SHA-256 hashing and hash-linked audit records.

These mechanisms support:

- Verification of ingested evidence bytes.
- Model artifact integrity checking.
- Generated report integrity checking.
- Detection of inconsistencies in recorded audit links.

### Remaining Integrity Limitations

- SHA-256 does not independently establish evidence source authenticity.
- Local evidence storage is not guaranteed to be physically immutable.
- Hash-linked records do not prevent every possible form of unauthorized modification.
- A valid audit chain does not independently prove that every investigative action was recorded.
- Hardware write-blocker integration has not been established.
- Independent trusted timestamping and external audit anchoring remain future work.
- Formal chain-of-custody procedures require additional organizational controls.

The application supports evidence integrity verification but does not replace professional forensic acquisition and custody procedures.

---

## 11. Legal and Evidentiary Boundaries

ForensicShield AI is an investigative decision-support application.

Its outputs are candidate findings requiring qualified human review.

The system does not independently establish:

- Criminal intent.
- Identity of a responsible individual.
- Legal guilt.
- Evidence authenticity at the original source.
- Guaranteed courtroom admissibility.

Legal admissibility depends on applicable jurisdiction, evidence acquisition procedures, documented chain of custody, expert validation and judicial assessment.

The generated reports are investigator-ready supporting documents rather than automatically court-admissible evidence.

Compliance with any specific legal evidentiary standard has not been independently established.

---

## 12. Live Monitoring and Simulated Replay Limitations

### 12.1 Simulated Replay

The application supports controlled incremental replay of prepared forensic logs.

Simulated replay is intended for academic demonstrations and functionality testing.

It does not establish real-time detection of an actual ransomware attack.

### 12.2 Authorized Local Directory Monitoring

The application supports monitoring an authorized local directory for incoming forensic records.

The demonstrated monitoring functionality uses local filesystem-based ingestion.

It does not establish direct enterprise-wide endpoint monitoring.

### 12.3 Remaining Deployment Requirements

- Authenticated log collection infrastructure.
- Secure communication mechanisms.
- Access control and role management.
- Reliable centralized evidence storage.
- Enterprise-scale performance testing.
- Independent security assessment.
- Operational monitoring and recovery procedures.

Production deployment requires additional engineering and validation.

---

## 13. Core Implementation and Optional Research

| Component | Current Status |
|---|---|
| TF-IDF feature extraction | Implemented |
| Random Forest binary classification | Implemented and preliminarily evaluated |
| Heuristic forensic detection | Functionally demonstrated |
| SHAP explainability | Functionally demonstrated |
| Investigation timeline | Functionally demonstrated |
| SHA-256 integrity verification | Functionally demonstrated |
| Hash-linked audit records | Functionally demonstrated |
| ReportLab PDF generation | Functionally demonstrated |
| Local directory monitoring | Functionally demonstrated |
| Simulated replay | Functionally demonstrated |
| Independent external validation | Pending |
| DistilBERT comparative evaluation | Not established |
| Multi-label technique classification | Not independently evaluated |
| Enterprise deployment | Future work |

Exploratory deep learning and multi-label approaches are not part of the verified primary model evaluation.

---

## 14. Final Application Demonstration

**Case Identifier:** CASE-218-FINAL-DEMO

**Evidence Type:** Controlled synthetic smoke-test logs

| Demonstration Parameter | Result |
|---|---|
| Parsed forensic records | 12 |
| Candidate findings | 9 |
| Evidence hash verification | Passed |
| Model inference | Passed |
| SHAP explanation | Passed |
| Timeline investigation | Passed |
| PDF generation and download | Passed |
| Audit chain verification | Passed |
| Updated report identifier | REP-A4C2B790 |

The generated report includes preliminary synthetic evaluation metrics and independent external validation limitations.

The nine candidate findings are not nine independently confirmed malicious events.

The latest complete automated regression test suite results have not been independently verified following the final corrections.

---

## 15. Future Work and Technical Roadmap

### Priority 1: Genuine External Dataset Validation

Complete independent annotation of the prepared 50-record sample and expand authorized external forensic datasets.

Conduct external evaluation using accuracy, precision, recall, F1-score, false positive rate and confusion matrices.

### Priority 2: Improved Dataset Quality

Expand the number and diversity of forensic records.

Implement template-family-separated training and testing partitions to reduce remaining leakage risk.

### Priority 3: Consistent Feature Engineering

Use a unified feature representation for model training and application inference.

Introduce explicit review-required handling for unfamiliar inputs.

### Priority 4: Technique-Level Classification

Develop and independently evaluate multi-class or multi-label classification using reliable technique annotations.

### Priority 5: Improved Explainable AI

Conduct systematic SHAP consistency, stability and explanation-quality assessments.

Obtain independent forensic expert feedback.

### Priority 6: Advanced Contextual Investigation

Improve cross-event relationships, host-specific context and investigation timeline reconstruction.

Evaluate temporal learning approaches using independently annotated forensic sequences.

### Priority 7: Enhanced Evidence Integrity

Explore restricted evidence storage, digitally signed

---

## Updated Research Contributions and Remaining Boundaries

| Research Gap | Implemented Improvement | Remaining Boundary |
|---|---|---|
| Manual analysis | Automated ingestion, detection and reporting | Manual time savings not measured |
| Limited anti-forensic classification | Binary NLP and technique-specific rules | Independent multiclass evaluation pending |
| Keyword-only limitations | Rule, NLP and hybrid comparison | Real-world generalization pending |
| Limited explainability | SHAP and event-wise reporting | Independent explanation-quality assessment pending |
| Limited investigation context | Timeline and contextual grouping | Causal reconstruction not established |
| Evidence integrity | SHA-256 and hash-linked audit | Immutable storage and legal certification pending |
| Dataset generalization | External acquisition, inference and supporting SILRAD evaluation | Independent anti-forensic labels pending |

### Comparative Evaluation

| Metric | Rule-only | NLP-only | Hybrid |
|---|---:|---:|---:|
| Accuracy | 89.66% | 93.10% | 100% |
| Precision | 100% | 100% | 100% |
| Recall | 86.96% | 91.30% | 100% |
| F1-score | 93.02% | 95.45% | 100% |

All results use the same 29 cleaned synthetic
test records.

The hybrid method combines rule and ML decisions.

The benchmark is small and previously examined.
Similar-template leakage risk remains.

Category-wise binary detection was evaluated
across nine synthetic categories, including benign.

The results do not establish independently
validated multiclass technique classification.

### Additional Verification

- Preprocessing checks: 8/8 passed.
- External candidate SHAP coverage: 2,388/2,388.
- Investigation events: 12.
- Candidate findings: 9.
- Contextual groups: 9.
- Logging gaps: 0.
- Timeline processing time: 7.741 milliseconds.
- Latest report: REP-A4C2B790.
- Event-wise PDF entries: 9/9, user verified.

Event-wise entries do not guarantee successful SHAP
attribution for every event.

Rule rationale and unavailable explanations are
reported explicitly.

### Final Research Boundary

The integrated application is functionally demonstrated.

Independent real-world ransomware investigation
validation remains NOT_EVALUATED.

Manual investigation time savings remain NOT_EVALUATED.

The project supports qualified investigator review
and does not guarantee legal admissibility.

The earlier regression suite passed 33/33 tests.
A new complete regression run is required following
the latest implementation changes.
