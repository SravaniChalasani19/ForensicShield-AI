# ForensicShield AI - Academic Project Submission Checklist

**Project ID:** 218

**Project Title:** Anti-forensic Technique Detection via Natural Language Processing for Forensic Text/Log Analysis, Applied to Ransomware Incident Post-attack Investigation.

**Last Updated:** 25 November 2026

## 1. Implementation Checklist

- [x] Flask-based investigation dashboard.
- [x] Case creation and evidence ingestion.
- [x] SHA-256 evidence integrity verification.
- [x] Forensic log parsing and normalization.
- [x] TF-IDF feature extraction.
- [x] Random Forest binary classification.
- [x] Technique-specific heuristic rules.
- [x] Hybrid detection evaluation.
- [x] SHAP-based feature explanations.
- [x] Contextual investigation timeline.
- [x] Host-wise logging gap analysis.
- [x] Authorized local directory monitoring.
- [x] Controlled simulated replay.
- [x] Investigator-ready PDF generation.
- [x] Hash-linked audit verification.

## 2. Research Evaluation Results

| Evaluation | Result |
|---|---:|
| Original synthetic records | 5,400 |
| Cleaned unique records | 143 |
| Training records | 114 |
| Testing records | 29 |
| Exact train-test overlap | 0 |
| Rule-only accuracy | 89.66% |
| NLP-only accuracy | 93.10% |
| Hybrid accuracy | 100% |
| Category-wise evaluation | 9 categories |
| Preprocessing verification | 8/8 passed |
| External SHAP explanations | 2,388/2,388 |
| Investigation demonstration time | 7.741 ms |

The comparative detection results apply only to the small controlled synthetic benchmark. Similar-template overlap remains a limitation.

## 3. External Dataset Status

| Dataset | Records | Status |
|---|---:|---|
| HackTheBox LogJammer | 4,252 | External analysis completed; source checksum matched |
| DFRWS 2008 | 51 | Investigator annotations acquired and analyzed |
| SILRAD | 196,840 | Supporting ransomware telemetry acquired |
| Independent review sample | 50 | Awaiting independent reviewer labels |

Independent anti-forensic classification metrics remain NOT_EVALUATED.

## 4. Supporting SILRAD Evaluation

- Cleaned training records: 32,312.
- Cleaned testing records: 140,964.
- Input features: 36.
- Accuracy: 96.56%.
- Precision: 96.71%.
- Recall: 66.78%.
- F1-score: 79.01%.
- Feature attribution analysis: Completed.
- Identifier feature ablation: Completed.

This separate model evaluates ransomware versus goodware classification, not anti-forensic technique classification.

## 5. Investigation Demonstration

Case ID: CASE-218-FINAL-DEMO

- Total events: 12.
- Candidate findings: 9.
- Contextual groups: 9.
- Logging gaps: 0.
- Timeline processing time: 7.741 milliseconds.
- Evidence integrity verification: Demonstrated.
- PDF generation: Demonstrated.
- Audit verification: Demonstrated.

The demonstration uses controlled synthetic evidence. Candidate findings are not independently confirmed malicious events.

## 6. Submission Artifacts

- [x] Application source code.
- [x] Configuration and dependency files.
- [x] Windows startup scripts.
- [x] Primary trained model and metadata.
- [x] Supporting SILRAD model.
- [x] Cleaned synthetic datasets.
- [x] Dataset provenance manifest.
- [x] Evaluation results and graphs.
- [x] Independent review preparation files.
- [x] Sample forensic reports.
- [ ] Final synchronized documentation.
- [ ] Complete research citation verification.
- [ ] Complete PDF explanation coverage verification.
- [x] Final automated regression test report.
- [ ] Final verified ZIP archive.
- [ ] Archive integrity checksum.

## 7. Software Testing Status

Final automated regression testing was completed on
25 November 2026 in an isolated project copy.

- Total tests: 33.
- Passed tests: 33.
- Failed tests: 0.
- Errors: 0.
- Execution time: 10.739 seconds.
- Software test success rate: 100%.

### Final Application Corrections

- Corrected PDF report filename and download handling.
- Added automatic report list refresh after generation.
- Improved Feasibility Audit button feedback.
- Added visible case-specific Verify Audit feedback.
- Removed Survey Citations from the application interface.
- Preserved all eight research papers in documentation.
- Added PDF filename, format, download and SHA-256
  integrity assertions to existing regression tests.

All 33 automated tests passed after the corrections.

Detailed results are available in TEST_REPORT.md and
reports/evaluation/final_regression_results.txt.

Software test success does not establish real-world
detection accuracy or independent research validation.
## 8. Remaining Research Limitations

- Independent reviewer labeling is pending.
- Genuine ransomware post-attack validation is not established.
- Template-family-separated evaluation remains pending.
- Independent multiclass technique classification is not established.
- Manual versus automated investigation time comparison is not evaluated.
- Enterprise deployment and scalability require further validation.
- Formal legal admissibility is not independently certified.
- External dataset redistribution permissions require verification.

## 9. Application Startup

1. Extract the final verified project archive.
2. Open Command Prompt in the project directory.
3. Install the required dependencies if necessary.
4. Run `python app.py`.
5. Open http://127.0.0.1:5000 in a web browser.
6. Follow the demonstration guide.

## 10. Final Submission Status

Core application implementation: COMPLETED.

Controlled application demonstration: VERIFIED.

Independent research validation: PARTIALLY COMPLETED.

Final submission package: PENDING FINAL VERIFICATION.

ForensicShield AI is an academic investigation support prototype. Its findings require qualified investigator review and independent corroboration.