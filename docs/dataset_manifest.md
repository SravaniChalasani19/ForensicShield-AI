# ForensicShield AI: Dataset & Feasibility Manifest
**Project 218 Specification Compliance Document**  
*Anti-Forensic Technique Detection via Natural Language Processing for Forensic Text/Log Analysis, Applied to Ransomware Incident Post-Attack Investigation*

---

## 1. Feasibility Gate & Provenance Audit

Under Section 4.1 of the Final Implementation Blueprint, a mandatory feasibility audit of available forensic datasets was conducted prior to model training and evaluation:

1. **HackTheBox Forensics (including LogJammer)**:
   - **Status**: Not supplied in the workspace repository.
   - **Reason**: HTB challenges require authorized account access and lawful participation. Furthermore, raw challenge artifacts (such as EVTX log files) do not come with pre-annotated, per-record ground-truth labels for anti-forensic techniques.
   - **Action**: Ingestion adapters are implemented and verified. Empirical metrics for HTB remain marked as `"Not evaluated"` until authorized files and verified ground-truth labels are deposited in `data/external/htb/`.

2. **DFRWS Forensic Challenges**:
   - **Status**: Not supplied in the workspace repository.
   - **Reason**: DFRWS Rodeo artifacts must be downloaded from the official conference repository and manually annotated by an investigator.
   - **Action**: Log parsers support common DFRWS syslog/auth.log exports. Marked as `"Not evaluated"` until external ground-truth logs are provided in `data/external/dfrws/`.

3. **SILRAD (Survey Reference 1)**:
   - **Status**: Not supplied.
   - **Distinction**: SILRAD is an academic Sysmon dataset for ransomware behavior. As mandated in the Blueprint, SILRAD provides sample-level ransomware execution labels, **not** anti-forensic technique ground truth. SILRAD must never be claimed as a main anti-forensic benchmark.

4. **Controlled Software Test Fixtures**:
   - **Status**: Available in `data/fixtures/`.
   - **Purpose**: Strictly for software unit tests, parsing smoke tests, pipeline integrity tests, and local demonstration.
   - **Strict Policy**: Synthetic samples are explicitly identified and never reported as proof of empirical real-world efficacy.

---

## 2. Dataset Feasibility Summary Table

| Dataset ID | Title | Format | Ground Truth Status | Local Availability | Role in Project 218 |
|---|---|---|---|---|---|
| `HTB-LOGJAMMER-2024` | HTB Forensics: LogJammer | EVTX / Windows Logs | Unlabeled Challenge | Pending deposit | Primary candidate validation |
| `DFRWS-FORENSIC-CHALLENGE` | DFRWS Forensic Challenge Logs | Syslog / Auditd / CSV | Unlabeled Challenge | Pending deposit | Secondary independent validation |
| `SILRAD-2025-SUPPORTING` | SILRAD Ransomware Telemetry | Sysmon CSV | Malware-level only | Pending deposit | Supporting comparative analysis |
| `CONTROLLED-BENIGN-SYNTHETIC-FIXTURES` | Software Verification Fixtures | JSON / CSV / TXT | Verified (Test Fixture) | Available | Unit & UI smoke testing only |

---

## 3. Data Ingestion & Canonical Schema

All ingested logs are parsed into the unified canonical schema:
- `case_id`, `evidence_id`, `event_id`
- `source_path`, `source_sha256`, `original_row`
- `timestamp_original`, `timestamp_utc`
- `host`, `provider`, `event_code`, `user`
- `raw_message`, `normalized_text`
- `ground_truth_label`, `label_source`
- `predicted_label`, `model_version`, `score`
- `rule_flags`, `shap_features`

Missing fields are preserved as `null` rather than fabricated.
