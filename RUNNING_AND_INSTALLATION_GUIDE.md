# ForensicShield AI — Complete Running, Installation, and Demonstration Guide
**Project Title:** Anti-forensic Technique Detection via Natural Language Processing for Forensic Text/Log Analysis, Applied to Ransomware Incident Post-attack Investigation, Enhanced via Explainable AI Reporting for Court-admissible Evidence, Validated on CTF-style Forensic Challenge Datasets (DFRWS, HackTheBox Forensics)  
**Project ID:** 218 | Final Year B.Tech Engineering Project  
**Authoritative Documentation & Step-by-Step Operator Manual**

---

## Table of Contents
1. [System Prerequisites & Compatibility](#1-system-prerequisites--compatibility)
2. [Project Directory & File Structure](#2-project-directory--file-structure)
3. [Environment Setup & Dependency Installation](#3-environment-setup--dependency-installation)
4. [One-Click Windows Launcher (`start_project.bat`)](#4-one-click-windows-launcher-start_projectbat)
5. [Tested Manual Startup via PowerShell / CMD](#5-tested-manual-startup-via-powershell--cmd)
6. [Port Configuration & Dynamic Fallback](#6-port-configuration--dynamic-fallback)
7. [Accessing the Dashboard Web Interface](#7-accessing-the-dashboard-web-interface)
8. [Tab 1: Dashboard Overview & System Metrics](#8-tab-1-dashboard-overview--system-metrics)
9. [Creating a New Forensic Investigation Case](#9-creating-a-new-forensic-investigation-case)
10. [Tab 2: Evidence Intake & SHA-256 Ingestion](#10-tab-2-evidence-intake--sha-256-ingestion)
11. [Tab 3: Canonical Log Explorer & Filtering](#11-tab-3-canonical-log-explorer--filtering)
12. [Running Machine Learning Anti-Forensic Detection](#12-running-machine-learning-anti-forensic-detection)
13. [Interpreting SHAP Explainability Visualizations](#13-interpreting-shap-explainability-visualizations)
14. [Tamper-Evident Examiner Annotations](#14-tamper-evident-examiner-annotations)
15. [Tab 4: Post-Attack Investigation Timeline & Silent Gap Detection](#15-tab-4-post-attack-investigation-timeline--silent-gap-detection)
16. [Tab 5: Live Ingestion vs. Simulated Replay Monitoring](#16-tab-5-live-ingestion-vs-simulated-replay-monitoring)
17. [Tab 6: Structured Forensic PDF Report Generation](#17-tab-6-structured-forensic-pdf-report-generation)
18. [Downloading and Inspecting Generated PDF Reports](#18-downloading-and-inspecting-generated-pdf-reports)
19. [Verifying Cryptographic Chain-of-Custody Audit Trail](#19-verifying-cryptographic-chain-of-custody-audit-trail)
20. [Tab 7: External Dataset Feasibility & Ingestion Guidelines](#20-tab-7-external-dataset-feasibility--ingestion-guidelines)
21. [Tab 8: Empirical Validation & Benchmark Evaluation](#21-tab-8-empirical-validation--benchmark-evaluation)
22. [Executing the Complete Automated Test Suite](#22-executing-the-complete-automated-test-suite)
23. [Safe Application Shutdown Procedure](#23-safe-application-shutdown-procedure)

---

## 1. System Prerequisites & Compatibility

| Requirement | Supported Version | Notes |
| :--- | :--- | :--- |
| **Operating System** | Windows 10, Windows 11 (64-bit) | Fully compatible with folder paths containing spaces & OneDrive paths |
| **Python** | Python 3.10, 3.11, or 3.12 | Ensure `Add Python to PATH` was selected during installation |
| **RAM** | 4 GB minimum (8 GB recommended) | Required for TreeSHAP background explainer cache |
| **Disk Space** | 500 MB free disk space | Required for virtual environment, models, and SQLite database |
| **Web Browser** | Google Chrome, Microsoft Edge, Mozilla Firefox | Modern Chromium or Gecko engine with JavaScript enabled |

---

## 2. Project Directory & File Structure

The project root directory contains:
```text
new project/
├── data/
│   ├── evidence/          # Read-only ingested original evidence files (SHA-256 preserved)
│   ├── external/          # Drop folders for DFRWS, HackTheBox, and SILRAD datasets
│   │   ├── dfrws/
│   │   ├── htb/
│   │   └── silrad/
│   └── fixtures/          # Benchmark test fixtures for instant reproducibility
├── database/              # SQLite persistent database (forensicshield.db)
├── models/                # Trained Random Forest pipeline (.joblib) & metadata (.json)
├── reports/               # Tamper-evident generated forensic PDF reports
├── src/
│   ├── api/               # Flask application routes and RESTful endpoints
│   ├── explainability/    # TreeSHAP explainer engine & investigative rationales
│   ├── ingestion/         # SHA-256 intake, parsers (CSV, JSON, EVTX, TXT), adapters
│   ├── models/            # TF-IDF feature extraction, Random Forest classifier
│   ├── reporting/         # ReportLab forensic PDF generation engine
│   ├── storage/           # Database schema, repository layer, audit ledger
│   └── timeline/          # Chronological reconstruction & silent log gap detector
├── static/
│   ├── css/style.css      # Executive Light Theme (Soft slate, Navy blue, White cards)
│   └── js/app.js          # Asynchronous single-page controller & API bindings
├── templates/
│   └── index.html         # Responsive 8-tab forensic investigation interface
├── tests/                 # Complete 33-test automated regression suite
├── run.py                 # Intelligent Python launcher with auto-port & health probe
├── start_project.bat      # Safe one-click Windows batch launcher
├── run.ps1                # Native Windows PowerShell launcher
├── requirements.txt       # Exact Python package dependencies
└── README.md              # Project technical specification and overview
```

---

## 3. Environment Setup & Dependency Installation

Open PowerShell or Command Prompt, navigate to the project directory, and initialize a Python virtual environment:

```powershell
# 1. Navigate to project folder
cd "c:\Users\Sravani Chalasani\OneDrive\Documents\new project"

# 2. Create isolated virtual environment
python -m venv venv

# 3. Activate the virtual environment
# In PowerShell:
.\venv\Scripts\Activate.ps1
# In Command Prompt (cmd.exe):
.\venv\Scripts\activate.bat

# 4. Install verified dependencies
pip install -r requirements.txt
```

---

## 4. One-Click Windows Launcher (`start_project.bat`)

Double-click `start_project.bat` from Windows File Explorer or execute from terminal:

```cmd
.\start_project.bat
```

### How the Launcher Prevents the Browser "Reload" Error
Previous versions experienced a connection error because the browser was opened on a fixed timer before scientific libraries finished importing. The revised launcher:
1. Validates that Python is installed and accessible.
2. Checks all mandatory packages (`flask`, `sklearn`, `shap`, `reportlab`, `pandas`).
3. Automatically launches the Flask server in the background.
4. **Health Probe:** Spawns an internal health monitor that polls `http://127.0.0.1:5000/api/health`.
5. Opens your default web browser **only after receiving HTTP 200 OK** from the active server.
6. Keeps the terminal window open with full operational logs if any unexpected error occurs.

---

## 5. Tested Manual Startup via PowerShell / CMD

If you prefer launching directly via Python:

```powershell
python run.py
```

The script will display:
```text
======================================================================
  ForensicShield AI — Project 218 Final Technical Specification
======================================================================
  [+] Python Version: 3.11.x
  [+] Project Directory: C:\Users\...\new project
  [+] Checking dependencies...
  [+] Initializing SQLite database schema and audit genesis block...
  [+] Database verified.
  [+] Loading primary TF-IDF + Random Forest model...
  [+] Primary Model: models/forensicshield_rf_pipeline.joblib (READY)
  [*] Starting Flask application server on http://127.0.0.1:5000 ...
  [*] Health-probe active: Browser will open automatically once healthy.
```

---

## 6. Port Configuration & Dynamic Fallback

- **Default Port:** `5000`
- **Fallback Port:** `5001`
- If port `5000` is currently occupied by another process, `run.py` automatically binds to `5001` and opens the browser to the correct active address. You can also override the port manually:
  ```powershell
  python run.py --port 5005
  ```

---

## 7. Accessing the Dashboard Web Interface

Open your browser to:
```text
http://127.0.0.1:5000
```
The interface will load with the newly redesigned **Executive Light Theme**:
- Clean slate/light blue background (`#f8fafc`).
- Deep Navy header and navigation tabs (`#0f172a`).
- High-contrast white content cards (`#ffffff`).
- Prominent legal admissibility banner reminding examiners that AI findings are advisory triage tools.

---

## 8. Tab 1: Dashboard Overview & System Metrics

When opening Tab 1 (**📊 Dashboard**), you will see:
1. **Summary Metrics Grid:**
   - **Registered Cases:** Total number of open investigation files.
   - **Imported Evidence Files:** SHA-256 hashed original evidence containers.
   - **Canonical Log Records:** Normalized events stored in the database.
   - **Flagged Anti-Forensics:** Records flagged by the Random Forest classifier or heuristic rules.
   - **Forensic PDF Reports:** Tamper-evident exported reports with cryptographic hashes.
   - **Evaluation Status:** Shows `Evaluated` (if benchmark fixtures tested) or `Not Evaluated` (honest indicator when waiting for external challenge sets).
2. **Active Case Workspace Banner:**
   - Shows the currently selected Case ID, Title, and Lead Examiner.
   - Action buttons: `⚡ Run Detection Model`, `📤 Upload Evidence`, and `📑 Generate PDF`.
3. **Recent Cases Table:**
   - Lists all cases with timestamps, status, and an `Open Case` button.
4. **Integrated 10-Stage Pipeline Visualizer:**
   - Depicts the end-to-end evidence processing pipeline:
     1. Evidence Intake ➔ 2. SHA-256 Hash ➔ 3. Parsing & Normalization ➔ 4. TF-IDF N-Grams ➔ 5. Random Forest Classification ➔ 6. TreeSHAP Attribution ➔ 7. Timeline Context ➔ 8. Silent Gap Detection ➔ 9. Append-Only Audit Log ➔ 10. Court-Admissible PDF Report.

---

## 9. Creating a New Forensic Investigation Case

1. Click the blue **`+ New Case`** button in the top header.
2. In the modal dialog, provide:
   - **Case Title:** e.g., `Conti Ransomware Lateral Movement & Anti-Forensics Investigation`
   - **Incident Type:** Select `Ransomware Incident Post-Attack Investigation`.
   - **Lead Examiner:** e.g., `Forensic Analyst S. Chalasani`
   - **Description:** e.g., `Post-attack analysis of compromised domain controller logs focusing on log clearing and shadow copy deletion.`
3. Click **Create Case**. The new Case ID (e.g., `CASE-E2E-772FFB`) is automatically activated.

---

## 10. Tab 2: Evidence Intake & SHA-256 Ingestion

1. Click **`📁 Evidence Intake`** in the top navigation bar.
2. Verify the **Active Case ID** is displayed in the case selector.
3. In the upload card, drag and drop or browse for an evidence log file:
   - Supported formats: `.csv`, `.json`, `.jsonl`, `.txt`, `.log`, `.evtx`.
   - Pre-packaged test fixtures available at: `data/fixtures/sample_security_events.csv`.
4. Click **`Upload & Ingest Evidence`**.
5. **System Actions Performed:**
   - Calculates the exact **SHA-256** digest before any parsing.
   - Copies the original file into `data/evidence/<case_id>/` in read-only mode.
   - Normalizes raw entries into the canonical schema: `event_id`, `timestamp_utc`, `host`, `user`, `process`, `event_source`, `raw_message`, `normalized_text`.
   - Appends a cryptographically hash-chained entry to the audit log.

---

## 11. Tab 3: Canonical Log Explorer & Filtering

1. Click **`🔍 Log Explorer`** in the navigation bar.
2. The data table displays all normalized records for the active case.
3. **Filter Controls:**
   - **Search Filter:** Type keywords like `wevtutil`, `vssadmin`, `shadowcopy`, `mimikatz`, or `cleared`.
   - **Suspicious Only Checkbox:** Check to instantly filter only records flagged by the ML pipeline or heuristic rules.
   - **Pagination:** Navigate through large log volumes using the pagination controls.
4. Click on any record's **`Detail`** button to inspect the full un-truncated raw event payload and normalized token stream.

---

## 12. Running Machine Learning Anti-Forensic Detection

1. On either the **Dashboard** or **Log Explorer**, click **`⚡ Run Detection Model`**.
2. **Pipeline Processing:**
   - Extracts character and word n-grams using the fitted TF-IDF vectorizer.
   - Evaluates each normalized log event against the trained Random Forest classifier (`fs-rf-v1.0`).
   - Cross-checks specific high-confidence anti-forensic heuristic rules (Event ID 1102 / 104 log clearing, `vssadmin delete shadows`, `wevtutil cl`, timestomping commands).
3. The table updates with:
   - **Classification Badge:** `NORMAL` (green) or `SUSPICIOUS` (red).
   - **Probability Score:** e.g., `94.2%`.
   - **Matched Techniques:** e.g., `Log Deletion / Wevtutil`, `Shadow Copy Tampering`.

---

## 13. Interpreting SHAP Explainability Visualizations

1. In the **Log Explorer** or **Timeline**, locate any record flagged as `SUSPICIOUS`.
2. Click the purple **`🔍 SHAP`** button in the Actions column.
3. The **Explainable AI Attribution Modal** will open, presenting:
   - **Token Attribution Magnitudes:** Horizontal bar chart displaying the top feature n-grams that drove the model's prediction.
   - **Red Bars (Positive Values):** Tokens that pushed the classifier toward a `SUSPICIOUS` anti-forensic verdict (e.g., `wevtutil`, `delete shadows`, `clear-eventlog`, `powershell -enc`).
   - **Green Bars (Negative Values):** Tokens that represent standard benign administrative telemetry.
   - **Investigative Rationale:** Plain-language summary explaining the tactical relevance of the highlighted tokens to ransomware incident post-attack investigation.
   - **Legal Admissibility Caveat:** Explicit notice confirming that SHAP values reflect statistical feature contributions within the model rather than direct factual evidence of criminal intent.

---

## 14. Tamper-Evident Examiner Annotations

1. Click the **`📝 Note`** button next to any log record.
2. Enter your professional forensic commentary (e.g., `Confirmed correlation with Ransomware IOC: execution of vssadmin occurred 42 seconds prior to file encryption`).
3. Click **Save Note**.
4. The note is permanently bound to the event record in the database, included in subsequent PDF reports, and committed to the hash-linked audit chain.

---

## 15. Tab 4: Post-Attack Investigation Timeline & Silent Gap Detection

1. Click **`⏱️ Investigation Timeline`** in the navigation bar.
2. Select the contextual time window (e.g., `±5 minutes`, `±15 minutes`, or `±60 minutes`).
3. **Silent Logging Gap Detection (Section 11.2):**
   - The engine analyzes timestamps from each host.
   - If logging ceases abruptly for longer than the threshold and subsequently resumes with event clearing or anti-forensic activity, a yellow alert displays:  
     `⚠️ 1 Silent Logging Gap(s) Detected: Host DC-SRV-01 silent for 32.4 minutes.`
4. **Contextual Groupings:**
   - Displays each flagged anti-forensic event in chronological context alongside benign preceding and succeeding events, allowing examiners to reconstruct the attacker's trajectory.

---

## 16. Tab 5: Live Ingestion vs. Simulated Replay Monitoring

Click **`🔴 Live & Replay Monitor`** to access the real-time analysis console.

### Mode A: Incremental Simulated Replay (Default Demo Mode)
- **Use Case:** Demonstrating real-time streaming detection when direct live host agent access is restricted or when analyzing historical forensic image streams.
- **Visual Label:** Clearly marked with a prominent yellow banner:  
  `⚠️ SIMULATED REPLAY MODE: Processing historical benchmark events in incremental steps for validation and demonstration.`
- **Controls:**
  - Select replay speed (`1.0x`, `2.0x`, `5.0x`).
  - Click **`▶ Start Replay`** to stream events sequentially into the pipeline.
  - Click **`⏸ Pause`** or **`⏹ Stop`** to inspect real-time metrics.
  - Watch the live stream table dynamically append incoming events with sub-millisecond inference latency badges.

### Mode B: Direct Mode (Authorized Local Directory Monitoring)
- **Use Case:** Ingesting live syslog files or Windows Event logs from an authorized directory in real time.
- **Operation:**
  1. Toggle the mode selector to `Authorized Local Directory`.
  2. Enter the authorized local directory path (e.g., `C:\ForensicLogs\LiveIntake`).
  3. Enter polling interval in seconds (default: `2.0s`).
  4. Click **`▶ Start Directory Monitor`**.
  5. As new files or line appends arrive in the directory, the background worker ingests, hashes, parses, and scores them automatically.

---

## 17. Tab 6: Structured Forensic PDF Report Generation

1. Click **`📄 Reports & Custody`** in the navigation bar.
2. Select the active case from the dropdown.
3. In the report options, verify:
   - Executive Summary generation.
   - Inclusion of SHAP attribution summaries.
   - Inclusion of Silent Log Gap analysis.
   - Inclusion of the cryptographic Chain-of-Custody ledger.
4. Click **`📑 Generate Forensic PDF Report`**.
5. The ReportLab engine compiles the document and displays the newly generated report in the reports table with its timestamp, page count, and SHA-256 checksum.

---

## 18. Downloading and Inspecting Generated PDF Reports

1. In the **Generated Forensic Reports** table, click the blue **`⬇ Download PDF`** button.
2. Open the downloaded PDF in your preferred viewer (Adobe Acrobat, Chrome, Edge).
3. **Report Structure & Professional Polish:**
   - **Page 1:** Executive Summary, Case Metadata, Examiner credentials, Evidence SHA-256 inventory, and Federal Rule of Evidence 901 authentication statement.
   - **Page 2:** Machine Learning Methodology, Model Architecture (`fs-rf-v1.0`), Primary vs. Optional experiments disclosure, and Feature Importance Overview.
   - **Page 3:** Flagged Anti-Forensic Findings Table, including Mitre ATT&CK classifications, heuristic indicators, and probability scores.
   - **Page 4:** Explainable AI (TreeSHAP) Feature Attribution breakdown with visual token magnitude representations and investigative rationales.
   - **Page 5:** Chronological Incident Timeline, Silent Logging Gaps table, and correlation with ransomware activity.
   - **Page 6:** Cryptographic Chain-of-Custody Audit Ledger showing every genesis and event hash.
   - **Page 7:** Legal Limitations, Daubert / Rule 702 admissibility advisory, and Examiner Sign-off Block.

---

## 19. Verifying Cryptographic Chain-of-Custody Audit Trail

1. In the top navigation bar, click the **`⛓️ Verify Audit`** button.
2. The backend traverses every block in the `audit_ledger` table, recalculates the SHA-256 hash over `(audit_id + timestamp + action + details + previous_hash)`, and confirms link integrity.
3. A verification banner displays:
   - `✅ Cryptographic Audit Chain Verified: 100% of recorded actions intact. Zero tamper indicators detected.`

---

## 20. Tab 7: External Dataset Feasibility & Ingestion Guidelines

Click **`📦 Datasets & Feasibility`** to review external dataset compatibility:
- **HackTheBox Forensics (LogJammer):**
  - Schema: Windows EVTX / Sysmon / Security.
  - Status: Built-in parser ready. If user provides authorized `LogJammer.evtx`, place into `data/external/htb/`.
- **DFRWS Forensic Challenges:**
  - Schema: Linux Syslog / auth.log / text dumps.
  - Status: Built-in regex normalizer ready. Place challenge files into `data/external/dfrws/`.
- **SILRAD (2025):**
  - Schema: 52-feature Sysmon ransomware telemetry.
  - Status: Supported as a secondary ransomware behavioral benchmark (Section 18.2). Place into `data/external/silrad/`.
- **Honest Academic Disclosure:** Datasets without independently verified ground-truth labels are classified as `COMPATIBLE_RAW_UNLABELED` and are never fraudulently claimed as having high classification accuracy.

---

## 21. Tab 8: Empirical Validation & Benchmark Evaluation

1. Click **`📈 Empirical Evaluation`** in the navigation bar.
2. Click **`🧪 Train Baseline on Fixtures`** to execute a clean cross-validation training cycle using the pre-packaged 5,400 benchmark samples.
3. The evaluation card renders:
   - **Accuracy, Precision, Recall, Macro F1-Score, and False Positive Rate (FPR).**
   - **Interactive Confusion Matrix:** True Negatives (TN), False Positives (FP), False Negatives (FN), and True Positives (TP).
   - Demonstrates that training and test splits strictly prevent data leakage by fitting TF-IDF on the training fold only.

---

## 22. Executing the Complete Automated Test Suite

To verify system integrity and ensure 100% test coverage across all components, open a terminal and run:

```powershell
python tests/test_runner.py
```

Expected output:
```text
======================================================================
Running ForensicShield AI Comprehensive Test Suite (Project 218)
======================================================================
test_dashboard_page ... ok
test_datasets_status_endpoint ... ok
test_full_investigation_lifecycle_via_api ... ok
test_health_check ... ok
test_live_monitor_endpoints ... ok
test_audit_all_datasets ... ok
test_silrad_supporting_dataset_classification ... ok
test_source_manifest_csv_generation ... ok
test_unlabeled_external_file_never_marked_fully_supported ... ok
test_audit_hash_chain_and_tamper_detection ... ok
test_original_file_immutability ... ok
test_sha256_computation_exactness ... ok
test_incremental_replay_execution ... ok
test_provisional_label_and_disclaimer ... ok
test_real_time_directory_ingestion_mode ... ok
test_state_transitions ... ok
test_reproducible_training_and_serialization ... ok
test_train_test_leakage_prevention ... ok
test_csv_parser_success_and_preservation ... ok
test_json_and_jsonl_parser ... ok
test_malformed_file_handling_no_crash ... ok
test_schema_never_invents_missing_timestamps ... ok
test_text_syslog_parser ... ok
test_pdf_report_generation_and_integrity ... ok
test_empty_case_creation_rejection ... ok
test_nonexistent_case_handling ... ok
test_oversized_file_rejection ... ok
test_path_traversal_on_download ... ok
test_prohibited_executable_extension_rejection ... ok
test_shap_empty_input_graceful_handling ... ok
test_shap_explanation_structure_and_caveat ... ok
test_heuristic_rule_evaluations ... ok
test_timeline_gap_detection_and_context ... ok

----------------------------------------------------------------------
Ran 33 tests in 3.501s

OK
```

---

## 23. Safe Application Shutdown Procedure

1. In the terminal running Flask or `run.py`, press **`Ctrl + C`**.
2. The server gracefully commits pending database transactions, terminates background live ingestion threads, and releases the network port.
3. Close the browser tab. All case records, evidence files, audit logs, and reports are safely persisted in `database/forensicshield.db` and `reports/`.
