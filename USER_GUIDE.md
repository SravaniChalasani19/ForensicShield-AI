# ForensicShield AI — Web Application User Guide

Welcome to the **ForensicShield AI Web Publication Edition**. This application is an educational, defensive digital forensics demonstration platform for investigating ransomware post-attack activity and detecting anti-forensic techniques.

---

## 1. Quick Start Walkthrough

```
[Register / Login] ➔ [Create Case] ➔ [Ingest Demo Evidence] ➔ [Run Model Analysis] 
        ➔ [Review Findings & SHAP] ➔ [Examine Timeline] ➔ [Add Review Notes] 
                ➔ [Verify Cryptographic Integrity] ➔ [Generate PDF Report]
```

---

## 2. Step-by-Step Instructions

### Step 1: Account Registration & Login
1. Open the application at `http://127.0.0.1:5000`.
2. If you do not have an account, click **Register**.
3. Provide your Full Name, Email, and a strong password (minimum 12 characters).
4. Click **Create Account**, then log in with your credentials.

### Step 2: Create an Investigation Case
1. On the dashboard, click **+ New Case**.
2. Enter a descriptive Case Title (e.g., `Financial Server Ransomware Triage`).
3. Enter case notes or incident scope in the Description field.
4. Click **Create Case**. The server assigns a unique identifier (`CASE-...`) and automatically designates you as the Lead Examiner.

### Step 3: Ingest Approved Demonstration Evidence
1. Navigate to the **Evidence Intake** tab or click **📤 Upload Evidence**.
2. Select an approved synthetic demonstration fixture:
   - **Synthetic Ransomware Smoke Test (12 events):** Quick demonstration of log clearing (1102, wevtutil), shadow copy deletion (vssadmin), and timestomping.
   - **Enterprise Ransomware Timeline (21 events):** Correlated multi-stage attack sequence.
   - **Linux Syslog Forensic Artifact (5 events):** Syslog truncation and timestomp artifacts.
3. Click **Verify SHA-256 & Ingest**.
4. The system computes the SHA-256 hash before parsing, verifies the cryptographic signature, normalizes the records into canonical format, and appends an entry to the tamper-evident audit ledger.

### Step 4: Run Machine Learning & Rule Detection
1. Click **🤖 Run NLP Analysis** on the dashboard or Log Explorer.
2. The pre-trained TF-IDF + Random Forest model (`fs-rf-v1.0`) scores every canonical event as Normal vs Suspicious.
3. Independent heuristic rules evaluate explicit command signatures (e.g., `vssadmin delete shadows`, `wevtutil cl`, `truncate -s 0`).

### Step 5: Explainable AI (SHAP) Inspection
1. Navigate to the **Log Explorer** tab.
2. Filter by `Flagged Anti-Forensics`.
3. Click the **💡 SHAP** button next to any flagged event.
4. A modal opens showing:
   - Model classification score and version.
   - Top positive token contributions (words driving the suspicious classification).
   - Mandatory Attribution Caveat explaining that SHAP highlights statistical correlations of this trained model, not legal proof of malicious intent.

### Step 6: Contextual Timeline & Log Gap Analysis
1. Navigate to the **Investigation Timeline** tab.
2. Review the chronological sequence of flagged events.
3. Examine the **Log Gap Detection** section: Identifies silent periods exceeding 30 minutes on active hosts, indicating potential audit log tampering or service stoppage.

### Step 7: Record Investigator Review Notes
1. In Log Explorer or Timeline, click **📝 Note**.
2. Document your human investigative observations.
3. The note is cryptographically hashed and linked to the case audit ledger.

### Step 8: Cryptographic Verification & PDF Report Generation
1. Click **🔍 Verify Audit** to verify the mathematical integrity of the hash chain.
2. Click **🔍 Verify Hash** next to any evidence file to confirm on-disk bit-for-bit immutability.
3. Click **📑 Generate PDF Report**.
4. Download the generated ReportLab PDF documenting the entire chain of custody, findings, SHAP attributions, and legal disclaimers.
