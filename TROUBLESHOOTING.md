# ForensicShield AI: Windows Troubleshooting & Operations Guide
**Project 218 Final Year B.Tech Operational Reference**  
*Common setup challenges, error resolutions, and environmental diagnostics*

---

## 1. Python Environment Diagnostics

### Issue 1: `python` or `py` is not recognized as an internal or external command
- **Cause:** Python is not added to the Windows system `PATH` environment variable.
- **Resolution:**
  1. Open Windows Search, type **"Environment Variables"**, and select **"Edit the system environment variables"**.
  2. Under User Variables or System Variables, select `Path` and click **Edit**.
  3. Add your Python installation path (e.g. `C:\Users\<User>\AppData\Local\Programs\Python\Python313`) and Scripts folder (`...\Python313\Scripts`).
  4. Restart your Command Prompt or Windows Terminal.
  5. Alternatively, invoke the Windows Python launcher directly: `py --version`.

---

## 2. PowerShell Script Execution Restrictions

### Issue 2: `File run.ps1 cannot be loaded because running scripts is disabled on this system`
- **Cause:** Windows PowerShell defaults to `Restricted` execution policy.
- **Resolution:**
  - Launch PowerShell and run:
    ```powershell
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\run.ps1
    ```
  - Alternatively, use the batch launcher `start_project.bat` or run `python app.py` directly.

---

## 3. Port Conflicts

### Issue 3: `OSError: [Errno 48] Address already in use` or `Port 5000 is in use`
- **Cause:** Another process or previous instance of Flask/AirPlay is listening on TCP port 5000.
- **Resolution:**
  1. Identify the process holding port 5000 in Command Prompt:
     ```cmd
     netstat -ano | findstr :5000
     ```
  2. Terminate the process by PID:
     ```cmd
     taskkill /F /PID <PID_NUMBER>
     ```
  3. Or change the port in `config.py` or `.env` to `5050` or `8080`.

---

## 4. Model Training & Availability

### Issue 4: Dashboard displays "○ Model Not Trained" and Analysis fails
- **Cause:** The machine learning pipeline has not been serialized into `models/`.
- **Resolution:**
  1. Train the baseline model from the command line:
     ```bash
     python scripts/train_models.py
     ```
  2. Or click **"🧪 Train Baseline on Fixtures"** in the **Empirical Evaluation** tab of the web application.
  3. Verify that `models/forensicshield_rf_pipeline.joblib` and `models/model_metadata.json` exist.

---

## 5. External Datasets & Feasibility Status

### Issue 5: Evaluation page displays "Benchmark Status: NOT EVALUATED"
- **Cause:** This is an intentional academic safeguard under Section 4.1 of the Blueprint. Accuracy and F1 metrics are never fabricated when external challenge datasets are unsupplied.
- **Resolution:**
  - To test evaluation on software fixtures:
    ```bash
    python scripts/run_evaluation.py --test-fixtures
    ```
  - To evaluate an external challenge file, place it in:
    - HackTheBox: `data/external/htb/`
    - DFRWS: `data/external/dfrws/`
    - SILRAD: `data/external/silrad/`
  - Re-run the feasibility audit:
    ```bash
    python scripts/check_datasets.py
    ```

---

## 6. ReportLab PDF Generation

### Issue 6: PDF fails to generate or returns 500 error
- **Cause:** Missing write permissions in `reports/` directory or unhandled special characters.
- **Resolution:**
  1. Verify directory exists: `mkdir reports`.
  2. Ensure `reportlab` is installed: `python -m pip install reportlab`.
  3. Check that the active case has at least one event record.

---

## 7. Evidence Integrity & Hashing

### Issue 7: Evidence Verification reports "Hash Mismatch"
- **Cause:** The file on disk in `data/originals/<case_id>/` was modified or overwritten after initial intake.
- **Resolution:**
  - ForensicShield AI sets files to read-only upon intake to protect them. Do not edit files inside `data/originals/`.
  - Re-import the original artifact through the **Evidence Intake** interface.
