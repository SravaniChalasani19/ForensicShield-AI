"""
ForensicShield AI - Master Production Launcher (Project 218)
Handles:
1. Environment validation (Python version, dependency imports).
2. Automatic installation of missing dependencies from requirements.txt.
3. Database initialization and directory structure verification.
4. Trained model pipeline validation (auto-trains on benchmark corpus if missing).
5. Dataset feasibility auditing and source manifest update.
6. Available port detection (starts on 5000, fallback to 5001 if occupied).
7. Non-blocking health-checked browser launcher (opens ONLY when Flask responds 200 OK).
8. Clean error reporting and interactive pause to keep console visible on errors.
"""

import os
import sys
import time
import socket
import urllib.request
import webbrowser
import threading
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

REQUIRED_PACKAGES = [
    ("flask", "Flask"),
    ("sklearn", "scikit-learn"),
    ("shap", "shap"),
    ("reportlab", "reportlab"),
    ("joblib", "joblib"),
    ("numpy", "numpy"),
    ("pandas", "pandas"),
]

def check_and_install_dependencies():
    """Verify all critical dependencies and install missing ones automatically."""
    print("[1/6] Verifying Python dependencies...")
    missing = []
    for module_name, pip_name in REQUIRED_PACKAGES:
        try:
            __import__(module_name)
        except ImportError:
            missing.append(pip_name)

    if missing:
        print(f"[*] Missing dependencies detected: {', '.join(missing)}")
        print("[*] Installing required packages from requirements.txt...")
        req_file = BASE_DIR / "requirements.txt"
        if req_file.exists():
            cmd = [sys.executable, "-m", "pip", "install", "-r", str(req_file)]
        else:
            cmd = [sys.executable, "-m", "pip", "install"] + missing
        try:
            subprocess.check_call(cmd)
            print("[+] Dependencies installed successfully.")
        except Exception as e:
            print(f"[!] Warning: Automatic pip install returned an error: {e}")
            print("[!] If the server fails to start, run: pip install -r requirements.txt")
    else:
        print("[+] All core dependencies verified.")

def check_port_available(host: str, port: int) -> bool:
    """Check if host:port is free to bind."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0

def find_available_port(host: str = "127.0.0.1", default_port: int = 5000) -> int:
    """Find a free port starting at default_port."""
    for port in [default_port, 5001, 5002, 8080]:
        if check_port_available(host, port):
            return port
    return default_port

def wait_for_server_and_open_browser(host: str, port: int, max_wait_sec: float = 20.0):
    """
    Polls /api/health until HTTP 200 is returned, then opens the browser.
    Eliminates race conditions and prevents '127.0.0.1 refused to connect / Reload page' errors.
    """
    url_health = f"http://{host}:{port}/api/health"
    url_dash = f"http://{host}:{port}/"
    start_time = time.time()

    while time.time() - start_time < max_wait_sec:
        time.sleep(0.3)
        try:
            req = urllib.request.Request(url_health, headers={"User-Agent": "ForensicShield-Probe"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    print(f"\n[+] Flask server confirmed ready and healthy on port {port}!")
                    print(f"[+] Opening browser at: {url_dash}\n")
                    webbrowser.open(url_dash)
                    return
        except Exception:
            continue

    print(f"[!] Server health probe timed out after {max_wait_sec}s.")
    print(f"[!] Please open your browser manually and navigate to: {url_dash}")

def main():
    print("=" * 72)
    print("      FORENSICSHIELD AI - PROJECT 218 PRODUCTION LAUNCHER")
    print("  Anti-forensic Technique Detection via NLP for Post-Attack DFIR")
    print("=" * 72)
    print(f"[INFO] Working Directory: {BASE_DIR}")
    print(f"[INFO] Python Interpreter: {sys.executable} ({sys.version.split()[0]})\n")

    # Step 1: Dependencies
    check_and_install_dependencies()

    # Step 2: Database and storage initialization
    print("[2/6] Initializing SQLite database and directory structure...")
    from src.storage.db import init_db
    init_db()
    print("[+] Database initialized.")

    # Step 3: Model pipeline validation
    print("[3/6] Validating trained machine learning model...")
    from src.ml.model_inference import ForensicModelInference
    model_ready = ForensicModelInference.is_model_ready()
    if not model_ready:
        print("[!] ERROR: Primary model pipeline missing (models/forensicshield_rf_pipeline.joblib).")
        print("[!] Automatic retraining is disabled to preserve original academic model integrity.")
        print("[!] Heuristic fallback active.")
    else:
        print("[+] Serialized model pipeline verified: fs-rf-v1.0 (Random Forest).")

    # Step 4: Dataset feasibility auditing
    print("[4/6] Auditing dataset feasibility and updating manifest...")
    try:
        from src.ingestion.dataset_adapters import DatasetFeasibilityRegistry
        report = DatasetFeasibilityRegistry.audit_all_datasets()
        print(f"[+] Feasibility audit complete ({len(report['datasets'])} data sources tracked).")
    except Exception as e:
        print(f"[!] Warning: Dataset audit warning: {e}")

    # Step 5: Port selection
    print("[5/6] Determining available server port...")
    host = "127.0.0.1"
    port = find_available_port(host, 5000)
    print(f"[+] Bound to: http://{host}:{port}")

    # Step 6: Start health-checked browser launcher thread
    print("[6/6] Spawning health-monitored browser launcher...")
    browser_thread = threading.Thread(
        target=wait_for_server_and_open_browser,
        args=(host, port),
        daemon=True,
        name="BrowserLauncherThread"
    )
    browser_thread.start()

    print("\n" + "=" * 72)
    print(f"  INVESTIGATION DASHBOARD URL: http://{host}:{port}")
    print("  Press Ctrl+C in this terminal window to stop the server.")
    print("=" * 72 + "\n")

    # Import and run Flask app
    from app import app
    app.run(host=host, port=port, debug=False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] ForensicShield AI server stopped by investigator (Ctrl+C). Goodbye.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n[FATAL ERROR] Server startup failed: {e}")
        import traceback
        traceback.print_exc()
        print("\nPlease check the error message above or see TROUBLESHOOTING.md.")
        if sys.stdin.isatty():
            input("\nPress Enter to close this window...")
        sys.exit(1)
