"""
ForensicShield AI - Production WSGI Application Entrypoint
Suitable for production deployment behind Gunicorn (Linux) or Waitress (Windows).

Usage:
  Linux / Gunicorn:
    gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 wsgi:app

  Windows / Waitress:
    waitress-serve --listen=127.0.0.1:5000 wsgi:app
"""

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Enforce production security check if running in production mode
if os.environ.get("FLASK_ENV") == "production" or os.environ.get("FORENSICSHIELD_PRODUCTION") == "1":
    if not os.environ.get("FORENSICSHIELD_SECRET_KEY"):
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: "
            "FORENSICSHIELD_SECRET_KEY environment variable must be explicitly defined in production. "
            "Generate a strong 32-byte secret key (e.g., using 'python -c \"import secrets; print(secrets.token_hex(32))\"')."
        )

from app import app

if __name__ == "__main__":
    # If executed directly with Python, run Waitress if installed, or fallback to production-wrapped serve
    try:
        from waitress import serve
        port = int(os.environ.get("PORT", 5000))
        host = os.environ.get("HOST", "127.0.0.1")
        print(f"[*] Starting ForensicShield AI production server via Waitress on http://{host}:{port}")
        serve(app, host=host, port=port, threads=8)
    except ImportError:
        port = int(os.environ.get("PORT", 5000))
        host = os.environ.get("HOST", "127.0.0.1")
        print(f"[*] Starting ForensicShield AI server on http://{host}:{port} (debug=False)")
        app.run(host=host, port=port, debug=False)
