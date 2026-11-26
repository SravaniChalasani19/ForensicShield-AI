"""
Vercel Serverless Entrypoint for ForensicShield AI
Exposes WSGI `app` for Vercel Python Serverless Functions.
"""
import sys
import os
from pathlib import Path

# Add project root directory to sys.path so internal imports resolve
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Ensure VERCEL environment variable is recognized
os.environ.setdefault("VERCEL", "1")

# Import Flask app
from app import app
