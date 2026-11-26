# ForensicShield AI — Production & Cloud Deployment Guide

## 1. Overview

This document provides step-by-step instructions for deploying the **ForensicShield AI Web Publication Edition** in local and production cloud environments.

---

## 2. System Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| Operating System | Windows 10/11, Ubuntu 22.04 LTS, Debian 12 | Ubuntu 22.04 LTS (Cloud) / Windows 11 (Lab) |
| Python Runtime | Python 3.10 | Python 3.11 or 3.12 |
| System RAM | 2 GB | 4 GB (Supports TreeExplainer SHAP batch computation) |
| Disk Storage | 1 GB | 5 GB Persistent Volume |
| Reverse Proxy | N/A | Nginx or Caddy with TLS/HTTPS termination |

---

## 3. Local Windows Demonstration Execution

### Method A: One-Click Startup (Recommended)
1. Double-click `start_project.bat` or run:
   ```cmd
   .\start_project.bat
   ```
2. The launcher performs environment checks, verifies dependencies and models, initialises SQLite, starts the Flask application, and opens `http://127.0.0.1:5000` in the browser.

### Method B: Manual Command-Line Startup
1. Open PowerShell or Command Prompt.
2. Navigate to the project root:
   ```cmd
   cd "ForensicShieldAI_Web_Publication"
   ```
3. Create and activate a virtual environment:
   ```cmd
   python -m venv venv
   .\venv\Scripts\activate
   ```
4. Install dependencies:
   ```cmd
   pip install -r requirements.txt
   ```
5. Launch the application:
   ```cmd
   python app.py
   ```
6. Access the dashboard:
   ```
   http://127.0.0.1:5000
   ```

---

## 4. Production WSGI Deployment

Never run the Flask built-in development server in production. Use a hardened WSGI application server.

### Option 1: Linux Deployment with Gunicorn & Nginx

1. **Install Gunicorn:**
   ```bash
   pip install gunicorn
   ```
2. **Configure Environment Variables:**
   ```bash
   cp .env.example .env
   # Edit .env and configure FORENSICSHIELD_SECRET_KEY, FORENSICSHIELD_HTTPS=1
   ```
3. **Execute via Gunicorn:**
   ```bash
   gunicorn -w 4 -b 127.0.0.1:5000 --timeout 120 wsgi:app
   ```
4. **Nginx Reverse Proxy Configuration:**
   ```nginx
   server {
       listen 80;
       server_name forensicshield.example.com;
       return 301 https://$host$request_uri;
   }

   server {
       listen 443 ssl http2;
       server_name forensicshield.example.com;

       ssl_certificate /etc/letsencrypt/live/forensicshield.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/forensicshield.example.com/privkey.pem;

       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Option 2: Windows Production Deployment with Waitress

1. **Install Waitress:**
   ```cmd
   pip install waitress
   ```
2. **Run Waitress:**
   ```cmd
   waitress-serve --listen=127.0.0.1:5000 --threads=8 wsgi:app
   ```

---

## 5. Container & Cloud Hosting (Render / Railway / Fly.io / Docker)

### Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

ENV FLASK_ENV=production
ENV FORENSICSHIELD_PRODUCTION=1
ENV PORT=5000

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--timeout", "120", "wsgi:app"]
```

### Persistent Storage Setup
Ensure the following directories are mapped to persistent volumes:
- `/app/data` (Stores `forensicshield.db` and approved demonstration fixtures)
- `/app/reports/generated` (Stores generated forensic PDF reports)
- `/app/data/originals` (Stores original SHA-256 evidence files)

---

## 6. Health Checks & Monitoring

- Health check endpoint: `GET /api/health`
- Response:
  ```json
  {
    "status": "HEALTHY",
    "app_name": "ForensicShield AI",
    "system_version": "v1.0.0",
    "model_version": "fs-rf-v1.0",
    "model_ready": true
  }
  ```
- Publicly accessible without authentication for cloud uptime orchestrators.
