import os
import json
import uuid
import csv
import io
import re
import hashlib
from pathlib import Path
from src.auth.auth import limiter
from datetime import datetime, timezone
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    send_file,
    abort,
    make_response,
)

from config import (
    APP_NAME,
    APP_SUBTITLE,
    SYSTEM_VERSION,
    MODEL_VERSION,
    BASE_DIR,
    REPORTS_DIR,
    ORIGINALS_DIR,
    LEGAL_DISCLAIMER,
    LITERATURE_SURVEY_MAPPING,
    MAX_CASES_PER_USER,
    MAX_EVIDENCE_PER_CASE,
    MAX_REPORTS_PER_CASE,
)
from src.storage.db import get_db_connection, init_db, _db_lock
from src.auth.auth import (
    auth_bp,
    csrf_token,
    verify_csrf,
    get_current_user,
    login_required,
)

from datetime import timedelta
from flask import redirect, url_for, session
from src.audit.audit_trail import AuditTrail
from src.ingestion.integrity import EvidenceIntegrityManager
from src.ingestion.parsers import LogParserRegistry
from src.ingestion.demo_fixtures import (
    get_approved_fixtures_catalog,
    load_approved_fixture_bytes,
    APPROVED_DEMO_FIXTURES,
)
from src.ingestion.live_monitor import live_monitor
from src.ingestion.dataset_adapters import DatasetFeasibilityRegistry
from src.preprocessing.text_cleaner import clean_log_text
from src.ml.model_inference import ForensicModelInference
from src.ml.model_trainer import ForensicModelTrainer
from src.ml.rules import evaluate_rules_on_text
from src.ml.evaluator import ForensicEvaluator
from src.explainability.shap_explainer import ForensicShapExplainer, SHAP_CAVEAT
from src.investigation.timeline import TimelineInvestigator
from src.reporting.pdf_generator import ForensicPdfReportGenerator

# Ensure DB is initialized
init_db()

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

# Production Secret Key Enforcement
_is_production = os.environ.get("FLASK_ENV") == "production" or os.environ.get("VERCEL_ENV") == "production"
_secret = os.environ.get("FORENSICSHIELD_SECRET_KEY")

if _is_production:
    if not _secret or len(_secret) < 32 or _secret in {"change-me", "dev-secret", "secret", "placeholder"}:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: In production mode, "
            "FORENSICSHIELD_SECRET_KEY must be set to a cryptographically strong secret of at least 32 characters."
        )
    app.config["SECRET_KEY"] = _secret
else:
    app.config["SECRET_KEY"] = _secret or os.urandom(32).hex()

# Enforce secure cookies over HTTPS and Vercel
_is_https = (
    os.environ.get("FORENSICSHIELD_HTTPS") == "1"
    or os.environ.get("VERCEL") == "1"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_is_https,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

app.register_blueprint(auth_bp)
limiter.init_app(app)
@app.before_request
def protect_application():
    if request.endpoint in {
        "auth.login",
        "auth.register",
        "static",
        "health_check",
    }:
        return None

    if not get_current_user():
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "Authentication required"
            }), 401

        return redirect(url_for("auth.login"))

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        verify_csrf()
    # Restrict shared live monitoring in web publication
    if request.path.startswith("/api/live/"):
        return jsonify({
            "status": "ERROR",
            "message": (
                "Live monitoring is unavailable "
                "in the public web edition."
            )
        }), 403
    # User-wise resource ownership protection
    owner_id = get_current_user()["user_id"]
    route_args = request.view_args or {}

    case_id = route_args.get("case_id")
    event_id = route_args.get("event_id")
    report_id = route_args.get("report_id")

    conn = get_db_connection()

    try:
        if case_id is not None:
            owned = conn.execute("""
                SELECT case_id FROM cases
                WHERE case_id = ? AND owner_id = ?
            """, (case_id, owner_id)).fetchone()

            if not owned:
                return jsonify({
                    "error": "Case not found"
                }), 404

        if event_id is not None:
            owned = conn.execute("""
                SELECT e.event_id
                FROM events e
                JOIN cases c ON e.case_id = c.case_id
                WHERE e.event_id = ? AND c.owner_id = ?
            """, (event_id, owner_id)).fetchone()

            if not owned:
                return jsonify({
                    "error": "Event not found"
                }), 404

        if report_id is not None:
            owned = conn.execute("""
                SELECT r.report_id
                FROM reports r
                JOIN cases c ON r.case_id = c.case_id
                WHERE r.report_id = ? AND c.owner_id = ?
            """, (report_id, owner_id)).fetchone()

            if not owned:
                return jsonify({
                    "error": "Report not found"
                }), 404

    finally:
        conn.close()


# Security headers
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    if request.endpoint != "static":
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "status": "ERROR",
        "error": "Too Many Requests",
        "message": "Rate limit exceeded. Please wait before submitting additional requests.",
        "retry_after": getattr(e, "description", None),
    }), 429
# -------------------------------------------------------------
# Web UI Pages
# -------------------------------------------------------------
@app.route("/")
def dashboard():
    """Renders the comprehensive ForensicShield AI dashboard."""
    conn = get_db_connection()
    cur = conn.cursor()

   
    owner_id = get_current_user()["user_id"]

    cur.execute(
        "SELECT COUNT(*) as count FROM cases WHERE owner_id = ?;",
        (owner_id,)
    )
    case_count = cur.fetchone()["count"]

    cur.execute("""
        SELECT COUNT(*) as count
        FROM evidence e
        JOIN cases c ON e.case_id = c.case_id
        WHERE c.owner_id = ?;
    """, (owner_id,))
    evidence_count = cur.fetchone()["count"]

    cur.execute("""
        SELECT COUNT(*) as count
        FROM events e
        JOIN cases c ON e.case_id = c.case_id
        WHERE c.owner_id = ?;
    """, (owner_id,))
    log_count = cur.fetchone()["count"]

    cur.execute("""
        SELECT COUNT(*) as count
        FROM events e
        JOIN cases c ON e.case_id = c.case_id
        WHERE c.owner_id = ?
        AND (
            e.predicted_label = 'suspicious'
            OR e.rule_flags IS NOT NULL
        );
    """, (owner_id,))
    flagged_count = cur.fetchone()["count"]

    cur.execute("""
        SELECT COUNT(*) as count
        FROM reports r
        JOIN cases c ON r.case_id = c.case_id
        WHERE c.owner_id = ?;
    """, (owner_id,))
    report_count = cur.fetchone()["count"]

    cur.execute("""
        SELECT * FROM cases
        WHERE owner_id = ?
        ORDER BY created_at DESC LIMIT 10;
    """, (owner_id,))
    recent_cases = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT r.* FROM reports r
        JOIN cases c ON r.case_id = c.case_id
        WHERE c.owner_id = ?
        ORDER BY r.created_at DESC LIMIT 5;
    """, (owner_id,))
    recent_reports = [dict(r) for r in cur.fetchall()]


    conn.close()

    eval_status = ForensicEvaluator.get_evaluation_status()
    model_ready = ForensicModelInference.is_model_ready()

    return render_template(
        "index.html",
        app_name=APP_NAME,
        app_subtitle=APP_SUBTITLE,
        system_version=SYSTEM_VERSION,
        model_version=MODEL_VERSION,
        model_ready=model_ready,
        case_count=case_count,
        evidence_count=evidence_count,
        log_count=log_count,
        flagged_count=flagged_count,
        report_count=report_count,
        recent_cases=recent_cases,
        recent_reports=recent_reports,
        eval_status=eval_status,
        legal_disclaimer=LEGAL_DISCLAIMER,
        literature=LITERATURE_SURVEY_MAPPING,
        csrf_token=csrf_token(),
        current_user=get_current_user(),
    )

# -------------------------------------------------------------
# REST API Endpoints (Section 9 Specification)
# -------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "HEALTHY",
        "app_name": APP_NAME,
        "system_version": SYSTEM_VERSION,
        "model_version": MODEL_VERSION,
        "model_ready": ForensicModelInference.is_model_ready(),
    })

@app.route("/api/cases", methods=["POST"])
def create_case():
    """Create a new forensic investigation case."""
   
    data = request.get_json(silent=True)

    if data is None:
        data = request.form.to_dict()

    if not isinstance(data, dict):
        return jsonify({
            "status": "ERROR",
            "message": "Invalid case data."
        }), 400

    raw_title = data.get(
        "case_title",
        "Ransomware Post-attack Investigation"
    )

    raw_description = data.get("description", "")

    if not isinstance(raw_title, str) or not isinstance(raw_description, str):
        return jsonify({
            "status": "ERROR",
            "message": "Invalid title or description."
        }), 400

    case_title = raw_title.strip()
    description = raw_description.strip()

    if not case_title or len(case_title) > 150:
        return jsonify({
            "status": "ERROR",
            "message": "Case title must contain 1 to 150 characters."
        }), 400

    if len(description) > 2000:
        return jsonify({
            "status": "ERROR",
            "message": "Description cannot exceed 2000 characters."
        }), 400

    case_id = f"CASE-{uuid.uuid4().hex.upper()}"

    current_user = get_current_user()
    owner_id = current_user["user_id"]
    examiner = current_user["full_name"]


    if not case_id or not case_title:
        return jsonify({"status": "ERROR", "message": "case_id and case_title are required."}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as count FROM cases WHERE owner_id = ?;", (owner_id,))
    user_case_count = cur.fetchone()["count"]
    if user_case_count >= MAX_CASES_PER_USER:
        conn.close()
        return jsonify({
            "status": "ERROR",
            "message": f"Resource limit reached: A demonstration account may create at most {MAX_CASES_PER_USER} cases."
        }), 400

    cur.execute("SELECT case_id FROM cases WHERE case_id = ?;", (case_id,))
    if cur.fetchone():
        conn.close()
        return jsonify({"status": "ERROR", "message": f"Case ID '{case_id}' already exists."}), 409

    created_at = datetime.now(timezone.utc).isoformat()
    
    cur.execute("""
        INSERT INTO cases (
            case_id,
            case_title,
            description,
            examiner,
            created_at,
            status,
            owner_id
        )
        VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?);
    """, (
        case_id,
        case_title,
        description,
        examiner,
        created_at,
        owner_id
    ))

    conn.commit()
    conn.close()

    # Log in audit trail
    AuditTrail.record_event(
        case_id=case_id,
        actor=examiner,
        action="CASE_CREATED",
        output_hash=None,
    )

    return jsonify({
        "status": "SUCCESS",
        "message": f"Case '{case_id}' created successfully.",
        "case": {
            "case_id": case_id,
            "case_title": case_title,
            "description": description,
            "examiner": examiner,
            "created_at": created_at,
        }
    }), 201

@app.route("/api/cases/<case_id>", methods=["GET"])
def get_case(case_id: str):
    """Read case metadata and associated evidence files."""
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM cases WHERE case_id = ?;", (case_id,))
    case_row = cur.fetchone()
    if not case_row:
        conn.close()
        return jsonify({"status": "ERROR", "message": f"Case '{case_id}' not found."}), 404

    cur.execute("""
        SELECT evidence_id, case_id, original_filename, sha256_hash,
               file_size_bytes, mime_type, ingested_at, ingested_by,
               parse_status, event_count, error_message
        FROM evidence WHERE case_id = ? ORDER BY ingested_at ASC;
    """, (case_id,))
    evidence_list = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT COUNT(*) as count FROM events WHERE case_id = ?;", (case_id,))
    event_count = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) as count FROM events WHERE case_id = ? AND (predicted_label = 'suspicious' OR rule_flags IS NOT NULL);", (case_id,))
    flagged_count = cur.fetchone()["count"]

    cur.execute("SELECT * FROM audit_log WHERE case_id = ? ORDER BY audit_id ASC;", (case_id,))
    audit_trail = [dict(r) for r in cur.fetchall()]

    conn.close()

    return jsonify({
        "status": "SUCCESS",
        "case": dict(case_row),
        "evidence": evidence_list,
        "event_count": event_count,
        "flagged_count": flagged_count,
        "audit_trail": audit_trail,
    })

@app.route("/api/demo/fixtures", methods=["GET"])
def get_demo_fixtures():
    """List approved synthetic demonstration fixtures for public web edition."""
    return jsonify({
        "status": "SUCCESS",
        "fixtures": get_approved_fixtures_catalog(),
        "disclaimer": (
            "All demonstration fixtures are safe synthetic records containing "
            "no confidential, proprietary, or operational malware data."
        ),
    })


@app.route("/api/cases/<case_id>/evidence", methods=["POST"])
def ingest_evidence(case_id: str):
    """
    Import authorized forensic log file, compute SHA-256 before transformation,
    store immutable copy, parse into canonical schema, and record audit entry.
    In the public web publication edition, evidence intake is restricted to
    server-controlled approved synthetic fixtures.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT case_id FROM cases WHERE case_id = ?;", (case_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"status": "ERROR", "message": f"Case '{case_id}' does not exist."}), 404

    # Enforce per-case evidence resource limits
    cur.execute("SELECT COUNT(*) as count FROM evidence WHERE case_id = ?;", (case_id,))
    existing_count = cur.fetchone()["count"]
    if existing_count >= MAX_EVIDENCE_PER_CASE:
        conn.close()
        return jsonify({
            "status": "ERROR",
            "message": f"Resource limit reached: A demonstration case may contain at most {MAX_EVIDENCE_PER_CASE} evidence files."
        }), 400
    conn.close()

    examiner = get_current_user()["full_name"]
    data = request.get_json(silent=True) if request.is_json else request.form.to_dict()
    fixture_id = data.get("fixture_id") if isinstance(data, dict) else None

    # Handle approved demonstration fixture
    if fixture_id:
        try:
            filename, file_bytes, expected_sha, fixture_info = load_approved_fixture_bytes(fixture_id)
        except ValueError as ve:
            return jsonify({"status": "ERROR", "message": str(ve)}), 400
        except RuntimeError as re:
            return jsonify({"status": "ERROR", "message": str(re)}), 500

        # Check for duplicate ingestion in this case
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT evidence_id FROM evidence WHERE case_id = ? AND sha256_hash = ?;",
            (case_id, expected_sha)
        )
        dup = cur.fetchone()
        conn.close()
        if dup:
            return jsonify({
                "status": "ERROR",
                "message": (
                    f"Demonstration fixture '{filename}' is already ingested into "
                    f"Case '{case_id}' (Evidence ID: {dup['evidence_id']})."
                )
            }), 409
    else:
        # Check if local/direct file upload is permitted via environment flag
        allow_arbitrary = os.environ.get("FORENSICSHIELD_ALLOW_LOCAL_FILE_UPLOAD") == "1"
        is_cloud_prod = (
            os.environ.get("FLASK_ENV") == "production"
            or os.environ.get("VERCEL_ENV") == "production"
            or os.environ.get("VERCEL") == "1"
        )
        if is_cloud_prod or not allow_arbitrary:
            return jsonify({
                "status": "ERROR",
                "message": (
                    "Direct arbitrary file upload is disabled in the public and production web edition "
                    "for zero-trust security and server isolation. Please select an approved synthetic demonstration fixture."
                )
            }), 403

        if "file" not in request.files:
            return jsonify({"status": "ERROR", "message": "No file artifact uploaded or fixture selected."}), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify({"status": "ERROR", "message": "No file selected."}), 400

        filename = file.filename
        file_bytes = file.read()

    try:
        # 1. Verify integrity and store original untouched
        evidence_meta = EvidenceIntegrityManager.ingest_original_evidence(
            case_id=case_id,
            filename=filename,
            file_bytes=file_bytes,
        )
    except ValueError as val_err:
        return jsonify({"status": "ERROR", "message": str(val_err)}), 400
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Evidence intake failed: {str(e)}"
        }), 500

    evidence_id = evidence_meta["evidence_id"]
    sha256_hash = evidence_meta["sha256_hash"]
    stored_path = Path(evidence_meta["stored_path"])

    # 2. Parse file into Canonical Log Events
    events, success_count, error_count, parse_errors = LogParserRegistry.parse_file(
        case_id=case_id,
        evidence_id=evidence_id,
        file_path=stored_path,
        source_sha256=sha256_hash,
    )

    parse_status = "SUCCESS" if error_count == 0 else ("PARTIAL" if success_count > 0 else "FAILED")

    # 3. Insert Evidence Record into DB (persisting raw evidence_data for serverless environments)
    with _db_lock:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO evidence (
                evidence_id, case_id, original_filename, stored_path,
                sha256_hash, file_size_bytes, mime_type, ingested_at,
                ingested_by, parse_status, event_count, error_message,
                evidence_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            evidence_id,
            case_id,
            evidence_meta["original_filename"],
            evidence_meta["stored_path"],
            sha256_hash,
            evidence_meta["file_size_bytes"],
            evidence_meta["extension"],
            datetime.now(timezone.utc).isoformat(),
            examiner,
            parse_status,
            success_count,
            "; ".join(parse_errors[:5]) if parse_errors else None,
            file_bytes,
        ))

        # 4. Insert Parsed Canonical Events
        for ev in events:
            # Check Heuristic Rules during ingestion
            rule_matches = evaluate_rules_on_text(ev.normalized_text or ev.raw_message)
            rule_flags_str = json.dumps(rule_matches) if rule_matches else None
            # Explicit synthetic demonstration labeling
            label_src = ev.label_source or ("SYNTHETIC_DEMO" if fixture_id else "FILE_INGEST")

            cur.execute("""
                INSERT INTO events (
                    event_id, case_id, evidence_id, source_path, source_sha256,
                    original_row, timestamp_original, timestamp_utc, host,
                    provider, event_code, "user", raw_message, normalized_text,
                    ground_truth_label, label_source, predicted_label,
                    model_version, score, rule_flags, shap_features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                ev.event_id,
                case_id,
                evidence_id,
                ev.source_path,
                ev.source_sha256,
                ev.original_row,
                ev.timestamp_original,
                ev.timestamp_utc,
                ev.host,
                ev.provider,
                ev.event_code,
                ev.user,
                ev.raw_message,
                ev.normalized_text,
                ev.ground_truth_label,
                label_src,
                None, # predicted_label (null before inference)
                None, # model_version
                None, # score
                rule_flags_str,
                None, # shap_features
            ))

        conn.commit()
        conn.close()

    # 5. Record Ingest Audit Entry
    AuditTrail.record_event(
        case_id=case_id,
        actor=examiner,
        action="DEMO_EVIDENCE_INGESTED" if fixture_id else "EVIDENCE_INGESTED",
        evidence_id=evidence_id,
        input_hash=sha256_hash,
        output_hash=sha256_hash,
    )

    return jsonify({
        "status": "SUCCESS",
        "evidence_id": evidence_id,
        "sha256_hash": sha256_hash,
        "file_size_bytes": evidence_meta["file_size_bytes"],
        "parse_status": parse_status,
        "events_parsed": success_count,
        "errors_count": error_count,
        "errors": parse_errors[:10],
        "is_synthetic": bool(fixture_id),
    }), 201

@app.route("/api/cases/<case_id>/events", methods=["GET"])
def get_case_events(case_id: str):
    """Retrieve paginated, searchable, filterable canonical events for a case."""
    search = request.args.get("search", "").strip()
    label_filter = request.args.get("label", "ALL").strip().upper()
    rule_only = request.args.get("rule_only", "false").lower() == "true"
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(200, max(10, int(request.args.get("per_page", 50))))
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cur = conn.cursor()

    query_parts = ["case_id = ?"]
    params = [case_id]

    if search:
        query_parts.append("(raw_message LIKE ? OR host LIKE ? OR user LIKE ? OR event_code LIKE ?)")
        wild = f"%{search}%"
        params.extend([wild, wild, wild, wild])

    if label_filter == "SUSPICIOUS":
        query_parts.append("(predicted_label = 'suspicious' OR rule_flags IS NOT NULL)")
    elif label_filter == "NORMAL":
        query_parts.append("predicted_label = 'normal'")

    if rule_only:
        query_parts.append("rule_flags IS NOT NULL")

    where_clause = " AND ".join(query_parts)

    cur.execute(f"SELECT COUNT(*) as total FROM events WHERE {where_clause};", tuple(params))
    total_count = cur.fetchone()["total"]

    cur.execute(f"""
        SELECT * FROM events 
        WHERE {where_clause}
        ORDER BY timestamp_utc ASC, original_row ASC
        LIMIT ? OFFSET ?;
    """, tuple(params + [per_page, offset]))

    events = [dict(r) for r in cur.fetchall()]
    conn.close()

    # Parse JSON rule_flags for cleaner consumption
    for e in events:
        if e.get("rule_flags"):
            try:
                e["rule_matches"] = json.loads(e["rule_flags"])
            except Exception:
                e["rule_matches"] = []
        else:
            e["rule_matches"] = []

    return jsonify({
        "status": "SUCCESS",
        "case_id": case_id,
        "page": page,
        "per_page": per_page,
        "total_events": total_count,
        "total_pages": (total_count + per_page - 1) // per_page,
        "events": events,
    })

@app.route("/api/cases/<case_id>/events/export", methods=["GET"])
def export_case_events_csv(case_id: str):
    """Export derived case events to CSV with formula injection defense and path redaction."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT event_id, evidence_id, source_sha256, original_row, timestamp_original,
               timestamp_utc, host, "user", event_code, raw_message, normalized_text,
               predicted_label, score, rule_flags
        FROM events WHERE case_id = ?
        ORDER BY timestamp_utc ASC, event_id ASC;
    """, (case_id,))
    rows = cur.fetchall()
    conn.close()

    def sanitize_csv_cell(val):
        if val is None:
            return ""
        s = str(val)
        # Redact internal filesystem paths
        s = re.sub(r"[A-Za-z]:\\[^\s,;\"]+", "[SECURE_ARCHIVE]", s)
        s = re.sub(r"/(?:tmp|var|home|usr|private)/[^\s,;\"]+", "[SECURE_ARCHIVE]", s)
        # Mitigate CSV Formula Injection (CWE-1236)
        if s.startswith(('=', '+', '-', '@', '\t', '\r')):
            s = "'" + s
        return s

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "event_id", "evidence_id", "source_sha256", "original_row", "timestamp_original",
        "timestamp_utc", "host", "user", "event_code", "raw_message", "normalized_text",
        "predicted_label", "score", "rule_flags"
    ])
    for r in rows:
        sanitized_row = [sanitize_csv_cell(cell) for cell in list(r)]
        writer.writerow(sanitized_row)

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={case_id}_events_export.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.route("/api/cases/<case_id>/analyze", methods=["POST"])
def analyze_case(case_id: str):
    """
    Run compatible trained NLP model on case events.
    Applies TF-IDF vectorization + Random Forest prediction.
    Highlights candidate indicators separately from ML output.
    """
    if not ForensicModelInference.is_model_ready():
        return jsonify({
            "status": "MODEL_NOT_TRAINED",
            "message": "Detection model is not trained. Train the model using scripts/train_models.py or the Model Training action.",
            "model_ready": False,
        }), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events WHERE case_id = ? ORDER BY event_id ASC;", (case_id,))
    events = [dict(r) for r in cur.fetchall()]

    if not events:
        conn.close()
        return jsonify({
            "status": "NO_EVENTS",
            "message": f"No events found for case '{case_id}'. Ingest evidence logs first.",
            "analyzed_count": 0,
        }), 400

    texts = [e["normalized_text"] or clean_log_text(e["raw_message"]) for e in events]
    predictions = ForensicModelInference.predict_batch(texts)

    flagged_count = 0
    with _db_lock:
        for ev, pred in zip(events, predictions):
            lbl = pred["predicted_label"]
            score = pred["score"]
            mv = pred["model_version"]

            # Re-evaluate rules
            rule_matches = evaluate_rules_on_text(ev["normalized_text"] or ev["raw_message"])
            rule_flags_str = json.dumps(rule_matches) if rule_matches else None

            if lbl == "suspicious" or rule_matches:
                flagged_count += 1

            cur.execute("""
                UPDATE events 
                SET predicted_label = ?, model_version = ?, score = ?, rule_flags = ?
                WHERE event_id = ?;
            """, (lbl, mv, score, rule_flags_str, ev["event_id"]))

        conn.commit()
        conn.close()

    # Record analysis action in audit trail
    AuditTrail.record_event(
        case_id=case_id,
        actor=request.json.get("examiner", "Forensic Examiner") if request.is_json else "Forensic Examiner",
        action="MODEL_INFERENCE_RUN",
        output_hash=f"ANALYZED_{len(events)}_FLAGGED_{flagged_count}",
    )

    return jsonify({
        "status": "SUCCESS",
        "case_id": case_id,
        "analyzed_events_count": len(events),
        "flagged_events_count": flagged_count,
        "model_version": predictions[0]["model_version"] if predictions else MODEL_VERSION,
        "message": f"Successfully analyzed {len(events)} events; flagged {flagged_count} candidate anti-forensic events.",
    })

@app.route("/api/events/<event_id>/explanation", methods=["GET"])
def get_event_explanation(event_id: str):
    """
    Generate Explainable AI (SHAP) feature attributions for a specific event.
    Displays top positive/negative token contributions with mandatory attribution caveat.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events WHERE event_id = ?;", (event_id,))
    ev = cur.fetchone()
    conn.close()

    if not ev:
        return jsonify({"status": "ERROR", "message": f"Event '{event_id}' not found."}), 404

    event_dict = dict(ev)
    text_to_explain = event_dict.get("normalized_text") or event_dict.get("raw_message", "")

    explanation = ForensicShapExplainer.explain_log_event(text_to_explain, top_k=8)

    # Save explanation into event record
    with _db_lock:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE events SET shap_features = ? WHERE event_id = ?;", (json.dumps(explanation), event_id))
        conn.commit()
        conn.close()

    return jsonify({
        "status": "SUCCESS",
        "event_id": event_id,
        "case_id": event_dict["case_id"],
        "predicted_label": event_dict.get("predicted_label"),
        "score": event_dict.get("score"),
        "model_version": event_dict.get("model_version") or MODEL_VERSION,
        "raw_message": event_dict["raw_message"],
        "normalized_text": text_to_explain,
        "explanation": explanation,
        "caveat": SHAP_CAVEAT,
    })

@app.route("/api/cases/<case_id>/timeline", methods=["GET"])
def get_case_timeline_api(case_id: str):
    """Read chronological investigation context, nearby event correlation, and log gaps."""
    window_minutes = int(request.args.get("window_minutes", 15))
    timeline_result = TimelineInvestigator.get_case_timeline(case_id, window_minutes=window_minutes)
    return jsonify({
        "status": "SUCCESS",
        "timeline": timeline_result,
    })

@app.route("/api/cases/<case_id>/report", methods=["POST"])
def generate_report(case_id: str):
    """Generate tamper-evident ReportLab forensic PDF report with traceable references."""
    current_user = get_current_user()
    examiner = current_user["full_name"] if current_user else "Forensic Officer"

    try:
        report_meta = ForensicPdfReportGenerator.generate_case_report(case_id, examiner_override=examiner)
        return jsonify({
            "status": "SUCCESS",
            "report_id": report_meta["report_id"],
            "filename": report_meta["filename"],
            "sha256_hash": report_meta["sha256_hash"],
            "download_url": report_meta["download_url"],
            "message": "Forensic PDF report generated and cryptographically hashed successfully.",
        }), 201
    except ValueError as ve:
        return jsonify({"status": "ERROR", "message": str(ve)}), 404
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"Report generation failed: {str(e)}"}), 500

@app.route("/api/reports/<report_id>/download", methods=["GET"])
def download_report(report_id: str):
    """Validate and serve forensic PDF reports."""
    import hashlib

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM reports WHERE report_id = ?;",
        (report_id,)
    )
    rep = cur.fetchone()
    conn.close()

    if not rep:
        abort(404, description="Report not found.")

    file_path = Path(rep["file_path"]).resolve()
    reports_root = REPORTS_DIR.resolve()

    pdf_bytes = None
    if reports_root in file_path.parents and file_path.is_file():
        try:
            pdf_bytes = file_path.read_bytes()
        except Exception:
            pdf_bytes = None

    if pdf_bytes is None and rep["report_data"]:
        pdf_bytes = bytes(rep["report_data"])

    if pdf_bytes is None:
        abort(404, description="Report file missing.")

    if len(pdf_bytes) < 5 or pdf_bytes[:5] != b"%PDF-":
        abort(422, description="Invalid PDF header.")

    hasher = hashlib.sha256(pdf_bytes)
    if hasher.hexdigest().lower() != str(rep["sha256_hash"]).lower():
        abort(409, description="Report integrity mismatch.")

    view_mode = request.args.get("view") == "1"

    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=not view_mode,
        download_name=rep["filename"] or file_path.name,
        mimetype="application/pdf",
    )
@app.route("/api/evaluation", methods=["GET"])
def get_evaluation():
    """Read measured metrics, or explicit not-evaluated state."""
    eval_status = ForensicEvaluator.get_evaluation_status()
    return jsonify(eval_status)


@app.route("/api/research/results", methods=["GET"])
def get_research_results():
    import json

    root = Path(__file__).resolve().parent
    evaluation = root / "reports" / "evaluation"

    def read_result(relative_path):
        path = evaluation / relative_path
        if not path.is_file():
            return None

        try:
            return json.loads(
                path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return None

    return jsonify({
        "silrad": read_result(
            "silrad/silrad_evaluation_summary.json"
        ),
        "ablation": read_result(
            "silrad/silrad_ablation_summary.json"
        ),
        "external": read_result(
            "external/external_combined_summary.json"
        ),
        "independent_anti_forensic_validation":
            "NOT_EVALUATED"
    })


@app.route("/api/research/graphs/<filename>")
def get_research_graph(filename):

    allowed = {
        "silrad_confusion_matrix.png",
        "silrad_performance.png",
        "silrad_shap_importance.png",
        "silrad_shap_summary.png"
    }

    if filename not in allowed:
        abort(404)

    path = (
        Path(__file__).resolve().parent
        / "reports" / "evaluation"
        / "silrad" / filename
    )

    if not path.is_file():
        abort(404)

    return send_file(
        str(path), mimetype="image/png"
    )



@app.route("/api/audit/verify", methods=["GET"])
def verify_audit():
    """Verify audit integrity for an owned case."""

    owner_id = get_current_user()["user_id"]
    case_id = request.args.get("case_id", "").strip()

    if not case_id:
        return jsonify({
            "status": "ERROR",
            "verified": False,
            "message": "Select an investigation case first."
        }), 400

    conn = get_db_connection()

    try:
        owned = conn.execute("""
            SELECT case_id FROM cases
            WHERE case_id = ? AND owner_id = ?
        """, (case_id, owner_id)).fetchone()
    finally:
        conn.close()

    if not owned:
        return jsonify({
            "status": "ERROR",
            "message": "Case not found."
        }), 404

    result = AuditTrail.verify_chain(case_id)
    return jsonify(result)


@app.route("/api/cases/<case_id>/evidence/<evidence_id>/verify", methods=["POST"])
def verify_evidence_integrity(case_id: str, evidence_id: str):
    """
    Verify on-disk byte integrity of stored evidence against its recorded SHA-256 digest.
    Demonstrates immutable evidence preservation (Section 11 & Section 19).
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence WHERE case_id = ? AND evidence_id = ?;", (case_id, evidence_id))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "ERROR", "message": f"Evidence '{evidence_id}' not found in case '{case_id}'."}), 404

    ev_data = dict(row)
    stored_path = Path(ev_data["stored_path"])
    ev_bytes = None

    if stored_path.is_file():
        try:
            ev_bytes = stored_path.read_bytes()
        except Exception:
            ev_bytes = None

    if ev_bytes is None and ev_data.get("evidence_data"):
        ev_bytes = bytes(ev_data["evidence_data"])
        try:
            stored_path.parent.mkdir(parents=True, exist_ok=True)
            stored_path.write_bytes(ev_bytes)
        except Exception:
            pass

    if ev_bytes is None:
        return jsonify({
            "status": "FILE_MISSING",
            "evidence_id": evidence_id,
            "verified": False,
            "message": "Stored evidence file is unavailable in filesystem or database."
        }), 404

    current_hash = hashlib.sha256(ev_bytes).hexdigest().lower()
    recorded_hash = ev_data["sha256_hash"].lower()
    is_verified = (current_hash == recorded_hash)

    AuditTrail.record_event(
        case_id=case_id,
        actor=get_current_user()["full_name"],
        action="EVIDENCE_INTEGRITY_VERIFIED" if is_verified else "EVIDENCE_INTEGRITY_FAILED",
        evidence_id=evidence_id,
        input_hash=recorded_hash,
        output_hash=current_hash,
    )

    return jsonify({
        "status": "SUCCESS",
        "evidence_id": evidence_id,
        "filename": ev_data["original_filename"],
        "recorded_sha256": recorded_hash,
        "computed_sha256": current_hash,
        "verified": is_verified,
        "match": is_verified,
        "message": "SHA-256 hash verified: file is bit-for-bit identical to ingested state." if is_verified else "INTEGRITY VIOLATION: Current digest does not match recorded digest!",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
    })

# -------------------------------------------------------------
# Real-Time Monitoring & Incremental Replay (Section 18.1)
# -------------------------------------------------------------
@app.route("/api/live/start", methods=["POST"])
def start_live_monitor():
    data = request.get_json(silent=True) or request.form.to_dict()
    mode = data.get("mode", "REPLAY")
    target_dir = data.get("target_dir")
    case_id = data.get("case_id")
    poll_interval = float(data.get("poll_interval", 1.0))

    result = live_monitor.start(
        mode=mode,
        target_dir=target_dir,
        case_id=case_id,
        poll_interval_sec=poll_interval,
    )
    code = 200 if result.get("status") in ["STARTED", "ALREADY_RUNNING"] else 400
    return jsonify(result), code

@app.route("/api/live/pause", methods=["POST"])
def pause_live_monitor():
    return jsonify(live_monitor.pause())

@app.route("/api/live/resume", methods=["POST"])
def resume_live_monitor():
    return jsonify(live_monitor.resume())

@app.route("/api/live/stop", methods=["POST"])
def stop_live_monitor():
    return jsonify(live_monitor.stop())

@app.route("/api/live/status", methods=["GET"])
def get_live_status():
    return jsonify(live_monitor.get_status())

# -------------------------------------------------------------
# External Datasets & Feasibility Status (Section 18.2)
# -------------------------------------------------------------
@app.route("/api/datasets/status", methods=["GET"])
def get_datasets_status():
    report = DatasetFeasibilityRegistry.audit_all_datasets()
    return jsonify(report)
@app.route("/data/source_manifest.csv", methods=["GET"])
def download_source_manifest():
    manifest_path = BASE_DIR / "data" / "source_manifest.csv"

    if not manifest_path.is_file():
        DatasetFeasibilityRegistry.audit_all_datasets()

    if not manifest_path.is_file():
        abort(404, description="Source manifest file not found.")

    return send_file(
        str(manifest_path),
        as_attachment=True,
        download_name="source_manifest.csv",
        mimetype="text/csv",
    )

@app.route("/api/cases/<case_id>/notes", methods=["POST"])
def add_case_note(case_id: str):
    """Add an investigator note to an event or case."""
    data = request.get_json(silent=True) or request.form.to_dict()
    event_id = data.get("event_id")
    author = get_current_user()["full_name"]
    note_text = data.get("note_text", "").strip()

    if not note_text:
        return jsonify({"status": "ERROR", "message": "note_text cannot be empty."}), 400

    now_utc = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = get_db_connection()
        cur = conn.cursor()
        if event_id is not None:
            owned_event = cur.execute("""
                SELECT event_id FROM events
                WHERE event_id = ? AND case_id = ?
            """, (event_id, case_id)).fetchone()

            if not owned_event:
                conn.close()
                return jsonify({
                    "status": "ERROR",
                    "message": "Event not found in this case."
                }), 404
        cur.execute("""
            INSERT INTO investigator_notes (case_id, event_id, author, note_text, created_at)
            VALUES (?, ?, ?, ?, ?);
        """, (case_id, event_id, author, note_text, now_utc))
        conn.commit()
        conn.close()

    AuditTrail.record_event(
        case_id=case_id,
        actor=author,
        action="NOTE_ADDED",
        evidence_id=event_id,
        output_hash=hashlib.sha256(note_text.encode("utf-8")).hexdigest(),
    )

    return jsonify({"status": "SUCCESS", "message": "Investigator note recorded."}), 201

@app.route("/api/models/train", methods=["POST"])
def trigger_model_training():
    """Protect the validated primary model from accidental overwrite."""

    return jsonify({
        "status": "ERROR",
        "message": (
            "Primary model is already trained and evaluated. "
            "Automatic UI retraining is disabled to preserve "
            "model integrity and evaluation consistency. "
            "Use scripts/train_full_model.py for controlled retraining."
        )
    }), 409

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
