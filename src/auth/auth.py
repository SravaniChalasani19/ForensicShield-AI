
import os
import secrets
import sqlite3
import uuid
import re

from datetime import datetime, timezone, timedelta
from functools import wraps
from hmac import compare_digest
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import (
    Blueprint,
    request,
    session,
    redirect,
    url_for,
    render_template,
    jsonify,
    abort,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from src.storage.db import get_db_connection, _db_lock


auth_bp = Blueprint("auth", __name__)

# Support both RATELIMIT_STORAGE_URI and FORENSICSHIELD_RATELIMIT_STORAGE
_rl_storage = os.environ.get("RATELIMIT_STORAGE_URI") or os.environ.get("FORENSICSHIELD_RATELIMIT_STORAGE", "memory://")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=_rl_storage,
    headers_enabled=True
)


# CSRF Protection
def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    return session["_csrf_token"]


def verify_csrf():
    expected = session.get("_csrf_token", "")
    supplied = request.form.get(
        "_csrf_token",
        request.headers.get("X-CSRF-Token", "")
    )

    if (
        not expected
        or not isinstance(supplied, str)
        or not supplied.isascii()
        or not compare_digest(expected, supplied)
    ):
        abort(400, description="Invalid security token.")


# Current User
def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = get_db_connection()

    try:
        user = conn.execute(
            """
            SELECT user_id, full_name, email
            FROM users
            WHERE user_id = ? AND is_active = 1
            """,
            (user_id,)
        ).fetchone()

        return dict(user) if user else None

    finally:
        conn.close()


# Login Protection
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not get_current_user():
            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Authentication required"
                }), 401

            return redirect(url_for("auth.login"))

        return view(*args, **kwargs)

    return wrapped


# Registration
@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per hour", methods=["POST"])
def register():
    if request.method == "GET":
        return render_template(
            "register.html",
            csrf_token=csrf_token()
        )

    verify_csrf()

    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    error = None

    if not full_name or len(full_name) > 100:
        error = "Enter a valid full name."

    elif len(email) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        error = "Enter a valid email address."

    elif not 12 <= len(password) <= 128:
        error = "Password must contain 12 to 128 characters."

    elif password != confirm_password:
        error = "Passwords do not match."

    if error:
        return render_template(
            "register.html",
            error=error,
            csrf_token=csrf_token()
        ), 400

    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash(
        password,
        method="scrypt"
    )

    created_at = datetime.now(timezone.utc).isoformat()

    try:
        with _db_lock:
            conn = get_db_connection()

            try:
                conn.execute(
                    """
                    INSERT INTO users (
                        user_id,
                        full_name,
                        email,
                        password_hash,
                        created_at,
                        is_active
                    )
                    VALUES (?, ?, ?, ?, ?, 1)
                    """,
                    (
                        user_id,
                        full_name,
                        email,
                        password_hash,
                        created_at
                    )
                )

                conn.commit()

            finally:
                conn.close()

    except (sqlite3.IntegrityError, Exception) as reg_err:
        err_msg = str(reg_err).lower()
        if "unique" in err_msg or "integrity" in err_msg or "duplicate" in err_msg or isinstance(reg_err, sqlite3.IntegrityError):
            return render_template(
                "register.html",
                error="Unable to register with these details.",
                csrf_token=csrf_token()
            ), 400
        raise

    return redirect(url_for("auth.login"))


# Login
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "GET":
        return render_template(
            "login.html",
            csrf_token=csrf_token()
        )

    verify_csrf()

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    user = None

    if len(email) <= 254 and len(password) <= 128:
        conn = get_db_connection()

        try:
            row = conn.execute(
                """
                SELECT * FROM users
                WHERE email = ? AND is_active = 1
                """,
                (email,)
            ).fetchone()
            user = dict(row) if row else None

        finally:
            conn.close()

    if user:
        # Check Account Lockout status
        locked_until_str = user.get("locked_until")
        if locked_until_str:
            try:
                lock_time = datetime.fromisoformat(locked_until_str)
                now_utc = datetime.now(timezone.utc)
                if lock_time.tzinfo is None:
                    lock_time = lock_time.replace(tzinfo=timezone.utc)
                if now_utc < lock_time:
                    remaining_mins = max(1, int((lock_time - now_utc).total_seconds() / 60))
                    return render_template(
                        "login.html",
                        error=f"Account temporarily locked due to excessive failed attempts. Please retry in {remaining_mins} minute(s).",
                        csrf_token=csrf_token()
                    ), 429
            except Exception:
                pass

        if check_password_hash(user["password_hash"], password):
            # Reset failed login count on successful authentication
            try:
                conn = get_db_connection()
                conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?;",
                    (user["user_id"],)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

            session.clear()
            session["user_id"] = user["user_id"]
            session.permanent = True
            csrf_token()

            return redirect("/")
        else:
            # Increment failed attempts on incorrect password
            try:
                conn = get_db_connection()
                current_failed = (user.get("failed_attempts") or 0) + 1
                new_lock = None
                if current_failed >= 5:
                    new_lock = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
                conn.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?;",
                    (current_failed, new_lock, user["user_id"])
                )
                conn.commit()
                conn.close()
                if current_failed >= 5:
                    return render_template(
                        "login.html",
                        error="Account temporarily locked for 15 minutes due to 5 consecutive failed login attempts.",
                        csrf_token=csrf_token()
                    ), 429
            except Exception:
                pass

    return render_template(
        "login.html",
        error="Invalid email or password.",
        csrf_token=csrf_token()
    ), 401


# Logout
@auth_bp.route("/logout", methods=["POST"])
def logout():
    verify_csrf()
    session.clear()

    return redirect(url_for("auth.login"))
