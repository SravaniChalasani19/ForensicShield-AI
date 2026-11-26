import os
import sqlite3
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from config import DB_PATH, DATABASE_URL

_db_lock = threading.RLock()

# Check if PostgreSQL is available via psycopg2 or pg8000
_HAS_PSYCOPG2 = False
try:
    import psycopg2
    import psycopg2.extras
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False


class DictRow(dict):
    """Row wrapper that allows both key and integer index access."""
    def __init__(self, d: Dict[str, Any], keys: List[str]):
        super().__init__(d)
        self._keys = keys

    def __getitem__(self, item):
        if isinstance(item, int):
            return super().__getitem__(self._keys[item])
        return super().__getitem__(item)


class PostgresConnectionWrapper:
    """Wrapper around psycopg2 connection to provide SQLite-like interface."""
    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, sql: str, params: Optional[tuple] = None):
        # Convert SQLite '?' parameter placeholders to PostgreSQL '%s'
        pg_sql = sql.replace("?", "%s")
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor) if _HAS_PSYCOPG2 else self._conn.cursor()
        if params is not None:
            cur.execute(pg_sql, params)
        else:
            cur.execute(pg_sql)
        return PostgresCursorWrapper(cur)

    def cursor(self):
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor) if _HAS_PSYCOPG2 else self._conn.cursor()
        return PostgresCursorWrapper(cur)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


class PostgresCursorWrapper:
    """Wrapper around psycopg2 cursor returning DictRow objects."""
    def __init__(self, raw_cursor):
        self._cursor = raw_cursor

    def execute(self, sql: str, params: Optional[tuple] = None):
        pg_sql = sql.replace("?", "%s")
        if params is not None:
            self._cursor.execute(pg_sql, params)
        else:
            self._cursor.execute(pg_sql)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        keys = [desc[0] for desc in self._cursor.description]
        return DictRow(dict(row), keys)

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows:
            return []
        keys = [desc[0] for desc in self._cursor.description]
        return [DictRow(dict(r), keys) for r in rows]

    @property
    def lastrowid(self):
        return getattr(self._cursor, "lastrowid", None)

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        self._cursor.close()


def get_db_connection(db_path: Path = DB_PATH):
    """
    Returns a database connection.
    If DATABASE_URL is configured (e.g., PostgreSQL on Neon/Supabase/Vercel Postgres),
    returns a PostgreSQL connection wrapper.
    Otherwise, returns an SQLite connection for offline and local testing.
    """
    db_url = os.environ.get("DATABASE_URL") or DATABASE_URL

    if db_url and (db_url.startswith("postgres://") or db_url.startswith("postgresql://")):
        if not _HAS_PSYCOPG2:
            raise RuntimeError(
                "DATABASE_URL is set to PostgreSQL, but 'psycopg2' is not installed. "
                "Install psycopg2-binary or unset DATABASE_URL to use SQLite."
            )
        # Handle uri prefix for SQLAlchemy/Neon compatibility
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        
        conn = psycopg2.connect(db_url)
        conn.autocommit = False
        return PostgresConnectionWrapper(conn)

    # Fallback to local / serverless SQLite
    # Ensure parent directory exists
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize database with authoritative schema for both SQLite and PostgreSQL."""
    db_url = os.environ.get("DATABASE_URL") or DATABASE_URL

    with _db_lock:
        if db_url and (db_url.startswith("postgres://") or db_url.startswith("postgresql://")):
            if _HAS_PSYCOPG2:
                _init_postgres(db_url)
                return
            else:
                pass  # Fall through to SQLite if psycopg2 is missing

        _init_sqlite(db_path)


def _init_sqlite(db_path: Path) -> None:
    """Initialize SQLite database with authoritative schema."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        );
    """)

    # User Account Lockout Migration for SQLite
    user_columns = {
        row["name"]
        for row in cur.execute("PRAGMA table_info(users)")
    }
    if "failed_attempts" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;")
    if "locked_until" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN locked_until TEXT;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_title TEXT NOT NULL,
            description TEXT,
            examiner TEXT,
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            owner_id TEXT REFERENCES users(user_id)
        );
    """)

    # Case Ownership Migration for existing SQLite DBs
    columns = {
        row["name"]
        for row in cur.execute("PRAGMA table_info(cases)")
    }
    if "owner_id" not in columns:
        cur.execute("""
            ALTER TABLE cases
            ADD COLUMN owner_id TEXT REFERENCES users(user_id);
        """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_cases_owner
        ON cases(owner_id);
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            mime_type TEXT,
            ingested_at TEXT NOT NULL,
            ingested_by TEXT,
            parse_status TEXT,
            event_count INTEGER DEFAULT 0,
            error_message TEXT,
            evidence_data BLOB,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );
    """)

    # Evidence Data Column Migration for existing SQLite DBs
    evidence_columns = {
        row["name"]
        for row in cur.execute("PRAGMA table_info(evidence)")
    }
    if "evidence_data" not in evidence_columns:
        cur.execute("""
            ALTER TABLE evidence
            ADD COLUMN evidence_data BLOB;
        """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            source_path TEXT,
            source_sha256 TEXT,
            original_row INTEGER,
            timestamp_original TEXT,
            timestamp_utc TEXT,
            host TEXT,
            provider TEXT,
            event_code TEXT,
            user TEXT,
            raw_message TEXT NOT NULL,
            normalized_text TEXT NOT NULL,
            ground_truth_label TEXT,
            label_source TEXT,
            predicted_label TEXT,
            model_version TEXT,
            score REAL,
            rule_flags TEXT,
            shap_features TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id),
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            actor TEXT,
            action TEXT NOT NULL,
            evidence_id TEXT,
            timestamp_utc TEXT NOT NULL,
            input_hash TEXT,
            output_hash TEXT,
            previous_entry_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            examiner TEXT,
            report_data BLOB,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );
    """)

    # Report Data Column Migration for existing SQLite DBs
    report_columns = {
        row["name"]
        for row in cur.execute("PRAGMA table_info(reports)")
    }
    if "report_data" not in report_columns:
        cur.execute("""
            ALTER TABLE reports
            ADD COLUMN report_data BLOB;
        """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS investigator_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            event_id TEXT,
            author TEXT NOT NULL,
            note_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );
    """)

    # Indices
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_predicted ON events(predicted_label);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp_utc);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_case ON reports(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_notes_case ON investigator_notes(case_id);")

    conn.commit()
    conn.close()


def _init_postgres(db_url: str) -> None:
    """Initialize PostgreSQL database schema with persistent cloud tables."""
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    conn = psycopg2.connect(db_url)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        );
    """)

    # User Account Lockout Migration for PostgreSQL
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TEXT;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_title TEXT NOT NULL,
            description TEXT,
            examiner TEXT,
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            owner_id TEXT REFERENCES users(user_id)
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            original_filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            file_size_bytes BIGINT NOT NULL,
            mime_type TEXT,
            ingested_at TEXT NOT NULL,
            ingested_by TEXT,
            parse_status TEXT,
            event_count INTEGER DEFAULT 0,
            error_message TEXT,
            evidence_data BYTEA
        );
    """)

    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='evidence' AND column_name='evidence_data'
            ) THEN
                ALTER TABLE evidence ADD COLUMN evidence_data BYTEA;
            END IF;
        END $$;
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            source_path TEXT,
            source_sha256 TEXT,
            original_row INTEGER,
            timestamp_original TEXT,
            timestamp_utc TEXT,
            host TEXT,
            provider TEXT,
            event_code TEXT,
            "user" TEXT,
            raw_message TEXT NOT NULL,
            normalized_text TEXT NOT NULL,
            ground_truth_label TEXT,
            label_source TEXT,
            predicted_label TEXT,
            model_version TEXT,
            score REAL,
            rule_flags TEXT,
            shap_features TEXT
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id SERIAL PRIMARY KEY,
            case_id TEXT,
            actor TEXT,
            action TEXT NOT NULL,
            evidence_id TEXT,
            timestamp_utc TEXT NOT NULL,
            input_hash TEXT,
            output_hash TEXT,
            previous_entry_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            examiner TEXT,
            report_data BYTEA
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS investigator_notes (
            note_id SERIAL PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            event_id TEXT,
            author TEXT NOT NULL,
            note_text TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)

    # Indices
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_predicted ON events(predicted_label);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp_utc);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_case ON reports(case_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_notes_case ON investigator_notes(case_id);")

    conn.commit()
    conn.close()


# Auto-initialize on import
init_db()
