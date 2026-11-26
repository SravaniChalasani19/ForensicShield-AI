import hashlib
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path
from src.storage.db import get_db_connection, _db_lock

GENESIS_HASH = "0" * 64

class AuditTrail:
    """
    Append-only tamper-evident audit ledger with SHA-256 cryptographic chaining.
    Records every critical investigative action: case creation, evidence import,
    log parsing, model analysis, XAI explanation generation, and report export.
    """

    @staticmethod
    def _compute_entry_hash(
        prev_hash: str,
        case_id: str,
        actor: str,
        action: str,
        evidence_id: Optional[str],
        timestamp_utc: str,
        input_hash: Optional[str],
        output_hash: Optional[str],
    ) -> str:
        payload = f"{prev_hash}|{case_id or ''}|{actor or ''}|{action or ''}|{evidence_id or ''}|{timestamp_utc}|{input_hash or ''}|{output_hash or ''}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def record_event(
        cls,
        case_id: Optional[str],
        actor: str,
        action: str,
        evidence_id: Optional[str] = None,
        input_hash: Optional[str] = None,
        output_hash: Optional[str] = None,
        custom_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an immutable action in the audit trail with hash chaining."""
        timestamp_utc = custom_timestamp or datetime.now(timezone.utc).isoformat()
        
        with _db_lock:
            conn = get_db_connection()
            cur = conn.cursor()

            # Retrieve previous entry hash
            cur.execute("SELECT entry_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1;")
            row = cur.fetchone()
            prev_hash = row["entry_hash"] if row else GENESIS_HASH

            entry_hash = cls._compute_entry_hash(
                prev_hash=prev_hash,
                case_id=case_id or "",
                actor=actor,
                action=action,
                evidence_id=evidence_id,
                timestamp_utc=timestamp_utc,
                input_hash=input_hash,
                output_hash=output_hash,
            )

            cur.execute("""
                INSERT INTO audit_log (
                    case_id, actor, action, evidence_id, timestamp_utc,
                    input_hash, output_hash, previous_entry_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                case_id, actor, action, evidence_id, timestamp_utc,
                input_hash, output_hash, prev_hash, entry_hash
            ))

            audit_id = cur.lastrowid
            if not audit_id:
                cur.execute(
                    "SELECT audit_id FROM audit_log WHERE entry_hash = ? ORDER BY audit_id DESC LIMIT 1;",
                    (entry_hash,)
                )
                id_row = cur.fetchone()
                audit_id = id_row["audit_id"] if id_row else None
            conn.commit()
            conn.close()

            return {
                "audit_id": audit_id,
                "case_id": case_id,
                "actor": actor,
                "action": action,
                "evidence_id": evidence_id,
                "timestamp_utc": timestamp_utc,
                "input_hash": input_hash,
                "output_hash": output_hash,
                "previous_entry_hash": prev_hash,
                "entry_hash": entry_hash,
            }

    @classmethod
    def get_case_audit_log(cls, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve chronological audit trail entries for a specific case."""
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_log WHERE case_id = ? ORDER BY audit_id ASC;", (case_id,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    @classmethod
    def verify_chain(cls, case_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify mathematical integrity of the cryptographic hash chain.
        Detects unauthorized record alteration, insertion, or deletion.
        """
        conn = get_db_connection()
        cur = conn.cursor()
        if case_id:
            cur.execute("SELECT * FROM audit_log WHERE case_id = ? ORDER BY audit_id ASC;", (case_id,))
        else:
            cur.execute("SELECT * FROM audit_log ORDER BY audit_id ASC;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        if not rows:
            return {
                "is_valid": True,
                "total_entries": 0,
                "message": "Audit chain is empty and valid (Genesis state).",
                "broken_at_id": None
            }

        expected_prev = GENESIS_HASH if not case_id else rows[0]["previous_entry_hash"]

        for i, row in enumerate(rows):
            # 1. Check backward linkage
            if not case_id and row["previous_entry_hash"] != expected_prev:
                return {
                    "is_valid": False,
                    "total_entries": len(rows),
                    "broken_at_id": row["audit_id"],
                    "error": f"Chain linkage broken at audit_id {row['audit_id']}. Expected prev_hash {expected_prev}, got {row['previous_entry_hash']}."
                }

            # 2. Check hash recalculation
            recalculated = cls._compute_entry_hash(
                prev_hash=row["previous_entry_hash"],
                case_id=row["case_id"] or "",
                actor=row["actor"] or "",
                action=row["action"] or "",
                evidence_id=row["evidence_id"],
                timestamp_utc=row["timestamp_utc"],
                input_hash=row["input_hash"],
                output_hash=row["output_hash"],
            )

            if recalculated != row["entry_hash"]:
                return {
                    "is_valid": False,
                    "total_entries": len(rows),
                    "broken_at_id": row["audit_id"],
                    "error": f"Hash integrity failure at audit_id {row['audit_id']}. Computed {recalculated}, stored {row['entry_hash']}."
                }

            expected_prev = row["entry_hash"]

        return {
            "is_valid": True,
            "total_entries": len(rows),
            "latest_hash": rows[-1]["entry_hash"],
            "message": "Audit chain integrity verified. All cryptographic links are valid.",
            "broken_at_id": None
        }
