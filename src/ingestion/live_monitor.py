"""
ForensicShield AI - Live Log Monitor and Incremental Replay Engine
Supports:
1. Real-time authorized local log directory monitoring (controlled polling with offset checkpoints).
2. Incremental Simulated Replay Demo (streaming approved test fixtures with visible labels).

Aligned with Section 18.1 of the Project 218 Blueprint.
"""

import os
import time
import json
import uuid
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from config import (
    BASE_DIR,
    DATA_DIR,
    FIXTURES_DIR,
    MODEL_VERSION,
    LEGAL_DISCLAIMER,
)
from src.storage.db import get_db_connection, _db_lock
from src.preprocessing.canonical import CanonicalLogEvent, parse_utc_timestamp
from src.preprocessing.text_cleaner import clean_log_text, extract_combined_features_text
from src.ml.rules import evaluate_rules_on_text
from src.ml.model_inference import ForensicModelInference
from src.audit.audit_trail import AuditTrail

LIVE_CHECKPOINT_FILE = DATA_DIR / "derived" / "live_checkpoint.json"
LIVE_FEED_DIR = DATA_DIR / "live_feed"

class LiveLogMonitor:
    """
    Thread-safe engine for live log monitoring and simulated replay.
    Preserves checkpoints, prevents duplicate ingestion, and records processing latency.
    """

    STATE_STOPPED = "STOPPED"
    STATE_RUNNING = "RUNNING"
    STATE_PAUSED = "PAUSED"

    MODE_DIRECTORY = "DIRECTORY"
    MODE_REPLAY = "REPLAY"

    def __init__(self):
        self._lock = threading.Lock()
        self.state = self.STATE_STOPPED
        self.mode = self.MODE_REPLAY
        self.case_id = "CASE-LIVE-STREAM"
        self.target_dir = LIVE_FEED_DIR
        self.fixture_path = FIXTURES_DIR / "sample_ransomware_incident.json"
        self.poll_interval_sec = 1.0

        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()

        # Metrics and tracking
        self.total_ingested = 0
        self.flagged_count = 0
        self.last_event_time: Optional[str] = None
        self.last_latency_ms = 0.0
        self.error_count = 0
        self.recent_errors: List[str] = []
        self.recent_events_buffer: List[Dict[str, Any]] = []  # Last 50 events
        self.buffer_max = 50

        # Checkpoints for deduplication & resumption
        self.file_offsets: Dict[str, int] = {}
        self.replay_index = 0
        self.processed_hashes = set()

        self._ensure_directories()
        self._load_checkpoint()
        # Pre-warm ML model into memory to eliminate cold-start latency in live threads
        try:
            ForensicModelInference.load_model()
        except Exception:
            pass

    def _ensure_directories(self):
        LIVE_FEED_DIR.mkdir(parents=True, exist_ok=True)
        (DATA_DIR / "derived").mkdir(parents=True, exist_ok=True)

    def _load_checkpoint(self):
        if LIVE_CHECKPOINT_FILE.exists():
            try:
                with open(LIVE_CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.file_offsets = data.get("file_offsets", {})
                    self.replay_index = data.get("replay_index", 0)
                    self.total_ingested = data.get("total_ingested", 0)
                    self.flagged_count = data.get("flagged_count", 0)
            except Exception:
                self.file_offsets = {}
                self.replay_index = 0

    def _save_checkpoint(self):
        try:
            with open(LIVE_CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "file_offsets": self.file_offsets,
                    "replay_index": self.replay_index,
                    "total_ingested": self.total_ingested,
                    "flagged_count": self.flagged_count,
                    "saved_at_utc": datetime.now(timezone.utc).isoformat()
                }, f, indent=2)
        except Exception as e:
            self._log_error(f"Checkpoint save error: {str(e)}")

    def _log_error(self, msg: str):
        with self._lock:
            self.error_count += 1
            self.recent_errors.append(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")
            if len(self.recent_errors) > 20:
                self.recent_errors.pop(0)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status": self.state,
                "mode": self.mode,
                "case_id": self.case_id,
                "poll_interval_sec": self.poll_interval_sec,
                "total_ingested": self.total_ingested,
                "flagged_count": self.flagged_count,
                "last_event_time": self.last_event_time,
                "last_latency_ms": round(self.last_latency_ms, 2),
                "error_count": self.error_count,
                "recent_errors": list(self.recent_errors[-5:]),
                "recent_events": list(self.recent_events_buffer[-15:]),
                "target_dir": str(self.target_dir),
                "checkpoint": {
                    "tracked_files": len(self.file_offsets),
                    "replay_index": self.replay_index,
                },
                "disclaimer": "PROVISIONAL AUTOMATED FINDINGS: Not definitive proof of malicious or anti-forensic conduct. Requires analyst validation.",
                "legal_notice": LEGAL_DISCLAIMER,
            }

    def start(
        self,
        mode: str = MODE_REPLAY,
        target_dir: Optional[str] = None,
        case_id: Optional[str] = None,
        poll_interval_sec: float = 1.0,
    ) -> Dict[str, Any]:
        with self._lock:
            if self.state == self.STATE_RUNNING:
                return {"status": "ALREADY_RUNNING", "message": "Live monitor is already running."}

            self.mode = self.MODE_DIRECTORY if mode.upper() == self.MODE_DIRECTORY else self.MODE_REPLAY
            if target_dir:
                self.target_dir = Path(target_dir).resolve()
                self.target_dir.mkdir(parents=True, exist_ok=True)
            self.case_id = (case_id or f"CASE-LIVE-{datetime.now(timezone.utc).strftime('%Y%m%d')}").strip()
            self.poll_interval_sec = max(0.01, float(poll_interval_sec))

            # Ensure case exists in DB
            self._ensure_case_exists(self.case_id)

            self.state = self.STATE_RUNNING
            self._stop_event.clear()
            self._pause_event.clear()

            self.thread = threading.Thread(target=self._run_loop, daemon=True, name="LiveMonitorWorker")
            self.thread.start()

            AuditTrail.record_event(
                case_id=self.case_id,
                actor="LiveMonitor",
                action="LIVE_MONITOR_STARTED",
                output_hash=f"MODE_{self.mode}",
            )

            return {
                "status": "STARTED",
                "mode": self.mode,
                "case_id": self.case_id,
                "target_dir": str(self.target_dir),
                "poll_interval_sec": self.poll_interval_sec,
            }

    def pause(self) -> Dict[str, Any]:
        with self._lock:
            if self.state != self.STATE_RUNNING:
                return {"status": "NOT_RUNNING", "message": f"Cannot pause from state '{self.state}'."}
            self.state = self.STATE_PAUSED
            self._pause_event.set()
            self._save_checkpoint()

            AuditTrail.record_event(
                case_id=self.case_id,
                actor="LiveMonitor",
                action="LIVE_MONITOR_PAUSED",
            )
            return {"status": "PAUSED", "message": "Live monitoring paused."}

    def resume(self) -> Dict[str, Any]:
        with self._lock:
            if self.state != self.STATE_PAUSED:
                return {"status": "NOT_PAUSED", "message": f"Cannot resume from state '{self.state}'."}
            self.state = self.STATE_RUNNING
            self._pause_event.clear()

            AuditTrail.record_event(
                case_id=self.case_id,
                actor="LiveMonitor",
                action="LIVE_MONITOR_RESUMED",
            )
            return {"status": "RESUMED", "message": "Live monitoring resumed."}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if self.state == self.STATE_STOPPED:
                return {"status": "ALREADY_STOPPED", "message": "Live monitor is already stopped."}

            self.state = self.STATE_STOPPED
            self._stop_event.set()
            self._pause_event.clear()
            self._save_checkpoint()

            if self.thread and self.thread.is_alive() and threading.current_thread() != self.thread:
                self.thread.join(timeout=1.0)

            AuditTrail.record_event(
                case_id=self.case_id,
                actor="LiveMonitor",
                action="LIVE_MONITOR_STOPPED",
                output_hash=f"TOTAL_{self.total_ingested}_FLAGGED_{self.flagged_count}",
            )
            return {"status": "STOPPED", "message": "Live monitoring stopped and checkpoint saved."}

    def _ensure_case_exists(self, case_id: str):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT case_id FROM cases WHERE case_id = ?;", (case_id,))
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO cases (case_id, case_title, description, examiner, created_at, status)
                VALUES (?, ?, ?, ?, ?, 'ACTIVE');
            """, (
                case_id,
                f"Live Monitoring Investigation ({self.mode})",
                f"Automated incremental session in mode {self.mode}. Authorized log ingestion stream.",
                "LiveMonitor Agent",
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()
        conn.close()

    def _run_loop(self):
        """Worker thread loop executing polling or incremental replay."""
        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                time.sleep(0.5)
                continue

            try:
                t0 = time.perf_counter()
                if self.mode == self.MODE_REPLAY:
                    processed = self._process_replay_step()
                else:
                    processed = self._process_directory_step()
                t1 = time.perf_counter()

                if processed > 0:
                    with self._lock:
                        self.last_latency_ms = (t1 - t0) * 1000.0 / processed
                        self.total_ingested += processed
                    self._save_checkpoint()

            except Exception as e:
                self._log_error(f"Execution error in run loop: {str(e)}")

            time.sleep(self.poll_interval_sec)

    def _process_replay_step(self) -> int:
        """Stream one or more events from the approved test fixture incrementally."""
        if not self.fixture_path.exists():
            # Fallback to smoke fixture
            self.fixture_path = FIXTURES_DIR / "synthetic_smoke_logs.json"

        if not self.fixture_path.exists():
            self._log_error(f"Replay fixture missing: {self.fixture_path}")
            return 0

        try:
            with open(self.fixture_path, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception as e:
            self._log_error(f"Failed reading replay fixture: {str(e)}")
            return 0

        if not records:
            return 0

        # Wrap around if reached end of fixture
        if self.replay_index >= len(records):
            self.replay_index = 0

        record = records[self.replay_index]
        self.replay_index += 1

        self._ingest_single_record(record, source_desc="SIMULATED_REPLAY_STREAM")
        return 1

    def _process_directory_step(self) -> int:
        """Poll authorized directory for newly appended lines or files."""
        if not self.target_dir.exists():
            return 0

        valid_exts = {".log", ".txt", ".json", ".csv"}
        files = [p for p in self.target_dir.iterdir() if p.is_file() and p.suffix.lower() in valid_exts]
        processed_count = 0

        for file_path in sorted(files):
            key = str(file_path.resolve())
            current_size = file_path.stat().st_size
            last_offset = self.file_offsets.get(key, 0)

            # Handle log rotation or truncation
            if current_size < last_offset:
                last_offset = 0

            if current_size == last_offset:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(last_offset)
                    new_lines = f.readlines()
                    new_offset = f.tell()

                self.file_offsets[key] = new_offset

                for line in new_lines:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    # Parse JSON or raw syslog line
                    if line_str.startswith("{") and line_str.endswith("}"):
                        try:
                            rec = json.loads(line_str)
                        except Exception:
                            rec = {"raw_message": line_str}
                    else:
                        rec = {"raw_message": line_str}

                    self._ingest_single_record(rec, source_desc=f"LIVE_DIR:{file_path.name}")
                    processed_count += 1

            except Exception as e:
                self._log_error(f"Error reading {file_path.name}: {str(e)}")

        return processed_count

    def _ingest_single_record(self, record: Dict[str, Any], source_desc: str):
        """Process, normalize, classify and store a single live or replayed event."""
        now_utc = datetime.now(timezone.utc).isoformat()
        raw_msg = (
            record.get("raw_message")
            or record.get("message")
            or record.get("command_line")
            or json.dumps(record)
        )
        norm_text = clean_log_text(raw_msg)

        # Compute SHA-256 fingerprint
        content_hash = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()

        # Deduplication check
        if content_hash in self.processed_hashes:
            return
        self.processed_hashes.add(content_hash)
        if len(self.processed_hashes) > 10000:
            self.processed_hashes.clear()

        event_id = f"EVT-LIVE-{uuid.uuid4().hex[:8].upper()}"
        ts_orig = record.get("timestamp_original") or record.get("timestamp") or record.get("TimeCreated") or now_utc
        ts_utc = parse_utc_timestamp(ts_orig) or now_utc
        host = record.get("host") or record.get("Computer") or "LOCAL-HOST"
        user = record.get("user") or record.get("User") or "SYSTEM"
        provider = record.get("provider") or record.get("ProviderName") or "LiveCollector"
        event_code = str(record.get("event_code") or record.get("event_id") or record.get("EventID") or "")

        # 1. Heuristic Rule matching
        rule_matches = evaluate_rules_on_text(norm_text)
        rule_flags_str = json.dumps(rule_matches) if rule_matches else None

        # 2. ML Inference (if ready)
        pred_label = "normal"
        score = 0.0
        mv = MODEL_VERSION
        if ForensicModelInference.is_model_ready():
            pred = ForensicModelInference.predict_single(norm_text)
            pred_label = pred["predicted_label"]
            score = pred["score"]
            mv = pred["model_version"]
        elif rule_matches:
            # If model is not trained but rules match, flag as suspicious
            pred_label = "suspicious"
            score = 0.85

        is_flagged = (pred_label == "suspicious") or bool(rule_matches)

        # 3. Insert into Database
        evidence_id = f"LIVE-SOURCE-{source_desc}"
        with _db_lock:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT evidence_id FROM evidence WHERE evidence_id = ?;", (evidence_id,))
            if not cur.fetchone():
                cur.execute("""
                    INSERT OR IGNORE INTO evidence (
                        evidence_id, case_id, original_filename, stored_path, sha256_hash,
                        file_size_bytes, mime_type, ingested_at, parse_status
                    ) VALUES (?, ?, ?, ?, ?, 0, 'live_stream', ?, 'SUCCESS');
                """, (
                    evidence_id,
                    self.case_id,
                    source_desc,
                    source_desc,
                    "0" * 64,
                    datetime.now(timezone.utc).isoformat(),
                ))
            cur.execute("""
                INSERT INTO events (
                    event_id, case_id, evidence_id, source_path, source_sha256,
                    original_row, timestamp_original, timestamp_utc, host,
                    provider, event_code, "user", raw_message, normalized_text,
                    ground_truth_label, label_source, predicted_label,
                    model_version, score, rule_flags, shap_features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                event_id,
                self.case_id,
                evidence_id,
                source_desc,
                content_hash,
                self.total_ingested + 1,
                ts_orig,
                ts_utc,
                host,
                provider,
                event_code,
                user,
                raw_msg,
                norm_text,
                record.get("ground_truth_label"),
                "LIVE_STREAM",
                pred_label,
                mv,
                score,
                rule_flags_str,
                None,
            ))
            conn.commit()
            conn.close()

        # Update in-memory sliding buffer
        event_summary = {
            "event_id": event_id,
            "timestamp_utc": ts_utc,
            "host": host,
            "provider": provider,
            "raw_message": raw_msg[:120] + ("..." if len(raw_msg) > 120 else ""),
            "predicted_label": pred_label,
            "score": round(score, 3),
            "is_flagged": is_flagged,
            "rule_matches": rule_matches,
            "mode": self.mode,
            "source": source_desc,
        }

        with self._lock:
            self.last_event_time = ts_utc
            if is_flagged:
                self.flagged_count += 1
            self.recent_events_buffer.append(event_summary)
            if len(self.recent_events_buffer) > self.buffer_max:
                self.recent_events_buffer.pop(0)

# Global singleton
live_monitor = LiveLogMonitor()
