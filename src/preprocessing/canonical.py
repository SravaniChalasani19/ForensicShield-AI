import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dateutil import parser as date_parser

def parse_utc_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """
    Convert complete ISO timestamps with explicit timezone
    information to UTC. Reject incomplete or ambiguous timestamps.
    """
    if not isinstance(ts_str, str) or not ts_str.strip():
        return None

    value = ts_str.strip()

    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]"
        r"\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?"
        r"(?:Z|[+-]\d{2}:?\d{2})",
        value
    ):
        return None

    try:
        dt = date_parser.isoparse(value)

        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc).isoformat()

    except (ValueError, OverflowError, TypeError):
        return None
class CanonicalLogEvent:
    """
    Project 218 Canonical Schema Representation for ingested and processed forensic logs.
    Preserves original raw messages, source references, hashes, and derived features.
    """
    def __init__(
        self,
        case_id: str,
        evidence_id: str,
        event_id: Optional[str] = None,
        source_path: Optional[str] = None,
        source_sha256: Optional[str] = None,
        original_row: Optional[int] = None,
        timestamp_original: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
        host: Optional[str] = None,
        provider: Optional[str] = None,
        event_code: Optional[str] = None,
        user: Optional[str] = None,
        raw_message: str = "",
        normalized_text: str = "",
        ground_truth_label: Optional[str] = None,
        label_source: Optional[str] = None,
        predicted_label: Optional[str] = None,
        model_version: Optional[str] = None,
        score: Optional[float] = None,
        rule_flags: Optional[str] = None,
        shap_features: Optional[str] = None,
    ):
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.event_id = event_id or f"EVT-{uuid.uuid4().hex[:10].upper()}"
        self.source_path = source_path
        self.source_sha256 = source_sha256
        self.original_row = original_row
        self.timestamp_original = timestamp_original
        self.timestamp_utc = timestamp_utc or parse_utc_timestamp(timestamp_original)
        self.host = host
        self.provider = provider
        self.event_code = str(event_code) if event_code is not None else None
        self.user = user
        self.raw_message = raw_message or ""
        self.normalized_text = normalized_text or ""
        self.ground_truth_label = ground_truth_label
        self.label_source = label_source
        self.predicted_label = predicted_label
        self.model_version = model_version
        self.score = float(score) if score is not None else None
        self.rule_flags = rule_flags
        self.shap_features = shap_features

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "original_row": self.original_row,
            "timestamp_original": self.timestamp_original,
            "timestamp_utc": self.timestamp_utc,
            "host": self.host,
            "provider": self.provider,
            "event_code": self.event_code,
            "user": self.user,
            "raw_message": self.raw_message,
            "normalized_text": self.normalized_text,
            "ground_truth_label": self.ground_truth_label,
            "label_source": self.label_source,
            "predicted_label": self.predicted_label,
            "model_version": self.model_version,
            "score": self.score,
            "rule_flags": self.rule_flags,
            "shap_features": self.shap_features,
        }
