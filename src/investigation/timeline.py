import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser
from src.storage.db import get_db_connection

INVESTIGATION_DISCLAIMER = (
    "Investigation Notice: Temporal proximity indicates investigative correlation, "
    "not proven causation or attack sequence without independent corroborating evidence."
)

class TimelineInvestigator:
    """
    Assembles contextual forensic timelines, correlates flagged suspicious events
    with nearby baseline events, detects uncharacteristic logging gaps, and joins investigator notes.
    """

    @classmethod
    def get_case_timeline(
        cls,
        case_id: str,
        window_minutes: int = 15,
        silent_gap_threshold_seconds: float = 1800.0,
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch all case events
        cur.execute("SELECT * FROM events WHERE case_id = ? ORDER BY timestamp_utc ASC, event_id ASC;", (case_id,))
        raw_events = [dict(r) for r in cur.fetchall()]

        # Fetch investigator notes
        cur.execute("SELECT * FROM investigator_notes WHERE case_id = ? ORDER BY created_at ASC;", (case_id,))
        notes = [dict(r) for r in cur.fetchall()]
        notes_by_event: Dict[str, List[Dict[str, Any]]] = {}
        for n in notes:
            ev_id = n.get("event_id") or "__general__"
            notes_by_event.setdefault(ev_id, []).append(n)

        conn.close()

        if not raw_events:
            return {
                "case_id": case_id,
                "total_events": 0,
                "flagged_events_count": 0,
                "flagged_events": [],
                "log_gaps": [],
                "timeline_items": [],
                "disclaimer": INVESTIGATION_DISCLAIMER,
            }

        # Identify flagged events
        flagged_events = []
        parsed_timeline = []

        for ev in raw_events:
            is_suspicious_ml = ev.get("predicted_label") == "suspicious"
            raw_flags = ev.get("rule_flags")

            if isinstance(raw_flags, str):
                try:
                    parsed_flags = json.loads(raw_flags)
                    has_rules = (
                        isinstance(parsed_flags, list)
                        and len(parsed_flags) > 0
                    )
                except (ValueError, TypeError):
                    has_rules = False
            else:
                has_rules = (
                    isinstance(raw_flags, list)
                    and len(raw_flags) > 0
                )
            is_flagged = is_suspicious_ml or has_rules

            dt_utc = None
            if ev.get("timestamp_utc"):
                try:
                    dt_utc = date_parser.isoparse(
                        ev["timestamp_utc"]
                    )

                    if dt_utc.tzinfo is None:
                        dt_utc = None
                    else:
                        dt_utc = dt_utc.astimezone(
                            timezone.utc
                        )
                except Exception:
                    dt_utc = None

            ev_item = dict(ev)
            ev_item["is_flagged"] = is_flagged
            ev_item["_dt"] = dt_utc
            ev_item["notes"] = notes_by_event.get(ev["event_id"], [])

            parsed_timeline.append(ev_item)
            if is_flagged:
                flagged_events.append(ev_item)

        # Detect log gaps on a per-host basis
        log_gaps = []
        events_by_host: Dict[str, List[Dict[str, Any]]] = {}
        for ev in parsed_timeline:
            h = ev.get("host")

            if (
                h
                and str(h).strip().upper()
                not in {"UNKNOWN_HOST", "UNKNOWN", "N/A"}
                and ev.get("_dt")
            ):
                events_by_host.setdefault(h, []).append(ev)

        for host, h_events in events_by_host.items():
            h_events.sort(key=lambda x: x["_dt"])
            for i in range(len(h_events) - 1):
                t1 = h_events[i]["_dt"]
                t2 = h_events[i + 1]["_dt"]
                delta_sec = (t2 - t1).total_seconds()

                if delta_sec >= silent_gap_threshold_seconds:
                    log_gaps.append({
                        "host": host,
                        "start_time": t1.isoformat(),
                        "end_time": t2.isoformat(),
                        "gap_duration_seconds": delta_sec,
                        "gap_duration_minutes": round(delta_sec / 60.0, 1),
                        "preceding_event_id": h_events[i]["event_id"],
                        "subsequent_event_id": h_events[i + 1]["event_id"],
                        "description": f"Silent logging period of {round(delta_sec / 60.0, 1)} minutes detected on {host}."
                    })

        # Assemble contextual windows around flagged events
        contextual_groups = []
        for fe in flagged_events:
            fe_dt = fe.get("_dt")
            nearby = []
            if fe_dt:
                window_delta = timedelta(minutes=window_minutes)
                start_w = fe_dt - window_delta
                end_w = fe_dt + window_delta

                for ev in parsed_timeline:
                    if ev["event_id"] != fe["event_id"] and ev.get("_dt"):
                        if start_w <= ev["_dt"] <= end_w:
                            # Prefer same host or cross-host context
                            nearby.append({
                                "event_id": ev["event_id"],
                                "timestamp_utc": ev["timestamp_utc"],
                                "host": ev["host"],
                                "user": ev["user"],
                                "raw_message": ev["raw_message"],
                                "predicted_label": ev["predicted_label"],
                                "same_host": (ev["host"] == fe["host"]),
                            })

            contextual_groups.append({
                "flagged_event_id": fe["event_id"],
                "timestamp_utc": fe["timestamp_utc"],
                "host": fe["host"],
                "user": fe["user"],
                "raw_message": fe["raw_message"],
                "predicted_label": fe["predicted_label"],
                "score": fe["score"],
                "rule_flags": fe["rule_flags"],
                "context_events_count": len(nearby),
                "nearby_events": nearby[:10],  # cap to top 10 for display
            })

        # Clean non-serializable datetime objects before returning
        for item in parsed_timeline:
            item.pop("_dt", None)
        for item in flagged_events:
            item.pop("_dt", None)

        return {
            "case_id": case_id,
            "total_events": len(raw_events),
            "flagged_events_count": len(flagged_events),
            "flagged_events": flagged_events,
            "contextual_groups": contextual_groups,
            "log_gaps": log_gaps,
            "timeline_items": parsed_timeline[:200],  # cap timeline preview
            "disclaimer": INVESTIGATION_DISCLAIMER,
        }
