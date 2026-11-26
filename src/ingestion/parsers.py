import os
import csv
import json
import io
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple
from src.preprocessing.canonical import CanonicalLogEvent, parse_utc_timestamp
from src.preprocessing.text_cleaner import clean_log_text, extract_combined_features_text

# Regex for common Linux Syslog: "Oct 15 08:12:30 LINUX-APP01 sshd[1420]: Accepted..."
SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|'
    r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'
    r'(?P<host>[\w\.\-]+)\s+'
    r'(?:(?P<service>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+)?'
    r'(?P<message>.*)$'
)

class LogParserRegistry:
    """
    Parses supported log formats (CSV, JSON, JSONL, TXT, Syslog, EVTX)
    into CanonicalLogEvent structures without fabricating missing data.
    """

    @classmethod
    def parse_file(
        cls,
        case_id: str,
        evidence_id: str,
        file_path: Path,
        source_sha256: str,
    ) -> Tuple[List[CanonicalLogEvent], int, int, List[str]]:
        """
        Main entry point for file parsing.
        Returns (parsed_events, success_count, error_count, error_messages).
        """
        ext = file_path.suffix.lower()
        if ext == ".csv":
            return cls.parse_csv(case_id, evidence_id, file_path, source_sha256)
        elif ext in [".json", ".jsonl"]:
            return cls.parse_json(case_id, evidence_id, file_path, source_sha256)
        elif ext in [".txt", ".log"]:
            return cls.parse_text_log(case_id, evidence_id, file_path, source_sha256)
        elif ext == ".evtx":
            return cls.parse_evtx(case_id, evidence_id, file_path, source_sha256)
        else:
            return [], 0, 1, [f"Unsupported format {ext}"]

    
    @classmethod
    def parse_csv(
        cls,
        case_id: str,
        evidence_id: str,
        file_path: Path,
        source_sha256: str,
    ) -> Tuple[List[CanonicalLogEvent], int, int, List[str]]:

        events = []
        errors = []

        with open(
            file_path,
            "r",
            encoding="utf-8-sig",
            errors="replace",
            newline=""
        ) as f:

            sample = f.read(2048)
            f.seek(0)

            delimiter = "\t" if "\t" in sample and "," not in sample else ","
            reader = csv.DictReader(f, delimiter=delimiter)

            fields = set(reader.fieldnames or [])

            is_htb = {
                "Id", "RecordId", "SourceFile", "TimeCreated"
            }.issubset(fields)

            is_dfrws = {
                "Time", "Inode", "Filename", "Note"
            }.issubset(fields)

            is_silrad = {
                "event.code", "Image", "Description", "class"
            }.issubset(fields)

            for row_idx, row in enumerate(reader, start=1):
                try:
                    ts_orig = (
                        row.get("timestamp")
                        or row.get("timestamp_original")
                        or row.get("timestamp_utc")
                        or row.get("TimeCreated")
                        or row.get("UtcTime")
                        or row.get("Date")
                    )

                    host = (
                        row.get("host")
                        or row.get("Computer")
                        or row.get("hostname")
                        or row.get("MachineName")
                    )

                    user = (
                        row.get("user")
                        or row.get("SubjectUserName")
                        or row.get("TargetUserName")
                        or row.get("User")
                    )

                    event_code = (
                        row.get("event_id")
                        or row.get("event_code")
                        or row.get("EventID")
                        or row.get("Id")
                        or row.get("event.code")
                    )

                    provider = (
                        row.get("provider")
                        or row.get("ProviderName")
                        or row.get("service")
                    )

                    process = row.get("process") or row.get("Image")

                    command_line = (
                        row.get("command_line")
                        or row.get("CommandLine")
                        or row.get("cmd")
                    )

                    raw_msg = (
                        row.get("raw_message")
                        or row.get("message")
                        or row.get("Message")
                        or row.get("raw_line")
                    )

                    gt_label = (
                        row.get("ground_truth_label")
                        or row.get("label")
                    )

                    if is_htb:
                        gt_label = None

                        if not raw_msg:
                            raw_msg = (
                                f"Message unavailable; "
                                f"Event ID: {event_code}; "
                                f"Provider: {provider}"
                            )

                    elif is_dfrws:
                        ts_orig = row.get("Time")
                        if ts_orig and ts_orig.startswith("0000"):
                            ts_orig = None

                        raw_msg = row.get("Note") or ""
                        gt_label = None

                    elif is_silrad:
                        ts_orig = None

                        raw_msg = " ".join(
                            str(row.get(key) or "")
                            for key in [
                                "Description",
                                "Details",
                                "EventType",
                                "Image",
                                "ParentImage",
                                "TargetObject"
                            ]
                        ).strip()

                        gt_label = None

                    elif not raw_msg:
                        raw_msg = " ".join(
                            f"{k}={v}"
                            for k, v in row.items()
                            if v and k not in {
                                "label",
                                "ground_truth_label",
                                "class"
                            }
                        )

                    norm_text = extract_combined_features_text({
                        "provider": provider,
                        "event_code": event_code,
                        "user": user,
                        "process": process,
                        "command_line": command_line,
                        "raw_message": raw_msg,
                    })

                    event = CanonicalLogEvent(
                        case_id=case_id,
                        evidence_id=evidence_id,
                        source_path=str(file_path),
                        source_sha256=source_sha256,
                        original_row=row_idx,
                        timestamp_original=ts_orig,
                        host=host,
                        provider=provider,
                        event_code=event_code,
                        user=user,
                        raw_message=raw_msg,
                        normalized_text=norm_text,
                        ground_truth_label=gt_label,
                        label_source="CSV_COLUMN" if gt_label else None,
                    )

                    # External timestamps without a verified timezone
                    # must not be represented as confirmed UTC.
                    if is_htb or is_dfrws:
                        event.timestamp_utc = None

                    events.append(event)

                except Exception as e:
                    errors.append(f"Row {row_idx}: {str(e)}")

        return events, len(events), len(errors), errors

    @classmethod
    def parse_json(
        cls,
        case_id: str,
        evidence_id: str,
        file_path: Path,
        source_sha256: str,
    ) -> Tuple[List[CanonicalLogEvent], int, int, List[str]]:
        events = []
        errors = []
        success_count = 0
        error_count = 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        # Try parsing as JSON array/object first
        items = []
        if content.startswith("[") and content.endswith("]"):
            try:
                items = json.loads(content)
            except Exception as e:
                pass

        if not items:
            # Try line-by-line JSONL
            for line_no, line in enumerate(content.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    obj["__row_idx"] = line_no
                    items.append(obj)
                except Exception as e:
                    error_count += 1
                    errors.append(f"Line {line_no} JSON parse error: {str(e)}")

        for item_idx, obj in enumerate(items, start=1):
            try:
                row_idx = obj.get("__row_idx", item_idx)
                ts_orig = (
                    obj.get("timestamp_original")
                    or obj.get("timestamp_utc")
                    or obj.get("timestamp")
                    or obj.get("TimeCreated")
                    or obj.get("UtcTime")
                )
                host = obj.get("host") or obj.get("Computer") or obj.get("hostname")
                user = obj.get("user") or obj.get("SubjectUserName") or obj.get("TargetUserName")
                event_code = obj.get("event_code") or obj.get("event_id") or obj.get("EventID")
                provider = obj.get("provider") or obj.get("ProviderName")
                process = obj.get("process") or obj.get("Image")
                cmd = obj.get("command_line") or obj.get("CommandLine")
                raw_msg = (
                    obj.get("raw_message")
                    or obj.get("message")
                    or obj.get("raw_line")
                    or json.dumps(obj)
                )
                gt_label = obj.get("ground_truth_label") or obj.get("label")

                temp_dict = {
                    "provider": provider,
                    "event_code": event_code,
                    "user": user,
                    "process": process,
                    "command_line": cmd,
                    "raw_message": raw_msg,
                }
                norm_text = extract_combined_features_text(temp_dict)

                event = CanonicalLogEvent(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    source_path=str(file_path),
                    source_sha256=source_sha256,
                    original_row=row_idx,
                    timestamp_original=ts_orig,
                    host=host,
                    provider=provider,
                    event_code=event_code,
                    user=user,
                    raw_message=raw_msg,
                    normalized_text=norm_text,
                    ground_truth_label=gt_label,
                    label_source="JSON_RECORD" if gt_label else None,
                )
                events.append(event)
                success_count += 1
            except Exception as e:
                error_count += 1
                errors.append(f"Record {item_idx}: {str(e)}")

        return events, success_count, error_count, errors

    @classmethod
    def parse_text_log(
        cls,
        case_id: str,
        evidence_id: str,
        file_path: Path,
        source_sha256: str,
    ) -> Tuple[List[CanonicalLogEvent], int, int, List[str]]:
        events = []
        errors = []
        success_count = 0
        error_count = 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                raw_line = line.strip()
                if not raw_line:
                    continue
                try:
                    match = SYSLOG_PATTERN.match(raw_line)
                    if match:
                        ts_orig = match.group("timestamp")
                        host = match.group("host")
                        provider = match.group("service")
                        msg = match.group("message")
                    else:
                        ts_orig = None
                        host = None
                        provider = None
                        msg = raw_line

                    norm_text = clean_log_text(raw_line)

                    event = CanonicalLogEvent(
                        case_id=case_id,
                        evidence_id=evidence_id,
                        source_path=str(file_path),
                        source_sha256=source_sha256,
                        original_row=line_no,
                        timestamp_original=ts_orig,
                        host=host,
                        provider=provider,
                        raw_message=raw_line,
                        normalized_text=norm_text,
                    )
                    events.append(event)
                    success_count += 1
                except Exception as e:
                    error_count += 1
                    errors.append(f"Line {line_no}: {str(e)}")

        return events, success_count, error_count, errors

    @classmethod
    def parse_evtx(
        cls,
        case_id: str,
        evidence_id: str,
        file_path: Path,
        source_sha256: str,
    ) -> Tuple[List[CanonicalLogEvent], int, int, List[str]]:
        events = []
        errors = []
        success_count = 0
        error_count = 0

        try:
            import Evtx.Evtx as evtx
            import xml.etree.ElementTree as ET

            with evtx.Evtx(str(file_path)) as log:
                for record_idx, record in enumerate(log.records(), start=1):
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

                        system_elem = root.find("ns:System", ns)
                        event_id_elem = system_elem.find("ns:EventID", ns) if system_elem is not None else None
                        event_code = event_id_elem.text if event_id_elem is not None else None

                        time_elem = system_elem.find("ns:TimeCreated", ns) if system_elem is not None else None
                        ts_orig = time_elem.attrib.get("SystemTime") if time_elem is not None else None

                        computer_elem = system_elem.find("ns:Computer", ns) if system_elem is not None else None
                        host = computer_elem.text if computer_elem is not None else None

                        provider_elem = system_elem.find("ns:Provider", ns) if system_elem is not None else None
                        provider = provider_elem.attrib.get("Name") if provider_elem is not None else None

                        # EventData elements
                        event_data = {}
                        data_elem = root.find("ns:EventData", ns)
                        if data_elem is not None:
                            for d in data_elem.findall("ns:Data", ns):
                                name = d.attrib.get("Name")
                                val = d.text or ""
                                if name:
                                    event_data[name] = val

                        user = event_data.get("SubjectUserName") or event_data.get("TargetUserName")
                        cmd = event_data.get("CommandLine")
                        proc = event_data.get("NewProcessName") or event_data.get("ProcessName")

                        raw_msg = f"EventID: {event_code} | Provider: {provider} | Computer: {host} | Details: {json.dumps(event_data)}"
                        norm_text = extract_combined_features_text({
                            "provider": provider,
                            "event_code": event_code,
                            "user": user,
                            "process": proc,
                            "command_line": cmd,
                            "raw_message": raw_msg
                        })

                        event = CanonicalLogEvent(
                            case_id=case_id,
                            evidence_id=evidence_id,
                            source_path=str(file_path),
                            source_sha256=source_sha256,
                            original_row=record_idx,
                            timestamp_original=ts_orig,
                            host=host,
                            provider=provider,
                            event_code=event_code,
                            user=user,
                            raw_message=raw_msg,
                            normalized_text=norm_text,
                        )
                        events.append(event)
                        success_count += 1
                    except Exception as rec_err:
                        error_count += 1
                        errors.append(f"EVTX Record {record_idx}: {str(rec_err)}")
        except ImportError:
            error_count += 1
            errors.append("python-evtx parser library is not installed in current environment.")
        except Exception as e:
            error_count += 1
            errors.append(f"EVTX file read error: {str(e)}")

        return events, success_count, error_count, errors
