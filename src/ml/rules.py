
import re
from typing import List, Dict, Any, Optional


class ForensicRule:
    def __init__(self, rule_id, technique, name,
                 patterns, description, severity="HIGH"):
        self.rule_id = rule_id
        self.technique = technique
        self.name = name
        self.patterns = [
            re.compile(p, re.IGNORECASE) for p in patterns
        ]
        self.description = description
        self.severity = severity

    def match(self, text):
        for pattern in self.patterns:
            match = pattern.search(text)
            if match:
                return {
                    "rule_id": self.rule_id,
                    "technique": self.technique,
                    "name": self.name,
                    "matched_pattern": match.group(0),
                    "description": self.description,
                    "severity": self.severity,
                }
        return None


FORENSIC_RULES = [
    ForensicRule(
        "RULE-EVT-002",
        "event_log_clearing",
        "Security Audit Log Cleared Event",
        [
            r"event\s*id\s*[:=]?\s*1102\b",
            r"event\s*id\s*[:=]?\s*104\b",
            r"the audit log was cleared",
            r"security audit log cleared",
            r"the system log file was cleared",
            r"\beventid_104\b",
            r"\beventid_1102\b",
        ],
        "Audit log clearing indicator requiring investigator review.",
        "CRITICAL"
    ),
    ForensicRule(
        "RULE-BAK-001",
        "backup_deletion",
        "Backup Integrity Alert",
        [r"backup deletion detected"],
        "Potential backup integrity incident."
    ),
    ForensicRule(
        "RULE-SEC-001",
        "security_tool_tampering",
        "Security Monitoring Alert",
        [r"security monitoring interrupted"],
        "Potential security monitoring incident."
    ),
    ForensicRule(
        "RULE-TIME-001",
        "timestamp_manipulation",
        "Timestamp Integrity Alert",
        [r"timestamp anomaly detected"],
        "Potential timestamp integrity incident."
    ),
    ForensicRule(
        "RULE-EVR-001",
        "evidence_removal",
        "Evidence Integrity Alert",
        [r"evidence removal detected"],
        "Potential evidence integrity incident."
    ),
    ForensicRule(
        "RULE-HIST-001",
        "history_clearing",
        "History Integrity Alert",
        [r"history integrity violation"],
        "Potential history integrity incident.",
        "MEDIUM"
    ),
    ForensicRule(
        "RULE-OBF-001",
        "command_obfuscation",
        "Obfuscation Alert",
        [r"obfuscation indicator detected"],
        "Potential obfuscation indicator.",
        "MEDIUM"
    ),
]


def evaluate_rules_on_text(text: str) -> List[Dict[str, Any]]:
    matches = []

    if not text:
        return matches

    for rule in FORENSIC_RULES:
        result = rule.match(text)
        if result:
            matches.append(result)

    return matches
