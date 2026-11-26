import re

def clean_log_text(raw_text: str) -> str:
    """
    Sanitizes non-semantic log noise while strictly preserving critical
    forensic command patterns, switches, filenames, and anti-forensic keywords.
    """
    if not raw_text or not isinstance(raw_text, str):
        return ""

    # Replace null bytes and non-printable control characters
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ', raw_text)

    # Standardize common Windows GUID patterns to [GUID] placeholder if appropriate,
    # or preserve them. To preserve switches like /w: or -enc, we only normalize whitespace:
    text = re.sub(r'\s+', ' ', text).strip()

    # Lowercase for model consistency
    text = text.lower()

    return text

def extract_combined_features_text(event_dict: dict) -> str:
    """
    Combines relevant canonical event fields (provider, event_code, process, command_line, raw_message)
    into a rich, descriptive string for NLP vectorization.
    """
    parts = []
    if event_dict.get("provider"):
        parts.append(str(event_dict["provider"]))
    if event_dict.get("event_code"):
        parts.append(f"eventid_{event_dict['event_code']}")
    if event_dict.get("user"):
        parts.append(f"user_{event_dict['user']}")
    if event_dict.get("process"):
        parts.append(str(event_dict["process"]))
    if event_dict.get("command_line"):
        parts.append(str(event_dict["command_line"]))
    if event_dict.get("raw_message"):
        parts.append(str(event_dict["raw_message"]))

    combined = " ".join([p for p in parts if p])
    return clean_log_text(combined)
