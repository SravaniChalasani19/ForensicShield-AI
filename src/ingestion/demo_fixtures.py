"""
ForensicShield AI - Approved Public Demonstration Evidence Fixtures
Server-side allowlist for safe, synthetic forensic log ingestion in the public web publication.

Enforces:
1. Strict server-side allowlist (no client-controlled paths).
2. Pre-computed SHA-256 cryptographic verification before intake.
3. Explicit synthetic labeling and data minimization.
4. Safe redistribution compliance (no confidential or real incident data).
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple
from config import BASE_DIR

APPROVED_DEMO_FIXTURES: Dict[str, Dict[str, Any]] = {
    "public_demo_logs": {
        "id": "public_demo_logs",
        "name": "Public Forensic Log Analysis Demo (3 Events - JSON)",
        "filename": "public_demo_logs.json",
        "relative_path": "data/fixtures/public_demo_logs.json",
        "expected_sha256": "6dac4e828686bebe6d85ddf6161384630492f1c17789dea72f7022b2619c0cf0",
        "record_count": 3,
        "format": "JSON (Windows Event Log)",
        "description": "Synthetic educational records demonstrating normal authentication and forensic audit alerts.",
        "is_synthetic": True,
        "classification": "SYNTHETIC_EDUCATIONAL_DEMO",
    },
}

def get_approved_fixtures_catalog() -> list:
    """Return public metadata list for the approved demonstration fixtures."""
    catalog = []
    for f_id, info in APPROVED_DEMO_FIXTURES.items():
        catalog.append({
            "id": info["id"],
            "name": info["name"],
            "filename": info["filename"],
            "record_count": info["record_count"],
            "format": info["format"],
            "description": info["description"],
            "sha256_hash": info["expected_sha256"],
            "is_synthetic": info["is_synthetic"],
            "classification": info["classification"],
        })
    return catalog


def load_approved_fixture_bytes(fixture_id: str) -> Tuple[str, bytes, str, Dict[str, Any]]:
    """
    Safely load an approved synthetic demonstration fixture from server storage.

    Returns:
        (filename, file_bytes, expected_sha256, fixture_info)

    Raises:
        ValueError: If fixture_id is unknown or invalid.
        RuntimeError: If file is missing or cryptographic hash verification fails.
    """
    if not isinstance(fixture_id, str) or fixture_id not in APPROVED_DEMO_FIXTURES:
        raise ValueError(
            f"Invalid or unapproved fixture identifier '{fixture_id}'. "
            f"Select a verified fixture from the demonstration catalog."
        )

    fixture = APPROVED_DEMO_FIXTURES[fixture_id]
    file_path = BASE_DIR / fixture["relative_path"]

    if not file_path.is_file():
        raise RuntimeError(
            f"Approved fixture file '{fixture['filename']}' is not available on server."
        )

    file_bytes = file_path.read_bytes()
    computed_hash = hashlib.sha256(file_bytes).hexdigest()

    if computed_hash.lower() != fixture["expected_sha256"].lower():
        raise RuntimeError(
            f"Cryptographic hash mismatch for approved fixture '{fixture['filename']}': "
            f"expected {fixture['expected_sha256']}, got {computed_hash}."
        )

    return fixture["filename"], file_bytes, fixture["expected_sha256"], fixture
