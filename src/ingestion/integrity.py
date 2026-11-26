import os
import stat
import hashlib
import uuid
from pathlib import Path
from typing import Dict, Any, Union
from werkzeug.utils import secure_filename
from config import ORIGINALS_DIR, MAX_CONTENT_LENGTH, ALLOWED_EXTENSIONS, DISALLOWED_EXTENSIONS

class EvidenceIntegrityManager:
    """
    Manages forensic evidence intake, SHA-256 cryptographic hashing,
    and immutable storage under data/originals/.
    """

    @staticmethod
    def compute_sha256(data: Union[bytes, Path, str]) -> str:
        """Compute strict SHA-256 digest from raw bytes or file path."""
        hasher = hashlib.sha256()
        if isinstance(data, bytes):
            hasher.update(data)
        else:
            path = Path(data)
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
        return hasher.hexdigest().lower()

    @classmethod
    def validate_file(cls, filename: str, file_size: int) -> Dict[str, Any]:
        """Validate filename extension and file size against security constraints."""
        safe_name = secure_filename(filename)
        if not safe_name:
            return {"valid": False, "error": "Invalid or empty filename."}

        ext = Path(safe_name).suffix.lower()
        if ext in DISALLOWED_EXTENSIONS:
            return {
                "valid": False,
                "error": f"Executable or script artifact '{ext}' is prohibited for direct ingestion. Upload logs or text exports only."
            }

        if ext not in ALLOWED_EXTENSIONS:
            return {
                "valid": False,
                "error": f"Unsupported file extension '{ext}'. Supported formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
            }

        if file_size > MAX_CONTENT_LENGTH:
            return {
                "valid": False,
                "error": f"File size ({file_size} bytes) exceeds maximum allowable limit ({MAX_CONTENT_LENGTH} bytes)."
            }

        return {"valid": True, "safe_filename": safe_name, "extension": ext}

    @classmethod
    def ingest_original_evidence(
        cls,
        case_id: str,
        filename: str,
        file_bytes: bytes,
    ) -> Dict[str, Any]:
        """
        Store unmodified original evidence into restricted storage with SHA-256 verification.
        Applies read-only attribute to protect original bits from accidental alteration.
        """
        validation = cls.validate_file(filename, len(file_bytes))
        if not validation["valid"]:
            raise ValueError(validation["error"])

        safe_filename = validation["safe_filename"]
        evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
        sha256_digest = cls.compute_sha256(file_bytes)

        # Restricted case-specific directory
        case_folder = ORIGINALS_DIR / case_id
        case_folder.mkdir(parents=True, exist_ok=True)

        target_path = case_folder / f"{evidence_id}_{safe_filename}"

        # Write original bytes
        with open(target_path, "wb") as f:
            f.write(file_bytes)

        # Make file read-only on disk
        try:
            os.chmod(target_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except Exception:
            pass  # Windows permissions fallback

        return {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "original_filename": filename,
            "safe_filename": safe_filename,
            "stored_path": str(target_path.resolve()),
            "sha256_hash": sha256_digest,
            "file_size_bytes": len(file_bytes),
            "extension": validation["extension"],
        }

    @classmethod
    def verify_stored_file(cls, stored_path: Union[str, Path], expected_sha256: str) -> bool:
        """Verify that stored evidence bytes still match their original ingested digest."""
        current_hash = cls.compute_sha256(stored_path)
        return current_hash.lower() == expected_sha256.lower()
