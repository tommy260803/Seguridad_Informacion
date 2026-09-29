"""
Cryptographic Forensic Evidence Manifest Generator for PhishGuard.
Creates immutable, tamper-evident audit packages with SHA-256 hashes of all artifacts
for digital forensics, SOC incident response (DFIR), and legal proceedings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_SIGNING_KEY = os.getenv("FORENSIC_SIGNING_KEY", "phishguard-forensic-integrity-key-v1").encode("utf-8")

def compute_sha256(data: bytes | str | None) -> Optional[str]:
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def compute_file_sha256(file_path: str | Path | None) -> Optional[str]:
    if not file_path:
        return None
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return None
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def generate_forensic_manifest(
    job_id: str,
    url: str,
    decision: str,
    probability: float,
    confidence: float,
    modalities_consulted: List[str],
    evidence_summary: List[Dict[str, Any]],
    raw_html: Optional[str | bytes] = None,
    screenshot_path: Optional[str | Path] = None,
    model_version: str = "1.0.0"
) -> Dict[str, Any]:
    """
    Builds a tamper-evident cryptographic manifest with SHA-256 verification hashes.
    """
    manifest_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    html_hash = compute_sha256(raw_html) if raw_html else None
    screenshot_hash = compute_file_sha256(screenshot_path) if screenshot_path else None
    
    # Canonical JSON serialization of evidence for hashing
    serialized_evidence = json.dumps(evidence_summary, sort_keys=True)
    evidence_hash = hashlib.sha256(serialized_evidence.encode("utf-8")).hexdigest()

    manifest_payload = {
        "manifest_version": "1.0.0",
        "manifest_id": manifest_id,
        "job_id": job_id,
        "created_at_utc": timestamp,
        "subject": {
            "target_url": url,
            "decision": decision,
            "probability": round(probability, 4),
            "confidence": round(confidence, 4),
            "modalities_consulted": modalities_consulted
        },
        "cryptographic_hashes": {
            "html_dom_sha256": html_hash,
            "screenshot_sha256": screenshot_hash,
            "evidence_features_sha256": evidence_hash,
            "model_version": model_version
        },
        "chain_of_custody": {
            "audit_agency": "PhishGuard Digital Forensics",
            "integrity_standard": "NIST SP 800-86 Guide to Integrating Forensic Techniques",
            "tamper_evident": True
        }
    }

    # Generate HMAC integrity signature over manifest data
    signing_bytes = json.dumps(manifest_payload, sort_keys=True).encode("utf-8")
    signature = hmac.new(_DEFAULT_SIGNING_KEY, signing_bytes, hashlib.sha256).hexdigest()
    manifest_payload["cryptographic_hashes"]["manifest_hmac_signature"] = signature

    return manifest_payload
