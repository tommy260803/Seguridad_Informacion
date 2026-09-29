"""
OASIS STIX 2.1 Threat Intelligence Exporter for PhishGuard.
Converts phishing detections and evidence into standardized STIX 2.1 bundles for SIEM/SOAR/MISP ingestion.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

def export_to_stix21(
    job_id: str,
    url: str,
    decision: str,
    probability: float,
    confidence: float,
    brand_name: Optional[str] = None,
    modalities_consulted: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Transforms a PhishGuard analysis result into an OASIS STIX 2.1 Bundle JSON.
    """
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle_id = f"bundle--{uuid.uuid4()}"
    indicator_id = f"indicator--{uuid.uuid4()}"
    observed_id = f"observed-data--{uuid.uuid4()}"
    attack_pattern_id = "attack-pattern--8f0a5e88-855a-4938-9045-97d022fb6929" # MITRE T1566.002 Spearphishing Link

    is_phish = decision == "phishing" or probability >= 0.5
    confidence_int = int(round(confidence * 100))

    # STIX Indicator Object
    indicator_obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"Malicious Phishing URL: {url}",
        "description": f"PhishGuard automated detection. Probability: {probability:.2%}, Decision: {decision}",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[url:value = '{url}']",
        "pattern_type": "stix",
        "valid_from": now_iso,
        "confidence": confidence_int,
        "labels": ["phishing", "credential-harvesting"] if is_phish else ["benign"]
    }

    # STIX Observed-Data Object
    observed_obj = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": observed_id,
        "created": now_iso,
        "modified": now_iso,
        "first_observed": now_iso,
        "last_observed": now_iso,
        "number_observed": 1,
        "object_refs": [indicator_id]
    }

    # MITRE ATT&CK Attack Pattern
    attack_pattern_obj = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": attack_pattern_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "Spearphishing Link",
        "description": "Adversaries may send spearphishing messages with a malicious link to harvest credentials.",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1566.002",
                "url": "https://attack.mitre.org/techniques/T1566/002/"
            }
        ]
    }

    objects = [indicator_obj, observed_obj, attack_pattern_obj]

    # Target Identity Object if brand was impersonated
    if brand_name:
        identity_id = f"identity--{uuid.uuid4()}"
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": brand_name.capitalize(),
            "identity_class": "organization",
            "sectors": ["financial-services", "technology"],
            "description": f"Target organization impersonated by phishing campaign: {brand_name}"
        }
        objects.append(identity_obj)

        # Relationship connecting indicator to target identity
        rel_obj = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "targets",
            "source_ref": indicator_id,
            "target_ref": identity_id
        }
        objects.append(rel_obj)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
