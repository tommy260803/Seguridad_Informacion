from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np


INFRA_FEATURE_VERSION = "infra-features-1.0.0"

INFRA_FEATURE_NAMES = (
    "infra_observation_available",
    "infra_status_success",
    "infra_status_blocked",
    "infra_status_error",
    "infra_dns_address_count_initial",
    "infra_dns_ipv4_count_initial",
    "infra_dns_ipv6_count_initial",
    "infra_redirect_count",
    "infra_redirect_host_change_count",
    "infra_redirect_registered_domain_change_count",
    "infra_tls_hop_count",
    "infra_tls_verification_failure_count",
    "infra_tls_max_chain_length",
    "infra_certificate_available",
    "infra_final_status_code",
    "infra_final_uses_https",
    "infra_total_dns_ms",
    "infra_total_request_ms",
)


class InfrastructureFeatureError(ValueError):
    """Raised when infrastructure evidence cannot be mapped safely."""


def _zero_features() -> dict[str, float]:
    return {name: 0.0 for name in INFRA_FEATURE_NAMES}


def extract_infrastructure_features(result: dict[str, Any] | None) -> dict[str, float]:
    """Map one analyzer result to a fixed, status-aware numeric vector.

    Missing or failed acquisition keeps an explicit availability/status signal;
    all measured values remain zero and are never interpreted as successful zeros.
    """
    features = _zero_features()
    if result is None:
        return features
    status = result.get("status")
    if status not in {"success", "blocked", "error"}:
        raise InfrastructureFeatureError(f"Unsupported infrastructure status: {status!r}")
    features[f"infra_status_{status}"] = 1.0
    features["infra_observation_available"] = float(status == "success")
    raw_features = result.get("features")
    if not isinstance(raw_features, dict):
        if status == "success":
            raise InfrastructureFeatureError("Successful result is missing features")
        return features
    for source_name, target_name in (
        ("dns_address_count_initial", "infra_dns_address_count_initial"),
        ("dns_ipv4_count_initial", "infra_dns_ipv4_count_initial"),
        ("dns_ipv6_count_initial", "infra_dns_ipv6_count_initial"),
        ("redirect_count", "infra_redirect_count"),
        ("redirect_host_change_count", "infra_redirect_host_change_count"),
        (
            "redirect_registered_domain_change_count",
            "infra_redirect_registered_domain_change_count",
        ),
        ("tls_hop_count", "infra_tls_hop_count"),
        ("tls_verification_failure_count", "infra_tls_verification_failure_count"),
        ("tls_max_chain_length", "infra_tls_max_chain_length"),
        ("certificate_available", "infra_certificate_available"),
        ("final_status_code", "infra_final_status_code"),
        ("final_uses_https", "infra_final_uses_https"),
        ("total_dns_ms", "infra_total_dns_ms"),
        ("total_request_ms", "infra_total_request_ms"),
    ):
        value = raw_features.get(source_name)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InfrastructureFeatureError(f"Feature {source_name} is not numeric")
        if not np.isfinite(value):
            raise InfrastructureFeatureError(f"Feature {source_name} is not finite")
        features[target_name] = float(value)
    return features


def load_infrastructure_results(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load JSONL evidence keyed by sample_id, rejecting duplicates and malformed rows."""
    source_path = Path(path)
    results: dict[str, dict[str, Any]] = {}
    try:
        lines = source_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise InfrastructureFeatureError(f"Cannot read infrastructure results: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
            sample_id = row["sample_id"]
            result = row["result"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise InfrastructureFeatureError(f"Invalid infrastructure result line {line_number}") from exc
        if not isinstance(sample_id, str) or not sample_id:
            raise InfrastructureFeatureError(f"Invalid sample_id at line {line_number}")
        if sample_id in results:
            raise InfrastructureFeatureError(f"Duplicate infrastructure result: {sample_id}")
        if not isinstance(result, dict):
            raise InfrastructureFeatureError(f"Result at line {line_number} is not an object")
        # Validate before exposing the row to downstream model code.
        extract_infrastructure_features(result)
        results[sample_id] = result
    return results


def infrastructure_feature_matrix(
    sample_ids: list[str], results_path: str | Path | None
) -> np.ndarray:
    results = load_infrastructure_results(results_path) if results_path else {}
    matrix = np.asarray(
        [
            [
                extract_infrastructure_features(results.get(sample_id))[name]
                for name in INFRA_FEATURE_NAMES
            ]
            for sample_id in sample_ids
        ],
        dtype=np.float64,
    )
    if matrix.shape != (len(sample_ids), len(INFRA_FEATURE_NAMES)) or not np.isfinite(matrix).all():
        raise InfrastructureFeatureError("Infrastructure feature matrix is invalid")
    return matrix
