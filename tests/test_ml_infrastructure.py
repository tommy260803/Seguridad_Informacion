import json
from pathlib import Path

import numpy as np
import pytest

from phishguard_ml.infrastructure import (
    INFRA_FEATURE_NAMES,
    InfrastructureFeatureError,
    extract_infrastructure_features,
    infrastructure_feature_matrix,
    load_infrastructure_results,
)


def successful_result() -> dict[str, object]:
    return {
        "status": "success",
        "features": {
            "dns_address_count_initial": 2,
            "dns_ipv4_count_initial": 1,
            "dns_ipv6_count_initial": 1,
            "redirect_count": 1,
            "redirect_host_change_count": 1,
            "redirect_registered_domain_change_count": 1,
            "tls_hop_count": 1,
            "tls_verification_failure_count": 0,
            "tls_max_chain_length": 3,
            "certificate_available": 1,
            "final_status_code": 200,
            "final_uses_https": 1,
            "total_dns_ms": 12.5,
            "total_request_ms": 44.0,
        },
    }


def test_successful_result_maps_to_fixed_numeric_registry() -> None:
    features = extract_infrastructure_features(successful_result())

    assert tuple(features) == INFRA_FEATURE_NAMES
    assert features["infra_observation_available"] == 1.0
    assert features["infra_status_success"] == 1.0
    assert features["infra_redirect_registered_domain_change_count"] == 1.0
    assert all(np.isfinite(value) for value in features.values())


@pytest.mark.parametrize("status", ["blocked", "error"])
def test_failed_result_preserves_status_without_claiming_availability(status: str) -> None:
    features = extract_infrastructure_features({"status": status, "features": {}})

    assert features["infra_observation_available"] == 0.0
    assert features[f"infra_status_{status}"] == 1.0
    assert features["infra_final_status_code"] == 0.0


def test_missing_result_is_distinct_from_successful_zeroes() -> None:
    features = extract_infrastructure_features(None)

    assert features["infra_observation_available"] == 0.0
    assert features["infra_status_success"] == 0.0
    assert features["infra_status_error"] == 0.0


def test_results_loader_rejects_duplicate_sample_ids(tmp_path: Path) -> None:
    path = tmp_path / "results.jsonl"
    row = {"sample_id": "same", "result": successful_result()}
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(InfrastructureFeatureError, match="Duplicate"):
        load_infrastructure_results(path)


def test_matrix_keeps_missing_rows_explicit_and_ordered(tmp_path: Path) -> None:
    path = tmp_path / "results.jsonl"
    path.write_text(
        json.dumps({"sample_id": "b", "result": successful_result()}) + "\n",
        encoding="utf-8",
    )

    matrix = infrastructure_feature_matrix(["a", "b"], path)

    assert matrix.shape == (2, len(INFRA_FEATURE_NAMES))
    assert matrix[0, 0] == 0.0
    assert matrix[1, 0] == 1.0
    assert matrix[1, INFRA_FEATURE_NAMES.index("infra_tls_max_chain_length")] == 3.0
