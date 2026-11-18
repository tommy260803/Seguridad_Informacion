"""Pytest validation suite for Phase 4: Performance Benchmarking and Reproducibility.

Verifies:
  1. Existence and non-emptiness of all mandatory deliverables.
  2. Integrity and schema of hardware_environment.json.
  3. Strict separation of Level A, Level B, and Level C metrics in latency_by_component.csv.
  4. Monotonicity of latency percentiles (P50 <= P90 <= P95 <= P99).
  5. Mathematical validity of the relative time savings formula.
  6. Statistical significance and valid p-values in performance_statistical_tests.csv.
  7. Integrity and dimension of the 5 publication figures.
  8. Resource usage and peak memory sanity checks.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
import pytest

DIR_PATH = Path(__file__).resolve().parent

MANDATORY_DELIVERABLES = [
    "BENCHMARK_PROTOCOL.md",
    "hardware_environment.json",
    "benchmark_raw_runs.csv",
    "latency_by_component.csv",
    "resource_usage.csv",
    "performance_comparison.csv",
    "latency_summary.csv",
    "performance_statistical_tests.csv",
    "fig_latency_by_policy.png",
    "fig_cumulative_cost_by_modality.png",
    "fig_f1_vs_latency_pareto.png",
    "fig_latency_distribution.png",
    "fig_savings_by_case_complexity.png",
    "run_performance_benchmark.py",
    "test_performance_consistency.py",
    "RESULTADOS_VERIFICADOS.md",
    "LIMITACIONES.md",
]


def test_mandatory_deliverables_exist():
    for fname in MANDATORY_DELIVERABLES:
        fpath = DIR_PATH / fname
        assert fpath.exists(), f"Missing mandatory deliverable: {fname}"
        assert fpath.stat().st_size > 0, f"Deliverable is empty: {fname}"


def test_hardware_environment_metadata():
    hw_path = DIR_PATH / "hardware_environment.json"
    data = json.loads(hw_path.read_text(encoding="utf-8"))
    assert "hardware" in data
    assert "cpu_model" in data["hardware"]
    assert "ram_total_gb" in data["hardware"]
    assert data["hardware"]["ram_total_gb"] > 0
    assert "packages" in data
    assert "scikit-learn" in data["packages"]
    assert "fastapi" in data["packages"]
    assert "python_version" in data


def test_performance_comparison_metrics_validity():
    csv_path = DIR_PATH / "performance_comparison.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 7, f"Expected at least 7 comparators, found {len(reader)}"

    m3_row = next(r for r in reader if "M3" in r["model_policy"])
    m3_mean = float(m3_row["latency_mean_ms"])

    for r in reader:
        # Probabilities & classification metrics
        for metric in ["accuracy", "precision", "recall", "f1_score", "fpr"]:
            val = float(r[metric])
            assert 0.0 <= val <= 1.0, f"Invalid {metric} {val} in {r['model_policy']}"

        # Latencies
        p50 = float(r["latency_p50_median_ms"])
        p90 = float(r["latency_p90_ms"])
        p95 = float(r["latency_p95_ms"])
        p99 = float(r["latency_p99_ms"])
        assert p50 <= p90 <= p95 <= p99, f"Non-monotonic percentiles in {r['model_policy']}: {p50}, {p90}, {p95}, {p99}"

        # Savings formula validation vs M3
        # Formula: 100 * (m3_mean - mean) / m3_mean
        cur_mean = float(r["latency_mean_ms"])
        expected_savings = round((m3_mean - cur_mean) / m3_mean * 100.0, 2)
        actual_savings = float(r["time_savings_vs_m3_pct"])
        assert abs(actual_savings - expected_savings) <= 0.1, (
            f"Savings formula mismatch in {r['model_policy']}: expected {expected_savings}, got {actual_savings}"
        )


def test_level_separation_in_component_latency():
    csv_path = DIR_PATH / "latency_by_component.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    levels = {r["level"] for r in reader}
    assert "Level_A" in levels, "Missing Level A (Algorithmic)"
    assert "Level_B" in levels, "Missing Level B (Acquisition/Network)"
    assert "Level_C" in levels, "Missing Level C (Operational/API)"

    # Verify Level A latencies are CPU scale (e.g. inference < 50ms)
    for r in reader:
        if r["level"] == "Level_A" and "inference" in r["component"]:
            p50 = float(r["p50"])
            assert p50 < 100.0, f"Level A CPU inference excessive: {r['component']} p50={p50}ms"

        # Verify Level B network latencies are higher
        if r["component"] == "M1_total_network_io":
            p50 = float(r["p50"])
            assert p50 > 100.0, f"Expected network I/O to be > 100ms, got {p50}ms"


def test_statistical_tests_consistency():
    csv_path = DIR_PATH / "performance_statistical_tests.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 6

    for r in reader:
        p_val = float(r["p_value"])
        assert 0.0 <= p_val <= 1.0, f"Invalid p-value: {p_val}"
        assert int(r["n_paired"]) == 83, f"Expected 83 paired samples, got {r['n_paired']}"
        assert r["test_type"] == "Wilcoxon_signed_rank_paired"

    # Cascada Original vs M3_pure must be statistically significant
    casc_vs_m3 = next(r for r in reader if r["policy_1"] == "Cascada_Original" and r["policy_2"] == "M3_pure")
    assert float(casc_vs_m3["p_value"]) < 0.01
    assert float(casc_vs_m3["mean_difference_ms"]) < 0, "Cascade should have negative latency difference vs M3"


def test_resource_usage_consistency():
    csv_path = DIR_PATH / "resource_usage.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 5
    for r in reader:
        peak_kb = float(r["peak_memory_kb"])
        assert peak_kb > 0, f"Peak memory must be > 0: {r['component']}"
        cpu_time = float(r["mean_cpu_time_per_sample_ms"])
        assert cpu_time > 0, f"CPU time must be > 0: {r['component']}"


def test_figures_png_integrity():
    for f in MANDATORY_DELIVERABLES:
        if f.endswith(".png"):
            png_path = DIR_PATH / f
            assert png_path.exists(), f"Figure missing: {f}"
            header = png_path.read_bytes()[:8]
            assert header == b"\x89PNG\r\n\x1a\n", f"Invalid PNG signature for {f}"
            assert png_path.stat().st_size > 20000, f"Figure {f} is suspiciously small ({png_path.stat().st_size} bytes)"
