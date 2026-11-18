"""Pytest test suite for Phase 5: Statistical Comparison, Ablation Studies, and Inferential Statistics.

Verifies:
  1. Mandatory deliverable files exist and are non-empty.
  2. Baselines A through F have valid classification metrics within [0, 1].
  3. Ablation studies quantify single-factor perturbations consistently.
  4. Inferential statistics: McNemar p-values, bootstrap CIs, and Benjamini-Hochberg FDR adjustments.
  5. Formal non-inferiority test for Cascada Asimétrica against M2 Monolítico (delta = 0.02).
  6. Calibration analysis: ECE, MCE, and Brier score ranges and ordering.
  7. High-resolution publication figures exist with valid PNG signatures.
"""
from __future__ import annotations

import csv
from pathlib import Path
import pytest

DIR_PATH = Path(__file__).resolve().parent

MANDATORY_DELIVERABLES = [
    "EXPERIMENTAL_DESIGN.md",
    "BASELINE_DEFINITIONS.md",
    "baseline_comparison.csv",
    "ablation_study.csv",
    "paired_statistics.csv",
    "bootstrap_confidence_intervals.csv",
    "calibration_analysis.csv",
    "sensitivity_analysis.csv",
    "SCIENTIFIC_FINDINGS.md",
    "METODOLOGIA_EXPERIMENTO.md",
    "RESULTADOS_VERIFICADOS.md",
    "LIMITACIONES.md",
    "fig_baseline_f1_vs_cost.png",
    "fig_ablation_tornado_chart.png",
    "fig_calibration_curves.png",
    "fig_bootstrap_diff_distributions.png",
    "fig_non_inferiority_forest_plot.png",
    "run_statistical_comparison.py",
    "test_statistical_comparison_consistency.py",
]


def test_mandatory_deliverables_exist():
    for fname in MANDATORY_DELIVERABLES:
        fpath = DIR_PATH / fname
        assert fpath.exists(), f"Missing deliverable: {fname}"
        assert fpath.stat().st_size > 0, f"Empty deliverable: {fname}"


def test_baseline_comparison_metrics_validity():
    csv_path = DIR_PATH / "baseline_comparison.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 6, f"Expected at least 6 baselines, found {len(reader)}"

    for r in reader:
        for metric in ["accuracy", "precision", "recall", "f1_score", "fpr", "fnr"]:
            val = float(r[metric])
            assert 0.0 <= val <= 1.0, f"Invalid {metric} {val} in {r['baseline_id']}"

        cov = float(r["coverage_pct"])
        assert 0.0 < cov <= 100.0, f"Invalid coverage {cov} in {r['baseline_id']}"

        ci_low = float(r["f1_ci95_low"])
        ci_high = float(r["f1_ci95_high"])
        f1 = float(r["f1_score"])
        assert ci_low <= f1 <= ci_high, f"F1 {f1} out of CI [{ci_low}, {ci_high}] in {r['baseline_id']}"


def test_ablation_study_consistency():
    csv_path = DIR_PATH / "ablation_study.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 6, f"Expected at least 6 ablations, found {len(reader)}"

    abl_ids = {r["ablation_id"] for r in reader}
    for expected_id in ["ABL-01", "ABL-02", "ABL-03A", "ABL-03B", "ABL-04", "ABL-05A", "ABL-05B", "ABL-06"]:
        assert expected_id in abl_ids, f"Missing ablation {expected_id}"

    for r in reader:
        delta_f1 = float(r["delta_f1"])
        f1_ref = float(r["f1_reference"])
        f1_abl = float(r["f1_ablated"])
        assert abs(delta_f1 - round(f1_abl - f1_ref, 4)) <= 0.001, (
            f"Delta F1 mismatch in {r['ablation_id']}: expected {round(f1_abl - f1_ref, 4)}, got {delta_f1}"
        )


def test_paired_statistics_and_non_inferiority():
    csv_path = DIR_PATH / "paired_statistics.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 6

    # Test M1 vs M0 is highly significant
    m1_vs_m0 = next(r for r in reader if r["comparison"] == "M1_Infra vs M0_Léxico")
    assert float(m1_vs_m0["mcnemar_p_value_raw"]) < 0.001
    assert float(m1_vs_m0["mean_delta_f1"]) > 0.05
    assert m1_vs_m0["significant_fdr_0_05"] == "True"

    # Test Cascada Asimetrica Non-Inferiority vs M2 Completo
    casc_asim_vs_m2 = next(r for r in reader if r["comparison"] == "Cascada_Asimétrica vs M2_Completo")
    assert casc_asim_vs_m2["non_inferior_established"] == "True"
    assert float(casc_asim_vs_m2["ci975_onesided_low"]) > -0.02


def test_calibration_metrics():
    csv_path = DIR_PATH / "calibration_analysis.csv"
    with open(csv_path, encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) == 4
    for r in reader:
        ece = float(r["expected_calibration_error_ece"])
        mce = float(r["maximum_calibration_error_mce"])
        brier = float(r["brier_score"])
        assert 0.0 <= ece <= 1.0
        assert 0.0 <= mce <= 1.0
        assert 0.0 <= brier <= 1.0
        assert ece <= mce, f"ECE {ece} cannot exceed MCE {mce} in {r['model_tier']}"

    # M1 and M2 must be well-calibrated (ECE < 0.05)
    m1_row = next(r for r in reader if r["model_tier"] == "M1_Infrastructure")
    assert float(m1_row["expected_calibration_error_ece"]) < 0.05
    m2_row = next(r for r in reader if r["model_tier"] == "M2_Content_DOM")
    assert float(m2_row["expected_calibration_error_ece"]) < 0.05


def test_figures_png_validity():
    for f in MANDATORY_DELIVERABLES:
        if f.endswith(".png"):
            fpath = DIR_PATH / f
            assert fpath.exists(), f"Missing figure: {f}"
            header = fpath.read_bytes()[:8]
            assert header == b"\x89PNG\r\n\x1a\n", f"Invalid PNG signature for {f}"
            assert fpath.stat().st_size > 20000, f"Figure too small: {f}"
