"""
Pruebas Automáticas de Consistencia y Reproducibilidad de Cascada y Salida Temprana
PhishPe / PhishGuard Pro - Revista Politécnica (Ecuador)
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PHASE2_DIR = ROOT / "paper_reproduction" / "02_early_exit"
PAIRED_PATH = PHASE2_DIR / "cascade_paired_predictions.csv"
POLICIES_CFG_PATH = PHASE2_DIR / "policies_configuration.json"
COMPARISON_PATH = PHASE2_DIR / "early_exit_comparison.csv"
SENSITIVITY_PATH = PHASE2_DIR / "threshold_sensitivity.csv"
FN_PATH = PHASE2_DIR / "false_negatives_by_stage.csv"
ABSTENTION_PATH = PHASE2_DIR / "abstention_analysis.csv"
PAIRED_TESTS_PATH = PHASE2_DIR / "paired_statistical_tests.csv"


@pytest.fixture(scope="session")
def paired_data():
    assert PAIRED_PATH.exists(), f"No existe {PAIRED_PATH}"
    with open(PAIRED_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture(scope="session")
def comparison_data():
    assert COMPARISON_PATH.exists(), f"No existe {COMPARISON_PATH}"
    with open(COMPARISON_PATH, encoding="utf-8") as f:
        return {r["policy"]: r for r in csv.DictReader(f)}


@pytest.fixture(scope="session")
def fn_data():
    assert FN_PATH.exists(), f"No existe {FN_PATH}"
    with open(FN_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture(scope="session")
def paired_tests_data():
    assert PAIRED_TESTS_PATH.exists(), f"No existe {PAIRED_TESTS_PATH}"
    with open(PAIRED_TESTS_PATH, encoding="utf-8") as f:
        return {r["comparison"]: r for r in csv.DictReader(f)}


def test_paired_predictions_integrity(paired_data):
    """Verifica que el dataset pareado contenga exactamente 691 muestras con identificadores únicos y consistentes."""
    assert len(paired_data) == 691
    sids = [r["sample_id"] for r in paired_data]
    assert len(sids) == len(set(sids)), "Los sample_id deben ser únicos"
    
    # Comprobar que todas las probabilidades estén acotadas en [0, 1]
    for r in paired_data:
        assert 0.0 <= float(r["p_m0"]) <= 1.0
        assert 0.0 <= float(r["p_m1"]) <= 1.0
        assert 0.0 <= float(r["p_m2"]) <= 1.0
        assert 0.0 <= float(r["p_m3"]) <= 1.0
        assert r["label"] in ("0", "1")


def test_policy_a_reference(comparison_data):
    """Verifica que la Política A ejecute el modelo completo M2 sin salidas tempranas."""
    p_a = comparison_data["Politica_A_M2_Completo"]
    assert int(p_a["n_evaluated"]) == 691
    assert float(p_a["avg_modalities"]) == 3.0
    assert float(p_a["html_acquisitions_saved_pct"]) == 0.0
    assert float(p_a["f1"]) >= 0.9300


def test_policy_b_historical_reproducibility(comparison_data, fn_data):
    """Verifica la reproducción exacta de las cifras históricas de la cascada M0->M1->M2."""
    p_b = comparison_data["Politica_B_Cascada_Historica"]
    assert int(p_b["n_evaluated"]) == 691
    # F1 = 0.9222
    assert abs(float(p_b["f1"]) - 0.9222) <= 0.0005
    # 25 Falsos Negativos totales
    assert int(p_b["fn"]) == 25
    # Ahorro de HTML: 75.83% (524 / 691)
    saved_count = round(float(p_b["html_acquisitions_saved_pct"]) * 691 / 100.0)
    assert saved_count == 524
    
    # 13 FN ocurrieron antes de M2 (12 en M0 y 1 en M1)
    fn_m0 = sum(1 for r in fn_data if r["stopping_stage_in_policy_b"] == "M0")
    fn_m1 = sum(1 for r in fn_data if r["stopping_stage_in_policy_b"] == "M1")
    assert fn_m0 == 12
    assert fn_m1 == 1
    assert fn_m0 + fn_m1 == 13


def test_policy_c_conservative_improvement(comparison_data):
    """Verifica que la Política C recupere Falsos Negativos y mejore F1 manteniendo alto ahorro de HTML."""
    p_c = comparison_data["Politica_C_Cascada_Conservadora"]
    p_b = comparison_data["Politica_B_Cascada_Historica"]
    
    # F1 mejora respecto a B
    assert float(p_c["f1"]) > float(p_b["f1"])
    assert float(p_c["f1"]) >= 0.9300
    # FN se reduce de 25 a 22 (recupera 3 FN tempranos)
    assert int(p_c["fn"]) == 22
    assert int(p_c["fn"]) < int(p_b["fn"])
    # Conserva más del 65% de ahorro en adquisiciones HTML
    assert float(p_c["html_acquisitions_saved_pct"]) >= 65.0


def test_policy_d_selective_classification(comparison_data):
    """Verifica que la clasificación selectiva (Política D) alcance precisión perfecta sobre el subconjunto decidido."""
    p_d_dec = comparison_data["Politica_D_Selectiva_Decididos"]
    assert float(p_d_dec["coverage"]) >= 0.9500
    assert float(p_d_dec["precision"]) == 1.0000
    assert int(p_d_dec["fp"]) == 0
    assert float(p_d_dec["f1"]) >= 0.9400


def test_policy_e_targeted_rescue(comparison_data):
    """Verifica que la Política E iguale el F1 de la Política C ejecutando menos modalidades promedio."""
    p_e = comparison_data["Politica_E_Rescate_Focalizado"]
    p_c = comparison_data["Politica_C_Cascada_Conservadora"]
    
    assert float(p_e["f1"]) == float(p_c["f1"])
    assert int(p_e["fn"]) == int(p_c["fn"])
    # Ejecuta menos modalidades promedio que C
    assert float(p_e["avg_modalities"]) < float(p_c["avg_modalities"])
    assert float(p_e["html_acquisitions_saved_pct"]) > float(p_c["html_acquisitions_saved_pct"])


def test_mcnemar_statistical_consistency(paired_tests_data):
    """Verifica la consistencia matemática de las pruebas de McNemar."""
    for comp_name, row in paired_tests_data.items():
        n = int(row["n"])
        n11 = int(row["n11_both_correct"])
        n00 = int(row["n00_both_wrong"])
        n10 = int(row["n10_ref_correct_cand_wrong"])
        n01 = int(row["n01_ref_wrong_cand_correct"])
        assert n11 + n00 + n10 + n01 == n == 691
        p_val = float(row["mcnemar_p_value"])
        assert 0.0 <= p_val <= 1.0


def test_non_inferiority_verification(paired_tests_data):
    """Verifica que la no inferioridad de la Política C frente a la Política A esté confirmada."""
    c_vs_a = paired_tests_data["Politica_C_vs_Politica_A"]
    assert c_vs_a["non_inferior_decision"] == "NO_INFERIOR_CONFIRMADO"
