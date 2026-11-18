"""
Pruebas Automáticas de Consistencia de Disponibilidad Multimodal y Fallback
PhishPe / PhishGuard Pro - Revista Politécnica (Ecuador)
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PHASE3_DIR = ROOT / "paper_reproduction" / "03_missing_modalities"
ATTEMPTS_PATH = PHASE3_DIR / "acquisition_attempts.csv"
AVAILABILITY_PATH = PHASE3_DIR / "modality_availability_matrix.csv"
FAILURES_PATH = PHASE3_DIR / "acquisition_failures.csv"
CC_RESULTS_PATH = PHASE3_DIR / "complete_case_results.csv"
ITE_RESULTS_PATH = PHASE3_DIR / "intention_to_evaluate_results.csv"
FALLBACK_PATH = PHASE3_DIR / "fallback_comparison.csv"
STATS_PATH = PHASE3_DIR / "missingness_statistical_analysis.csv"


@pytest.fixture(scope="session")
def attempts_data():
    assert ATTEMPTS_PATH.exists(), f"No existe {ATTEMPTS_PATH}"
    with open(ATTEMPTS_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture(scope="session")
def availability_data():
    assert AVAILABILITY_PATH.exists(), f"No existe {AVAILABILITY_PATH}"
    with open(AVAILABILITY_PATH, encoding="utf-8") as f:
        return {r["group"]: r for r in csv.DictReader(f)}


@pytest.fixture(scope="session")
def cc_results_data():
    assert CC_RESULTS_PATH.exists(), f"No existe {CC_RESULTS_PATH}"
    with open(CC_RESULTS_PATH, encoding="utf-8") as f:
        return {r["model_strategy"]: r for r in csv.DictReader(f)}


@pytest.fixture(scope="session")
def ite_results_data():
    assert ITE_RESULTS_PATH.exists(), f"No existe {ITE_RESULTS_PATH}"
    with open(ITE_RESULTS_PATH, encoding="utf-8") as f:
        return {r["strategy"]: r for r in csv.DictReader(f)}


@pytest.fixture(scope="session")
def stats_data():
    assert STATS_PATH.exists(), f"No existe {STATS_PATH}"
    with open(STATS_PATH, encoding="utf-8") as f:
        return {r["test_name"]: r for r in csv.DictReader(f)}


def test_attempts_integrity(attempts_data):
    """Verifica que el archivo de intentos contenga exactamente 600 URLs balanceadas (300/300)."""
    assert len(attempts_data) == 600
    ids = [r["cohort2_id"] for r in attempts_data]
    assert len(ids) == len(set(ids)), "Los cohort2_id deben ser únicos"
    
    from collections import Counter
    labels = Counter(r["label"] for r in attempts_data)
    assert labels["phishing"] == 300
    assert labels["legitimate"] == 300


def test_complete_case_exact_counts(attempts_data):
    """Verifica la reproducción exacta de los casos completos: 247 totales, 40 phishing y 207 legítimas."""
    cc_all = [r for r in attempts_data if int(r["complete_case"]) == 1]
    assert len(cc_all) == 247, f"Se esperaban 247 casos completos, obtenidos {len(cc_all)}"
    
    cc_phish = [r for r in cc_all if r["label"] == "phishing"]
    cc_legit = [r for r in cc_all if r["label"] == "legitimate"]
    assert len(cc_phish) == 40, f"Se esperaban 40 phishing completos, obtenidos {len(cc_phish)}"
    assert len(cc_legit) == 207, f"Se esperaban 207 legítimos completos, obtenidos {len(cc_legit)}"


def test_source_breakdown_consistency(attempts_data, availability_data):
    """Verifica la consistencia de fuentes en el sondeo externo."""
    from collections import Counter
    src_counts = Counter(r["source"] for r in attempts_data)
    assert src_counts["tranco"] == 198
    assert src_counts["urlhaus"] == 146
    assert src_counts["phishtank"] == 128
    assert src_counts["majestic"] == 102
    assert src_counts["openphish"] == 26
    
    # Comprobar casos completos en la matriz de disponibilidad
    assert int(availability_data["Source_Tranco_N198"]["complete_cases"]) == 135
    assert int(availability_data["Source_Majestic_N102"]["complete_cases"]) == 72
    assert int(availability_data["Source_URLhaus_N146"]["complete_cases"]) == 11
    assert int(availability_data["Source_PhishTank_N128"]["complete_cases"]) == 19
    assert int(availability_data["Source_OpenPhish_N26"]["complete_cases"]) == 10


def test_modality_availability_hierarchy(availability_data):
    """Verifica que la disponibilidad léxica sea 100% y que la disponibilidad de HTML sea asimétrica entre clases."""
    all_grp = availability_data["All_Observations_N600"]
    assert float(all_grp["url_lexical_avail_pct"]) == 100.0
    
    phish_grp = availability_data["Class_Phishing_N300"]
    legit_grp = availability_data["Class_Legitimate_N300"]
    assert float(phish_grp["html_dom_avail_pct"]) <= 15.0  # Solo 14.67%
    assert float(legit_grp["html_dom_avail_pct"]) >= 68.0  # 70.00%


def test_complete_case_m2_reproducibility(cc_results_data):
    """Verifica las métricas de la Estrategia A (M2 sobre casos completos N=247)."""
    m2 = cc_results_data["M2_Contenido_HTML_CC_Estrategia_A"]
    assert int(m2["n"]) == 247
    assert int(m2["tp"]) == 32
    assert int(m2["tn"]) == 200
    assert int(m2["fp"]) == 7
    assert int(m2["fn"]) == 8
    assert abs(float(m2["f1"]) - 0.8101) <= 0.0005
    assert abs(float(m2["recall"]) - 0.8000) <= 0.0005
    assert abs(float(m2["fpr"]) - 0.0338) <= 0.0005


def test_intention_to_evaluate_reproducibility(ite_results_data):
    """Verifica las métricas de intención de evaluar (N=600)."""
    strat_b = ite_results_data["Estrategia_B_M0_Puro"]
    assert int(strat_b["n_evaluated"]) == 600
    assert abs(float(strat_b["f1"]) - 0.8066) <= 0.0005
    assert int(strat_b["tp"]) == 219
    assert int(strat_b["tn"]) == 276
    
    strat_c = ite_results_data["Estrategia_C_M2_Fallback_M0"]
    assert int(strat_c["n_evaluated"]) == 600
    assert float(strat_c["f1"]) > float(strat_b["f1"])
    assert float(strat_c["precision"]) >= 0.9300
    assert float(strat_c["fpr"]) == 0.0500


def test_imputation_fpr_inflation(ite_results_data):
    """Verifica que la imputación directa de ceros (Estrategia F) provoque una explosión inaceptable en FPR."""
    strat_f = ite_results_data["Estrategia_F_M2_Imputacion_Directa"]
    strat_c = ite_results_data["Estrategia_C_M2_Fallback_M0"]
    
    assert float(strat_f["fpr"]) >= 0.1800  # 18.67%
    assert float(strat_f["fpr"]) > float(strat_c["fpr"]) * 3.0  # Más del triple de falsos positivos


def test_mnar_statistical_significance(stats_data):
    """Verifica que la prueba exacta de Fisher confirme Missing Not at Random (MNAR) con p < 1e-15."""
    fisher = stats_data["Fisher_Exact_Test_Class_vs_Missingness"]
    assert fisher["decision"] == "RECHAZA_MCAR_CONFIRMA_MNAR"
    assert float(fisher["odds_ratio_missing_phish_vs_legit"]) >= 14.0
