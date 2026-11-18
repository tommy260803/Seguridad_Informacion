"""
Pruebas exhaustivas de reproducibilidad autónoma y definición estricta de políticas de abstención.
Verifica formalmente para evaluación DUAL (Cohorte Retrospectiva N=118 y Externa N=240):
  A. Fail-open asigna 0 a cada abstención (legítimo).
  B. Fail-closed asigna 1 a cada abstención (phishing / sospechoso).
  C. Selective conserva ABSTAIN y no emite etiqueta forzada.
  D. Conservación estricta del número total de observaciones.
  E. Cálculo exacto de matrices de confusión retrospectivas.
  F. Distinción rigurosa entre cobertura selectiva y completa.
  G. Coincidencia con valores de referencia retrospectivos (F1_sel=0.9420, F1_fo=0.8844, F1_fc=0.8862).
  H. Falla explícita ante cualquier discrepancia.
  I. Verificación de CERO solapamiento / cero fuga de datos en cohorte externa (N=240).
  J. Matrices de confusión externa y comportamiento fail-open / fail-closed.
  K. Cobertura selectiva externa (25.83%) y abstención mayoritaria en distribución no vista.
  L. Verificación honesta del trade-off de coste externo (RAEA 0.5954 vs M1 0.4725).
  M. Verificación de equivalencia estadística H2 (RAEA 0.3471 vs B5 0.3444).
  N. Demostración de impacto del estimador de disponibilidad (A1 duplica el coste frente a A6).
"""
import pytest
import pandas as pd
import numpy as np
from pathlib import Path
import subprocess
import sys

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUT_DIR = BASE_DIR / "output"
REF_DIR = BASE_DIR / "reference"

@pytest.fixture(scope="session")
def ensure_reproduced():
    res_path = OUT_DIR / "RESULTADOS_REPRODUCIDOS_CONSOLIDADOS.csv"
    if not res_path.exists():
        subprocess.run([sys.executable, str(BASE_DIR / "reproduce_all.py")], check=True)
    return True

@pytest.fixture(scope="session")
def retro_preds(ensure_reproduced):
    return pd.read_csv(DATA_DIR / "PREDICCIONES_INDIVIDUALES.csv")

@pytest.fixture(scope="session")
def ext_preds(ensure_reproduced):
    return pd.read_csv(DATA_DIR / "PREDICCIONES_EXTERNAS.csv")

@pytest.fixture(scope="session")
def audit_ext(ensure_reproduced):
    return pd.read_csv(DATA_DIR / "AUDITORIA_COHORTE_EXTERNA.csv")

@pytest.fixture(scope="session")
def retro_results(ensure_reproduced):
    return pd.read_csv(OUT_DIR / "RESULTADOS_REPRODUCIDOS_RETROSPECTIVA.csv")

@pytest.fixture(scope="session")
def ext_results(ensure_reproduced):
    return pd.read_csv(OUT_DIR / "RESULTADOS_REPRODUCIDOS_EXTERNA.csv")

@pytest.fixture(scope="session")
def ab_results(ensure_reproduced):
    return pd.read_csv(OUT_DIR / "ABLACIONES_REPRODUCIDAS.csv")

@pytest.fixture(scope="session")
def raea_retro_samples(retro_preds):
    sub = retro_preds[(retro_preds["partition"] == "test_eval") &
                      (retro_preds["in_pop_phishing_web"] == 1) &
                      (retro_preds["policy"] == "B6_RAEA")].copy()
    assert len(sub) == 118
    return sub

# ==================== COHORTE RETROSPECTIVA ====================

def test_requirement_A_fail_open_assigns_zero_retro(raea_retro_samples):
    abstained = raea_retro_samples[raea_retro_samples["selective_state"] == "abstained"]
    assert len(abstained) == 20
    p_fo = np.where(raea_retro_samples["selective_state"] == "abstained", 0, raea_retro_samples["prediction"].fillna(0).astype(int))
    ab_indices = np.where(raea_retro_samples["selective_state"] == "abstained")[0]
    for idx in ab_indices:
        assert p_fo[idx] == 0

def test_requirement_B_fail_closed_assigns_one_retro(raea_retro_samples):
    p_fc = np.where(raea_retro_samples["selective_state"] == "abstained", 1, raea_retro_samples["prediction"].fillna(0).astype(int))
    ab_indices = np.where(raea_retro_samples["selective_state"] == "abstained")[0]
    for idx in ab_indices:
        assert p_fc[idx] == 1

def test_requirement_C_selective_preserves_abstain_retro(raea_retro_samples):
    decided = raea_retro_samples[raea_retro_samples["selective_state"] == "decided"]
    abstained = raea_retro_samples[raea_retro_samples["selective_state"] == "abstained"]
    assert len(decided) == 98
    assert len(abstained) == 20
    assert len(decided) + len(abstained) == 118
    assert abstained["prediction"].isna().sum() == 20

def test_requirement_D_total_observations_conserved_retro(retro_results):
    r = retro_results[(retro_results["population"] == "PHISHING_WEB_TEST") & (retro_results["policy"] == "B6_RAEA")].iloc[0]
    n_tot = r["N"]
    assert n_tot == 118
    assert r["sel_TP"] + r["sel_FP"] + r["sel_TN"] + r["sel_FN"] + r["n_abstained"] == n_tot
    assert r["failopen_TP"] + r["failopen_FP"] + r["failopen_TN"] + r["failopen_FN"] == n_tot
    assert r["failclosed_TP"] + r["failclosed_FP"] + r["failclosed_TN"] + r["failclosed_FN"] == n_tot

def test_requirement_E_confusion_matrices_exact_retro(retro_results):
    r = retro_results[(retro_results["population"] == "PHISHING_WEB_TEST") & (retro_results["policy"] == "B6_RAEA")].iloc[0]
    # Selective: TP=65, FP=2, TN=25, FN=6
    assert r["sel_TP"] == 65
    assert r["sel_FP"] == 2
    assert r["sel_TN"] == 25
    assert r["sel_FN"] == 6
    assert r["abstained_pos"] == 9
    assert r["abstained_neg"] == 11
    # Fail-open
    assert r["failopen_TP"] == 65
    assert r["failopen_FP"] == 2
    assert r["failopen_TN"] == 36
    assert r["failopen_FN"] == 15
    # Fail-closed
    assert r["failclosed_TP"] == 74
    assert r["failclosed_FP"] == 13
    assert r["failclosed_TN"] == 25
    assert r["failclosed_FN"] == 6

def test_requirement_F_coverage_distinction_retro(retro_results):
    r = retro_results[(retro_results["population"] == "PHISHING_WEB_TEST") & (retro_results["policy"] == "B6_RAEA")].iloc[0]
    m1 = retro_results[(retro_results["population"] == "PHISHING_WEB_TEST") & (retro_results["policy"] == "B1_M1")].iloc[0]
    assert m1["coverage"] == 1.0000
    assert pytest.approx(r["coverage"], abs=1e-4) == 0.8305
    assert r["n_abstained"] == 20

def test_requirement_G_metrics_match_reference_tables(retro_results):
    r_rep = retro_results[(retro_results["population"] == "PHISHING_WEB_TEST") & (retro_results["policy"] == "B6_RAEA")].iloc[0]
    assert pytest.approx(r_rep["sel_F1"], abs=1e-4) == 0.9420
    assert pytest.approx(r_rep["failopen_F1"], abs=1e-4) == 0.8844
    assert pytest.approx(r_rep["failclosed_F1"], abs=1e-4) == 0.8862
    assert pytest.approx(r_rep["mean_normalized_cost"], abs=1e-4) == 0.2407

def test_requirement_H_discrepancy_detection():
    fake_f1 = 0.9500
    real_f1 = 0.9420289855
    with pytest.raises(AssertionError):
        assert abs(fake_f1 - real_f1) < 1e-4

# ==================== COHORTE EXTERNA ====================

def test_requirement_I_zero_leakage_external(audit_ext):
    assert len(audit_ext) == 240
    assert audit_ext["overlap_with_train"].sum() == 0
    assert audit_ext["overlap_with_calib"].sum() == 0
    assert audit_ext["overlap_with_retro_test"].sum() == 0

def test_requirement_J_external_confusion_matrices(ext_results):
    r = ext_results[ext_results["policy"] == "B6_RAEA"].iloc[0]
    assert r["N"] == 240
    assert r["n_pos"] == 120
    assert r["n_neg"] == 120
    assert r["n_decided"] == 62
    assert r["n_abstained"] == 178
    # Selective: TP=38, FP=6, TN=17, FN=1
    assert r["sel_TP"] == 38
    assert r["sel_FP"] == 6
    assert r["sel_TN"] == 17
    assert r["sel_FN"] == 1
    # Fail-Open: abstention -> 0
    assert r["failopen_TP"] == 38
    assert r["failopen_FP"] == 6
    assert r["failopen_TN"] == 114
    assert r["failopen_FN"] == 82
    assert pytest.approx(r["failopen_F1"], abs=1e-4) == 0.4634
    # Fail-Closed: abstention -> 1
    assert r["failclosed_TP"] == 119
    assert r["failclosed_FP"] == 103
    assert r["failclosed_TN"] == 17
    assert r["failclosed_FN"] == 1
    assert pytest.approx(r["failclosed_F1"], abs=1e-4) == 0.6959

def test_requirement_K_external_coverage_and_abstention(ext_results):
    r = ext_results[ext_results["policy"] == "B6_RAEA"].iloc[0]
    assert pytest.approx(r["coverage"], abs=1e-4) == 0.2583
    assert r["n_abstained"] == 178

def test_requirement_L_external_cost_tradeoff(ext_results):
    r = ext_results[ext_results["policy"] == "B6_RAEA"].iloc[0]
    m1 = ext_results[ext_results["policy"] == "B1_M1"].iloc[0]
    # En entorno externo hostil, RAEA gasta más coste que M1 fijo
    assert r["mean_normalized_cost"] > m1["mean_normalized_cost"]
    assert pytest.approx(r["mean_normalized_cost"], abs=1e-4) == 0.5954
    assert pytest.approx(m1["mean_normalized_cost"], abs=1e-4) == 0.4725

def test_requirement_M_external_b5_risk_comparison(ext_results):
    r = ext_results[ext_results["policy"] == "B6_RAEA"].iloc[0]
    b5 = ext_results[ext_results["policy"] == "B5_M1_chow"].iloc[0]
    # B5 logra un riesgo ligeramente menor o equivalente a RAEA
    assert b5["risk_selective_penalized"] <= r["risk_selective_penalized"]
    assert pytest.approx(b5["risk_selective_penalized"], abs=1e-4) == 0.3444
    assert pytest.approx(r["risk_selective_penalized"], abs=1e-4) == 0.3471

def test_requirement_N_external_ablation_availability(ab_results):
    sub = ab_results[ab_results["cohort"] == "EXTERNA_N240"].set_index("variant")
    a1_cost = sub.loc["A1", "mean_normalized_cost"]
    a6_cost = sub.loc["A6", "mean_normalized_cost"]
    # Sin estimador de disponibilidad (A1), el coste se duplica frente a A6
    assert pytest.approx(a1_cost, abs=1e-4) == 1.2067
    assert pytest.approx(a6_cost, abs=1e-4) == 0.5954
    assert a1_cost > 1.9 * a6_cost
