"""
Pruebas de consistencia de la evaluacion prospectiva sobre la cohorte independiente N=240.
"""
import pytest
import pandas as pd
import numpy as np
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "artifacts" / "raea_independent_n240"

@pytest.fixture(scope="session")
def manifest_df():
    p = OUT_DIR / "COHORTE_INDEPENDIENTE_N240_MANIFIESTO.csv"
    assert p.exists(), "El manifiesto de la cohorte N=240 no existe"
    return pd.read_csv(p)

@pytest.fixture(scope="session")
def results_df():
    p = OUT_DIR / "RESULTADOS_INDEPENDIENTES_N240.csv"
    assert p.exists(), "La tabla de resultados N=240 no existe"
    return pd.read_csv(p)

@pytest.fixture(scope="session")
def ablations_df():
    p = OUT_DIR / "ABLACIONES_INDEPENDIENTES_N240.csv"
    assert p.exists(), "La tabla de ablaciones N=240 no existe"
    return pd.read_csv(p)

@pytest.fixture(scope="session")
def stats_df():
    p = OUT_DIR / "ESTADISTICA_INDEPENDIENTE_N240.csv"
    assert p.exists(), "La tabla estadistica N=240 no existe"
    return pd.read_csv(p)

def test_n240_manifest_balance_and_disjointness(manifest_df):
    assert len(manifest_df) == 240
    assert (manifest_df["label_int"] == 1).sum() == 120
    assert (manifest_df["label_int"] == 0).sum() == 120
    
    # 240 dominios disjuntos
    assert manifest_df["registered_domain"].nunique() == 240
    
    # 0 solapamiento con train
    train_df = pd.read_csv(ROOT / "data" / "processed" / "0.1.0" / "samples.csv")
    train_doms = set(train_df["registered_domain"].dropna().str.lower())
    n240_doms = set(manifest_df["registered_domain"].dropna().str.lower())
    assert len(n240_doms.intersection(train_doms)) == 0

def test_n240_raea_selective_f1(results_df):
    raea = results_df[results_df["policy"] == "B6_RAEA"].iloc[0]
    # TP=38, FP=6, FN=1 -> F1 = 76 / 83 = 0.915663
    assert raea["sel_TP"] == 38
    assert raea["sel_FP"] == 6
    assert raea["sel_FN"] == 1
    assert pytest.approx(raea["sel_F1"], abs=1e-4) == 0.9157
    assert raea["sel_recall"] > 0.95 # Solo 1 falso negativo

def test_n240_risk_reduction_h1(results_df, stats_df):
    raea = results_df[results_df["policy"] == "B6_RAEA"].iloc[0]
    m1 = results_df[results_df["policy"] == "B1_M1"].iloc[0]
    
    # Reduccion de riesgo > 85%
    reduction = (m1["penalized_risk"] - raea["penalized_risk"]) / m1["penalized_risk"]
    assert reduction > 0.85
    
    h1 = stats_df[stats_df["hypothesis"] == "H1_Risk_RAEA_vs_M1"].iloc[0]
    assert h1["p_holm"] < 0.05
    assert "ACEPTADA" in str(h1["verdict"])

def test_n240_availability_estimator_saving(ablations_df):
    a1 = ablations_df[ablations_df["variant"] == "A1"].iloc[0]
    a6 = ablations_df[ablations_df["variant"] == "A6"].iloc[0]
    
    # Sin estimador de disponibilidad (A1), el coste sube > 80%
    cost_increase = (a1["normalized_cost"] - a6["normalized_cost"]) / a6["normalized_cost"]
    assert cost_increase > 0.80
    assert a1["trajectories_differ_from_A6"] > 150

def test_n240_h2_rejection(stats_df):
    h2 = stats_df[stats_df["hypothesis"] == "H2_Risk_RAEA_vs_B5"].iloc[0]
    assert "RECHAZADA" in str(h2["verdict"])
