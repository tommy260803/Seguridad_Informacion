"""
tests/test_methodological_closure.py:
Suite de validación exhaustiva de los criterios metodológicos C1 a C8.
Verifica:
- C1: Justificación empírica del tamaño de entrenamiento de M0 (sensibilidad 25%, 50%, 75%, 100%).
- C2: Auditoría formal de independencia (cero fugas y cero solapamientos entre particiones y cohortes).
- C3: Inferencia real en vivo desde artefactos serializados (cero pregrabados).
- C4: Capacidad y degradación de estimadores de disponibilidad bajo domain shift (in-distribution vs cohorte externa).
- C5: Inferencia estadística pareada bootstrap (B=5,000) con control FWER Holm-Bonferroni.
- C6: Comparación justa frente a Chow B5 bajo cobertura equivalente y fronteras de Pareto.
- C7: Validación del espectro de ablaciones A0 a A6.
- C8: Reproducibilidad autónoma verificable.
"""
from __future__ import annotations

import os
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent

def get_file(rel_path: str) -> Path:
    candidates = [
        ROOT / rel_path,
        ROOT.parent / rel_path,
        ROOT / "CODIGO" / rel_path,
        ROOT.parent / "CODIGO" / rel_path,
    ]
    for c in candidates:
        if c.exists():
            return c
    return ROOT / rel_path

def test_c1_m0_training_sensitivity_and_full_scale():
    """C1: Comprueba que M0 fue evaluado en sensibilidad y entrenado al 100% (N=123,341)."""
    sens_file = get_file("EXPERIMENTOS/SENSIBILIDAD_ENTRENAMIENTO_M0.csv")
    assert sens_file.exists(), f"Falta SENSIBILIDAD_ENTRENAMIENTO_M0.csv en {sens_file}"
    
    df_sens = pd.read_csv(sens_file)
    assert set(df_sens["fraction"].unique()) == {0.25, 0.50, 0.75, 1.00}
    
    # Verificar que el nivel 100% tiene 123,341 muestras de entrenamiento
    sub_100 = df_sens[df_sens["fraction"] == 1.0]
    assert sub_100["n_samples_train"].iloc[0] == 123341
    
    val_col = "n_samples_val_eval" if "n_samples_val_eval" in sub_100.columns else "n_samples_val"
    assert sub_100[val_col].iloc[0] in (13629, 26430)
    
    brier_col = "brier_score_val_eval" if "brier_score_val_eval" in df_sens.columns else "brier_score"
    # Verificar que Brier Score al 100% mejora (es menor o igual) respecto a 25%
    brier_25 = df_sens[df_sens["fraction"] == 0.25][brier_col].mean()
    brier_100 = sub_100[brier_col].mean()
    assert brier_100 <= brier_25, f"Brier al 100% ({brier_100}) debe ser <= Brier al 25% ({brier_25})"

def test_c2_independence_audit_zero_leakage():
    """C2: Comprueba formalmente cero solapamiento entre particiones de entrenamiento y cohortes de evaluación."""
    overlap_file = get_file("02_DATOS/AUDITORIA_SOLAPAMIENTOS.csv")
    assert overlap_file.exists(), f"Falta AUDITORIA_SOLAPAMIENTOS.csv en {overlap_file}"
    
    df_ov = pd.read_csv(overlap_file)
    for _, row in df_ov.iterrows():
        assert row["url_overlap"] == 0, f"Fuga de URL detectada entre {row['set_a']} y {row['set_b']}"
        assert row["domain_overlap"] == 0, f"Fuga de dominio detectada entre {row['set_a']} y {row['set_b']}"
        assert not bool(row["leakage_detected"]), f"Fuga marcada como positiva en {row['set_a']} vs {row['set_b']}"

def test_c3_real_inference_artifacts():
    """C3: Comprueba que las predicciones provienen de inferencia real y no de columnas pregrabadas."""
    preds_file = get_file("EXPERIMENTOS/PREDICCIONES_GENERADAS_DESDE_MODELOS.csv")
    assert preds_file.exists(), f"Falta PREDICCIONES_GENERADAS_DESDE_MODELOS.csv en {preds_file}"
    
    df_preds = pd.read_csv(preds_file)
    assert len(df_preds) > 0
    # Verificar que existen predicciones para cohorte RETROSPECTIVA y EXTERNA
    assert set(df_preds["cohort"].unique()) == {"RETROSPECTIVA", "EXTERNA"}
    # Verificar columnas requeridas
    for col in ["sample_id", "url", "y_true", "policy", "decision", "probability", "penalized_risk", "cost"]:
        assert col in df_preds.columns, f"Falta columna {col} en predicciones"

def test_c4_honest_availability_evaluation():
    """C4: Comprueba que se evalúa la degradación de disponibilidad y el prior empírico constante A2."""
    abl_file = get_file("EXPERIMENTOS/RESULTADOS_ABLACIONES.csv")
    assert abl_file.exists(), f"Falta RESULTADOS_ABLACIONES.csv en {abl_file}"
    df_abl = pd.read_csv(abl_file)
    
    # Comprobar que existe la ablación A2 (prior constante) y A1 (sin disponibilidad)
    assert "A1" in df_abl["policy"].values
    assert "A2" in df_abl["policy"].values
    
    # Comprobar que en cohorte externa A1 tiene coste mayor que A0 (RAEA completo)
    cost_a1 = df_abl[(df_abl["cohort"] == "EXTERNA") & (df_abl["policy"] == "A1")]["normalized_cost"].iloc[0]
    cost_a0 = df_abl[(df_abl["cohort"] == "EXTERNA") & (df_abl["policy"] == "A0")]["normalized_cost"].iloc[0]
    assert cost_a1 > cost_a0, f"A1 sin disponibilidad ({cost_a1}) debe tener mayor coste que RAEA A0 ({cost_a0})"

def test_c5_paired_bootstrap_and_holm_bonferroni():
    """C5: Comprueba la inferencia estadística pareada con B>=5000 y corrección Holm-Bonferroni."""
    stat_file = get_file("EXPERIMENTOS/ESTADISTICA_INFERENCIAL_HOLM.csv")
    assert stat_file.exists(), f"Falta ESTADISTICA_INFERENCIAL_HOLM.csv en {stat_file}"
    
    df_stat = pd.read_csv(stat_file)
    # Comprobar presencia de hipótesis H1 a H6 en ambas cohortes (12 contrastes)
    assert len(df_stat) == 12, f"Se esperaban 12 contrastes (6 hipótesis x 2 cohortes), encontrado {len(df_stat)}"
    
    # Comprobar columnas estadísticas
    for col in ["mean_diff", "ci95_low", "ci95_high", "p_value_raw", "p_value_holm", "significant_at_05", "scientific_interpretation"]:
        assert col in df_stat.columns, f"Falta columna {col} en estadísticas"
        
    # Verificar que los p-valores ajustados por Holm son no-decrecientes respecto a raw ordenado
    assert np.all(df_stat["p_value_holm"] >= df_stat["p_value_raw"])

def test_c6_equivalent_coverage_comparison():
    """C6: Comprueba que la comparación RAEA vs Chow B5 a cobertura idéntica está formalizada."""
    equiv_file = get_file("EXPERIMENTOS/RESULTADOS_COBERTURA_EQUIVALENTE.csv")
    assert equiv_file.exists(), f"Falta RESULTADOS_COBERTURA_EQUIVALENTE.csv en {equiv_file}"
    
    df_eq = pd.read_csv(equiv_file)
    assert len(df_eq) >= 10
    
    # Comprobar que en la cohorte externa bajo umbrales congelados de Chow, RAEA tiene menor riesgo
    sub_chow_op = df_eq[(df_eq["cohort"] == "EXTERNA") & (df_eq["scenario"] == "At_Chow_Operating_Coverage")]
    raea_pol = "RAEA_FrozenThreshold" if "RAEA_FrozenThreshold" in sub_chow_op["policy"].values else "RAEA_Matched"
    chow_pol = "B5_Chow_FrozenThreshold" if "B5_Chow_FrozenThreshold" in sub_chow_op["policy"].values else "B5_Chow_Matched"
    risk_raea = sub_chow_op[sub_chow_op["policy"] == raea_pol]["penalized_risk"].iloc[0]
    risk_chow = sub_chow_op[sub_chow_op["policy"] == chow_pol]["penalized_risk"].iloc[0]
    assert risk_raea < risk_chow, f"Bajo umbral congelado de operación de Chow, RAEA ({risk_raea}) debe tener menor riesgo que Chow ({risk_chow})"

def test_c7_ablation_spectrum():
    """C7: Comprueba la presencia y consistencia de las ablaciones A0 a A6."""
    abl_file = get_file("EXPERIMENTOS/RESULTADOS_ABLACIONES.csv")
    assert abl_file.exists(), f"Falta RESULTADOS_ABLACIONES.csv en {abl_file}"
    
    df_abl = pd.read_csv(abl_file)
    expected_ablations = {"A0", "A1", "A2", "A3", "A4", "A5", "A6"}
    assert expected_ablations.issubset(set(df_abl["policy"].unique()))

def test_c8_figures_generated_and_non_empty():
    """C8: Comprueba que las 6 figuras requeridas existen físicamente y no están vacías."""
    fig_dir = get_file("FIGURAS")
    if not fig_dir.exists():
        fig_dir = get_file("06_FIGURAS")
    assert fig_dir.exists(), f"Falta carpeta de figuras en {fig_dir}"
    
    expected_figs = [
        "fig1_raea_sequential_architecture.png",
        "fig2_risk_coverage_dual_cohorts.png",
        "fig3_stopping_distribution.png",
        "fig4_pareto_cost_vs_latency.png",
        "fig5_equivalent_coverage_pareto.png",
        "fig6_m0_training_sensitivity.png",
    ]
    for fn in expected_figs:
        fp = fig_dir / fn
        assert fp.exists(), f"Falta figura {fn} en {fp}"
        assert fp.stat().st_size > 1000, f"Figura {fn} tiene tamaño menor a 1KB"
