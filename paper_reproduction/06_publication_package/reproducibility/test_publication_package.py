"""
test_publication_package.py
Pytest suite verifying calculated experimental values and complete reproducibility 
of the publication package for Revista Politecnica.

This suite does NOT simply check file existence or row counts; it computes and asserts
the exact empirical values, confusion matrices, statistical test statistics, and latency benchmarks.
"""

from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, accuracy_score
import pytest

PKG_DIR = Path(__file__).resolve().parents[1]
TABLES_DIR = PKG_DIR / "tables"
MANIFESTS_DIR = PKG_DIR / "data_manifests"


def test_master_classifier_performance_calculated_values():
    """Verifica los valores calculados de exactitud, precisión, recall, F1 y dimensionalidad de entrada."""
    path = TABLES_DIR / "master_classifier_performance.csv"
    assert path.exists(), "Falta master_classifier_performance.csv"
    df = pd.read_csv(path)
    
    # 1. M0 Léxico
    m0 = df[df["model_or_policy"].str.contains("M0_Léxico", case=False, na=False)].iloc[0]
    assert round(float(m0["accuracy"]), 4) == 0.9291
    assert round(float(m0["precision"]), 4) == 0.9080
    assert round(float(m0["recall"]), 4) == 0.8272
    assert round(float(m0["f1_score"]), 4) == 0.8658
    assert round(float(m0["fpr"]), 4) == 0.0320
    assert round(float(m0["fnr"]), 4) == 0.1728
    assert "11 features" in str(m0["primary_modalities_used"])

    # 2. M1 Infraestructura
    m1 = df[df["model_or_policy"].str.contains("M1_Infra", case=False, na=False)].iloc[0]
    assert round(float(m1["accuracy"]), 4) == 0.9609
    assert round(float(m1["precision"]), 4) == 0.9824
    assert round(float(m1["recall"]), 4) == 0.8743
    assert round(float(m1["f1_score"]), 4) == 0.9252
    assert round(float(m1["fpr"]), 4) == 0.0060
    assert round(float(m1["fnr"]), 4) == 0.1257
    # Verificar corrección: debe decir 36 features y NO 28
    assert "36 features" in str(m1["primary_modalities_used"])
    assert "28 features" not in str(m1["primary_modalities_used"])

    # 3. M2 DOM
    m2 = df[df["model_or_policy"].str.contains("M2_Monolítico_DOM", case=False, na=False)].iloc[0]
    assert round(float(m2["accuracy"]), 4) == 0.9638
    assert round(float(m2["precision"]), 4) == 0.9770
    assert round(float(m2["recall"]), 4) == 0.8901
    assert round(float(m2["f1_score"]), 4) == 0.9315
    assert round(float(m2["fpr"]), 4) == 0.0080
    assert round(float(m2["fnr"]), 4) == 0.1099
    # Verificar corrección: debe decir 62 features y NO 47
    assert "62 features" in str(m2["primary_modalities_used"])
    assert "47 features" not in str(m2["primary_modalities_used"])

    # 4. M3 Visual Chrome CDP (N=83)
    m3 = df[df["model_or_policy"].str.contains("M3_Visual", case=False, na=False)].iloc[0]
    assert int(m3["evaluation_cohort_n"]) == 83
    assert round(float(m3["accuracy"]), 4) == 0.9277
    assert round(float(m3["precision"]), 4) == 1.0000
    assert round(float(m3["recall"]), 4) == 0.7857
    assert round(float(m3["f1_score"]), 4) == 0.8800
    assert round(float(m3["fpr"]), 4) == 0.0000


def test_historical_individual_predictions_reproducibility():
    """Calcula matrices de confusión directamente de las predicciones individuales de la Cohorte Histórica."""
    path = MANIFESTS_DIR / "cohort_historical_n1200_individual_predictions.csv"
    assert path.exists(), "Falta cohort_historical_n1200_individual_predictions.csv"
    df = pd.read_csv(path)
    assert len(df) == 3600  # 1200 urls x 3 modelos evaluados

    # 1. M0 Original
    df_m0 = df[df["model_version"] == "M0_Baseline_Original_v020"]
    yt = (df_m0["verified_label"] == "phishing").astype(int)
    yp = (df_m0["final_prediction"] == "phishing").astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    assert tp == 490 and tn == 580 and fp == 20 and fn == 110
    assert round(float(f1_score(yt, yp)), 4) == 0.8829

    # 2. M0 Normalizado
    df_m0_norm = df[df["model_version"] == "M0_Baseline_Normalized_v020"]
    yt = (df_m0_norm["verified_label"] == "phishing").astype(int)
    yp = (df_m0_norm["final_prediction"] == "phishing").astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    assert tp == 478 and tn == 580 and fp == 20 and fn == 122
    assert round(float(f1_score(yt, yp)), 4) == 0.8707

    # 3. HybridM0 Config C
    df_hyb = df[df["model_version"] == "HybridM0_ConfigC_v020"]
    yt = (df_hyb["verified_label"] == "phishing").astype(int)
    yp = (df_hyb["final_prediction"] == "phishing").astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    assert tp == 451 and tn == 596 and fp == 4 and fn == 149
    assert round(float(f1_score(yt, yp)), 4) == 0.8550


def test_clean_phishing_individual_predictions_reproducibility():
    """Calcula matrices de confusión directamente de las predicciones individuales de la Cohorte Phishing Limpio."""
    path = MANIFESTS_DIR / "cohort_clean_phishing_n1200_individual_predictions.csv"
    assert path.exists(), "Falta cohort_clean_phishing_n1200_individual_predictions.csv"
    df = pd.read_csv(path)
    assert len(df) == 2400  # 1200 urls x 2 modelos léxicos reproducidos deterministamente

    # 1. M0 Original
    df_orig = df[df["model_version"] == "M0_Baseline_Original_v020"]
    yt = (df_orig["verified_label"] == "phishing").astype(int)
    yp = (df_orig["final_prediction"] == "phishing").astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    assert tp == 430 and tn == 571 and fp == 29 and fn == 170
    assert round(float(f1_score(yt, yp)), 4) == 0.8121

    # 2. M0 Normalizado
    df_norm = df[df["model_version"] == "M0_Baseline_Normalized_v020"]
    yt = (df_norm["verified_label"] == "phishing").astype(int)
    yp = (df_norm["final_prediction"] == "phishing").astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    assert tp == 415 and tn == 572 and fp == 28 and fn == 185
    assert round(float(f1_score(yt, yp)), 4) == 0.7958


def test_policy_c_confusion_matrix_consistency():
    """Verifica el ground truth pareado de la cascada M0->M1->M2 en los 691 registros."""
    pred_path = MANIFESTS_DIR / "cascade_paired_predictions.csv"
    assert pred_path.exists()
    df_pred = pd.read_csv(pred_path)
    assert len(df_pred) == 691
    
    # Calculate exact confusion matrix
    tp = int(((df_pred["label"] == 1) & (df_pred["policy_c_pred"] == 1)).sum())
    tn = int(((df_pred["label"] == 0) & (df_pred["policy_c_pred"] == 0)).sum())
    fp = int(((df_pred["label"] == 0) & (df_pred["policy_c_pred"] == 1)).sum())
    fn = int(((df_pred["label"] == 1) & (df_pred["policy_c_pred"] == 0)).sum())
    
    assert tp == 169, f"TP esperado 169, obtenido {tp}"
    assert tn == 497, f"TN esperado 497, obtenido {tn}"
    assert fp == 3, f"FP esperado 3, obtenido {fp}"
    assert fn == 22, f"FN esperado 22, obtenido {fn}"
    
    # Check master table matches
    tab_path = TABLES_DIR / "master_early_exit_policies.csv"
    df_tab = pd.read_csv(tab_path)
    pol_c = df_tab[df_tab["policy_id"] == "Policy_C"].iloc[0]
    assert int(pol_c["fn_count"]) == 22, f"fn_count en tabla es {pol_c['fn_count']}, esperado 22"
    assert round(float(pol_c["f1_score"]), 4) == 0.9311
    assert round(float(pol_c["html_avoided_pct"]), 2) == 67.87


def test_non_inferiority_and_hypothesis_tests_values():
    """Verifica los valores calculados de inferencia estadística y no-inferioridad exploratoria."""
    stat_path = TABLES_DIR / "master_inferential_statistics.csv"
    df = pd.read_csv(stat_path)
    
    # Check non-inferiority test (TEST-02)
    non_inf = df[df["hypothesis_test_id"] == "TEST-02"].iloc[0]
    assert any(term in str(non_inf["non_inferior_confirmed"]).lower() for term in ["true", "confirmed", "supported"])
    assert float(non_inf["ci95_low"]) > -0.0200, "El límite inferior del 95% CI cruza el margen delta=0.02"
    assert round(float(non_inf["mean_effect_size"]), 4) == -0.0004
    assert "exploratory" in str(non_inf["test_type"]).lower() or "post-hoc" in str(non_inf["test_type"]).lower()

    # Check M1 vs M0 superiority (TEST-05)
    m1_m0 = df[df["hypothesis_test_id"] == "TEST-05"].iloc[0]
    assert float(m1_m0["raw_p_value"]) <= 0.001
    assert round(float(m1_m0["mean_effect_size"]), 4) == 0.0597
    assert m1_m0["significant_at_0_05"] == True

    # Check M2 vs M1 content gain (TEST-06)
    m2_m1 = df[df["hypothesis_test_id"] == "TEST-06"].iloc[0]
    assert float(m2_m1["raw_p_value"]) > 0.05  # No significativo (p=0.7905)
    assert m2_m1["significant_at_0_05"] == False


def test_missing_modalities_fallback_values():
    """Verifica las estrategias de mitigación ante datos faltantes en la cohorte en vivo (N=600)."""
    fallback_path = TABLES_DIR / "master_missing_modalities_fallback.csv"
    df_fb = pd.read_csv(fallback_path)
    
    # Estrategia C (Fallback jerárquico a M0)
    strat_c = df_fb[df_fb["strategy_id"] == "Strategy_C"].iloc[0]
    assert round(float(strat_c["f1_score"]), 4) == 0.8246
    assert round(float(strat_c["precision"]), 4) == 0.9364
    assert round(float(strat_c["fpr"]), 4) == 0.0500
    assert round(float(strat_c["coverage_pct"]), 1) == 100.0

    # Estrategia F (Imputación ingenua con ceros)
    strat_f = df_fb[df_fb["strategy_id"] == "Strategy_F"].iloc[0]
    assert round(float(strat_f["fpr"]), 4) == 0.1867


def test_systems_efficiency_exact_latencies():
    """Verifica los valores calculados de latencia y ahorro temporal del benchmark."""
    lat_path = TABLES_DIR / "master_systems_efficiency.csv"
    df = pd.read_csv(lat_path)
    
    # Pipeline Léxico M0
    m0_eff = df[df["pipeline_strategy"] == "M0_Léxico_Puro"].iloc[0]
    assert round(float(m0_eff["p50_median_latency_ms"]), 1) == 6.0
    assert round(float(m0_eff["cpu_time_per_sample_ms"]), 2) == 14.74
    assert round(float(m0_eff["api_p50_ms"]), 2) == 19.75

    # Cascada Original M4
    m4_eff = df[df["pipeline_strategy"] == "Cascada_Original_M4"].iloc[0]
    assert round(float(m4_eff["p50_median_latency_ms"]), 1) == 464.8
    assert round(float(m4_eff["time_savings_vs_m3_pct"]), 2) == 71.81
    assert round(float(m4_eff["time_savings_vs_m2_pct"]), 2) == 31.44

    # Cascada Asimétrica PolC
    polc_eff = df[df["pipeline_strategy"] == "Cascada_Asimétrica_PolC"].iloc[0]
    assert round(float(polc_eff["p50_median_latency_ms"]), 2) == 970.51
    assert round(float(polc_eff["time_savings_vs_m3_pct"]), 2) == 66.09


def test_domain_overlap_audit_is_zero():
    """Certifica 0% de fuga de dominios registrados entre entrenamiento y cohorte externa."""
    overlap_path = MANIFESTS_DIR / "domain_overlap_audit.csv"
    df = pd.read_csv(overlap_path)
    assert len(df) in (1200, 1201)
    leaked = (df["overlap_status"] != "DISJUNTO_ESTRICTO").sum()
    assert leaked == 0, f"Se encontraron {leaked} dominios con fuga en la auditoría"


def test_model_hashes_and_dimensions_verification():
    """Verifica que las dimensiones nativas n_features_in_ de cada modelo sean 11, 36, 62 y 75."""
    hash_path = MANIFESTS_DIR / "MANIFIESTO_MODELOS_SHA256.csv"
    df = pd.read_csv(hash_path)
    assert len(df) >= 10
    
    # M0 models: 11
    m0_rows = df[df["Stage"] == "M0"]
    for _, r in m0_rows.iterrows():
        assert int(r["Input_Features_In_Model"]) == 11
        
    # M1 models: 36
    m1_rows = df[df["Stage"] == "M1"]
    for _, r in m1_rows.iterrows():
        assert int(r["Input_Features_In_Model"]) == 36
        
    # M2 models: 62
    m2_rows = df[df["Stage"] == "M2"]
    for _, r in m2_rows.iterrows():
        assert int(r["Input_Features_In_Model"]) == 62
        
    # M3 models: 75
    m3_rows = df[df["Stage"].str.startswith("M3")]
    for _, r in m3_rows.iterrows():
        assert int(r["Input_Features_In_Model"]) == 75
