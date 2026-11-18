"""Prueba de consistencia y determinismo de la reproducción científica de RAEA-Phish."""
import json
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "raea_final"


def test_required_artifacts_exist():
    required = [
        "DATOS_Y_ETIQUETAS.csv",
        "PREDICCIONES_Y_DECISIONES.csv",
        "RESULTADOS_COMPARATIVOS.csv",
        "ABLACIONES_VERIFICADAS.csv",
        "ESTADISTICA_Y_RIESGO.csv",
        "run_metadata.json",
    ]
    for fname in required:
        p = OUT / fname
        assert p.exists(), f"Artefacto obligatorio ausente: {fname}"
        assert p.stat().st_size > 0, f"Artefacto vacío: {fname}"


def test_population_split_integrity():
    df = pd.read_csv(OUT / "DATOS_Y_ETIQUETAS.csv")
    assert len(df) == 600
    assert (df.groupby("partition").size() == 300).all()
    # Sin duplicados de URLs
    assert df["dup_url_in_cohort"].sum() == 0
    # Sin dominios solapados entre train y test
    assert df["domain_in_both_partitions"].sum() == 0


def test_ablation_modifications_are_genuine():
    abl = pd.read_csv(OUT / "ABLACIONES_VERIFICADAS.csv")
    test_abl = abl[abl.population == "ORIGINAL_TEST_N300"].set_index("variant")

    # A1: disponibilidad asumida al 100% genera trayectorias distintas
    assert test_abl.loc["A1", "urls_trajectory_differs_from_A6"] > 0

    # A2: sin coste asimétrico aumenta los falsos negativos
    assert test_abl.loc["A2", "sel_FN"] > test_abl.loc["A6", "sel_FN"]

    # A3: sin abstención debe tener cobertura 100% y 0 abstenciones
    assert test_abl.loc["A3", "coverage"] == 1.0
    assert test_abl.loc["A3", "n_abstained"] == 0

    # A4: sin VOI solicita exactamente 1 modalidad (solo M0)
    assert test_abl.loc["A4", "mean_modalities_requested_incl_url"] == 1.0


def test_primary_hypotheses_integrity():
    st = pd.read_csv(OUT / "ESTADISTICA_Y_RIESGO.csv")
    prim = st[st.family == "primary"].set_index("hypothesis")

    # H1, H2, H3 presentes
    assert "H1" in prim.index
    assert "H2" in prim.index
    assert "H3" in prim.index

    # H3: RAEA es más barato que M1 (p < 0.001)
    assert prim.loc["H3", "p_one_sided_raea_lower"] < 0.001
    assert prim.loc["H3", "estimate"] < 0.0


def test_confusion_matrix_arithmetic_consistency():
    res = pd.read_csv(OUT / "RESULTADOS_COMPARATIVOS.csv")
    for _, r in res.iterrows():
        # Matriz selectiva suma N_decididos
        assert r["sel_TP"] + r["sel_FP"] + r["sel_TN"] + r["sel_FN"] == r["n_decided"]
        # Cobertura + abstenciones suma N
        assert r["n_decided"] + r["n_abstained"] == r["N"]
        # Fail-open y fail-closed suman N
        assert r["failopen_TP"] + r["failopen_FP"] + r["failopen_TN"] + r["failopen_FN"] == r["N"]
        assert r["failclosed_TP"] + r["failclosed_FP"] + r["failclosed_TN"] + r["failclosed_FN"] == r["N"]


def test_f1_confusion_matrix_exact_reconciliation():
    """Detecta cualquier discrepancia entre la matriz de confusión y el F1 reportado."""
    res = pd.read_csv(OUT / "RESULTADOS_COMPARATIVOS.csv")
    for _, r in res.iterrows():
        # F1 selectivo
        tp, fp, fn = r["sel_TP"], r["sel_FP"], r["sel_FN"]
        if 2 * tp + fp + fn > 0:
            calc_f1 = 2 * tp / (2 * tp + fp + fn)
            assert abs(calc_f1 - r["sel_F1"]) < 1e-5, (
                f"Discrepancia en F1 selectivo para {r['population']} {r['policy']}: "
                f"calculado {calc_f1:.6f} vs reportado {r['sel_F1']:.6f}"
            )
        # F1 fail-open
        tp_fo, fp_fo, fn_fo = r["failopen_TP"], r["failopen_FP"], r["failopen_FN"]
        if 2 * tp_fo + fp_fo + fn_fo > 0:
            calc_fo_f1 = 2 * tp_fo / (2 * tp_fo + fp_fo + fn_fo)
            assert abs(calc_fo_f1 - r["failopen_F1"]) < 1e-5, (
                f"Discrepancia en F1 fail-open para {r['population']} {r['policy']}"
            )
        # F1 fail-closed
        tp_fc, fp_fc, fn_fc = r["failclosed_TP"], r["failclosed_FP"], r["failclosed_FN"]
        if 2 * tp_fc + fp_fc + fn_fc > 0:
            calc_fc_f1 = 2 * tp_fc / (2 * tp_fc + fp_fc + fn_fc)
            assert abs(calc_fc_f1 - r["failclosed_F1"]) < 1e-5, (
                f"Discrepancia en F1 fail-closed para {r['population']} {r['policy']}"
            )

    # Verificación específica del valor 0.9420 en RAEA PHISHING_WEB_TEST
    raea_pw = res[(res["population"] == "PHISHING_WEB_TEST") & (res["policy"] == "B6_RAEA")].iloc[0]
    assert raea_pw["sel_TP"] == 65
    assert raea_pw["sel_FP"] == 2
    assert raea_pw["sel_FN"] == 6
    assert abs(raea_pw["sel_F1"] - (130.0 / 138.0)) < 1e-5
    assert round(raea_pw["sel_F1"], 4) == 0.9420

