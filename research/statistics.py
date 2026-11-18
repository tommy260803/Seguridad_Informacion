"""
research.statistics: Inferencia estadística no paramétrica mediante bootstrap pareado (B=5,000)
con unión estricta por identificador y corrección de multiplicidad escalonada Holm-Bonferroni.
Evalúa las hipótesis formales H1 a H6 en cohorte retrospectiva y cohorte externa independiente.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from research.workspace import find_data_file, get_candidate_roots, get_experiments_dir

B_BOOT = 5000
SEED = 42

def paired_bootstrap(d: np.ndarray, b: int = B_BOOT, seed: int = SEED) -> Tuple[float, float, float, float]:
    """
    Calcula la media de la diferencia pareada, el intervalo de confianza al 95%
    y el p-valor bilateral empírico mediante remuestreo bootstrap con reemplazo.
    """
    rng = np.random.default_rng(seed)
    n = len(d)
    orig_mean = float(np.mean(d))
    idx = rng.integers(0, n, size=(b, n))
    b_means = np.mean(d[idx], axis=1)
    
    ci_low = float(np.percentile(b_means, 2.5))
    ci_high = float(np.percentile(b_means, 97.5))
    
    # P-valor bilateral empírico acotado en [1/B, 1.0]
    prop_leq = np.mean(b_means <= 0)
    prop_geq = np.mean(b_means >= 0)
    p_two = 2.0 * min(prop_leq, prop_geq)
    p_two = float(np.clip(p_two, 1.0 / b, 1.0))
    
    return orig_mean, ci_low, ci_high, p_two

def bootstrap_f1_difference(
    df_a: pd.DataFrame,
    df_b: pd.DataFrame,
    b: int = B_BOOT,
    seed: int = SEED,
    delta: float = 0.05
) -> Tuple[float, float, float, float, bool]:
    """
    Bootstrap pareado para diferencia de F1 selectivo (F1_A - F1_B).
    Evalúa no inferioridad de A frente a B con margen delta (H0: F1_A - F1_B < -delta).
    """
    rng = np.random.default_rng(seed)
    merged = pd.merge(df_a, df_b, on="sample_id", suffixes=('_a', '_b'))
    n = len(merged)
    
    def calc_f1(df, prefix):
        sub = df[df[f"selective_state{prefix}"] == "covered"]
        tp = np.sum((sub[f"decision{prefix}"] == "phishing") & (sub["y_true_a"] == 1))
        fp = np.sum((sub[f"decision{prefix}"] == "phishing") & (sub["y_true_a"] == 0))
        fn = np.sum((sub[f"decision{prefix}"] == "legitimate") & (sub["y_true_a"] == 1))
        denom = 2 * tp + fp + fn
        return (2.0 * tp / denom) if denom > 0 else 0.0

    orig_f1_a = calc_f1(merged, "_a")
    orig_f1_b = calc_f1(merged, "_b")
    orig_diff = orig_f1_a - orig_f1_b
    
    b_diffs = np.zeros(b)
    for i in range(b):
        sample_idx = rng.integers(0, n, size=n)
        sample = merged.iloc[sample_idx]
        b_diffs[i] = calc_f1(sample, "_a") - calc_f1(sample, "_b")
        
    ci_low = float(np.percentile(b_diffs, 2.5))
    ci_high = float(np.percentile(b_diffs, 97.5))
    
    # P-valor para no-inferioridad: P(diff <= -delta)
    p_non_inferior = float(np.mean(b_diffs <= -delta))
    non_inferior_supported = bool(ci_low >= -delta)
    
    return orig_diff, ci_low, ci_high, p_non_inferior, non_inferior_supported

def apply_holm_bonferroni(hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aplica el procedimiento secuencial step-down de Holm-Bonferroni sobre los p-valores crudos.
    Garantiza control estricto del Family-Wise Error Rate (FWER) a nivel alpha = 0.05.
    """
    m = len(hypotheses)
    if m == 0:
        return hypotheses
        
    sorted_indices = sorted(range(m), key=lambda i: hypotheses[i]["p_value_raw"])
    running_max = 0.0
    adjusted_p = [0.0] * m
    for rank, orig_idx in enumerate(sorted_indices):
        multiplier = m - rank
        raw_p = hypotheses[orig_idx]["p_value_raw"]
        val = raw_p * multiplier
        running_max = max(running_max, val)
        adjusted_p[orig_idx] = float(min(1.0, running_max))
        
    for i, h in enumerate(hypotheses):
        h["p_value_holm"] = adjusted_p[i]
        h["significant_at_05"] = bool(adjusted_p[i] <= 0.05)
        
    return hypotheses

def evaluate_paired_hypothesis(
    df_cohort: pd.DataFrame,
    policy_a: str,
    policy_b: str,
    metric_col: str,
    hypothesis_id: str,
    cohort_name: str,
    metric_label: str,
    description: str = ""
) -> Dict[str, Any]:
    """
    Une explícitamente ambas políticas por 'sample_id' y calcula la diferencia pareada (A - B).
    """
    df_a = df_cohort[df_cohort["policy"] == policy_a][["sample_id", metric_col]].rename(columns={metric_col: "metric_a"})
    df_b = df_cohort[df_cohort["policy"] == policy_b][["sample_id", metric_col]].rename(columns={metric_col: "metric_b"})
    
    merged = pd.merge(df_a, df_b, on="sample_id")
    n_paired = len(merged)
    if n_paired == 0:
        raise ValueError(f"No hay muestras emparejadas entre {policy_a} y {policy_b}")
        
    diff = (merged["metric_a"] - merged["metric_b"]).to_numpy(dtype=np.float64)
    mean_diff, ci_low, ci_high, p_raw = paired_bootstrap(diff)
    
    return {
        "cohort": cohort_name,
        "hypothesis_id": hypothesis_id,
        "description": description,
        "policy_a": policy_a,
        "policy_b": policy_b,
        "metric": metric_label,
        "n_paired": n_paired,
        "mean_diff": mean_diff,
        "ci95_low": ci_low,
        "ci95_high": ci_high,
        "p_value_raw": p_raw,
    }

def run_hypothesis_tests(workspace_root: Path | None = None) -> pd.DataFrame:
    here = Path(__file__).resolve()
    root = workspace_root or here.parent.parent
    
    exp_dir = get_experiments_dir()
    preds_path = None
    candidate_paths = [
        exp_dir / "PREDICCIONES_GENERADAS_DESDE_MODELOS.csv",
        root / "EXPERIMENTOS" / "PREDICCIONES_GENERADAS_DESDE_MODELOS.csv",
        root / "05_EXPERIMENTOS" / "PREDICCIONES_GENERADAS_DESDE_MODELOS.csv",
        root / "build_investigacion_original" / "04_EXPERIMENTOS" / "PREDICCIONES_GENERADAS_DESDE_MODELOS.csv",
    ]
    for cp in candidate_paths:
        if cp.exists():
            preds_path = cp
            break
            
    if preds_path is None:
        raise FileNotFoundError(
            "No se encontró PREDICCIONES_GENERADAS_DESDE_MODELOS.csv. "
            "Ejecute 'python -m research.evaluate' primero."
        )

    print("=" * 75)
    print("[research.statistics] CONTRASTES DE HIPÓTESIS BOOTSTRAP PAREADO CON HOLM-BONFERRONI")
    print(f"Fuente de datos: {preds_path.name}")
    print(f"Iteraciones: B={B_BOOT:,} | Semilla: {SEED} | Control FWER: Holm-Bonferroni")
    print("=" * 75)

    df_all = pd.read_csv(preds_path)
    raw_tests = []

    for cohort_name in ["RETROSPECTIVA", "EXTERNA"]:
        df_cohort = df_all[df_all["cohort"] == cohort_name].copy()
        
        # H1: RAEA reduce el riesgo penalizado frente a M1 (R_RAEA - R_M1 < 0)
        raw_tests.append(evaluate_paired_hypothesis(
            df_cohort, "B6_RAEA", "B1_M1", "penalized_risk", "H1_risk_raea_vs_m1", cohort_name, "penalized_risk",
            description="Reducción de riesgo penalizado de RAEA frente a M1"
        ))
        
        # H2: RAEA reduce el riesgo frente a Chow B5 (diferencia pareada en riesgo R_RAEA - R_B5)
        raw_tests.append(evaluate_paired_hypothesis(
            df_cohort, "B6_RAEA", "B5_M1_chow", "penalized_risk", "H2_risk_raea_vs_b5", cohort_name, "penalized_risk",
            description="Diferencia de riesgo de RAEA frente a B5 Chow"
        ))
        
        # H3: RAEA reduce el coste de adquisición frente a M2 completo (C_RAEA - C_M2 < 0)
        raw_tests.append(evaluate_paired_hypothesis(
            df_cohort, "B6_RAEA", "B2_M2", "cost", "H3_cost_raea_vs_m2", cohort_name, "normalized_cost",
            description="Reducción de coste de adquisición de RAEA frente a M2 completo"
        ))
        
        # H4: No inferioridad de F1 selectivo RAEA vs M1 (margen delta = 0.05)
        df_raea = df_cohort[df_cohort["policy"] == "B6_RAEA"]
        df_m1 = df_cohort[df_cohort["policy"] == "B1_M1"]
        f1_diff, f1_ci_l, f1_ci_h, p_noninf, noninf_supp = bootstrap_f1_difference(df_raea, df_m1, b=B_BOOT, seed=SEED, delta=0.05)
        raw_tests.append({
            "cohort": cohort_name,
            "hypothesis_id": "H4_f1_non_inferiority_raea_vs_m1",
            "description": f"No-inferioridad F1 selectivo RAEA vs M1 (delta=0.05, soporte CI>=-delta: {noninf_supp})",
            "policy_a": "B6_RAEA",
            "policy_b": "B1_M1",
            "metric": "f1_selective_diff",
            "n_paired": len(df_raea),
            "mean_diff": f1_diff,
            "ci95_low": f1_ci_l,
            "ci95_high": f1_ci_h,
            "p_value_raw": max(1.0 / B_BOOT, p_noninf),
        })
        
        # H5: Inclusión de disponibilidad (RAEA B6) reduce coste frente a sin disponibilidad (A1)
        raw_tests.append(evaluate_paired_hypothesis(
            df_cohort, "B6_RAEA", "A1", "cost", "H5_cost_raea_vs_no_avail", cohort_name, "normalized_cost",
            description="Reducción de coste al modelar disponibilidad (B6 vs A1 sin disponibilidad)"
        ))
        
        # H6: RAEA con estimador de disponibilidad vs RAEA con prior constante (A2)
        raw_tests.append(evaluate_paired_hypothesis(
            df_cohort, "B6_RAEA", "A2", "cost", "H6_cost_raea_vs_prior_avail", cohort_name, "normalized_cost",
            description="Diferencia de coste entre estimador de disponibilidad y prior constante (B6 vs A2)"
        ))

    # Aplicar corrección Holm-Bonferroni sobre la familia completa de 12 contrastes (6 hipótesis x 2 cohortes)
    adjusted_tests = apply_holm_bonferroni(raw_tests)
    df_stats = pd.DataFrame(adjusted_tests)
    
    # Agregar columna explícita de interpretación rigurosa: no afirmar equivalencia si p no es significativo
    def get_scientific_interpretation(row):
        h_id = row["hypothesis_id"]
        sig = row["significant_at_05"]
        diff = row["mean_diff"]
        ci_l = row["ci95_low"]
        ci_h = row["ci95_high"]
        
        if h_id == "H4_f1_non_inferiority_raea_vs_m1":
            if ci_l >= -0.05:
                return f"No-inferioridad respaldada (IC95% [{ci_l:.4f}, {ci_h:.4f}] >= -0.05)."
            else:
                return f"No se rechaza margen de inferioridad; no se concluye equivalencia."
        elif "risk" in h_id:
            if sig and diff < 0:
                return f"Reducción estadísticamente significativa de riesgo (p_adj < 0.05)."
            elif sig and diff > 0:
                return f"Riesgo significativamente mayor (p_adj < 0.05)."
            else:
                return f"Diferencia no estadísticamente significativa (IC95% [{ci_l:.4f}, {ci_h:.4f}]); NO implica equivalencia."
        elif "cost" in h_id:
            if sig and diff < 0:
                return f"Ahorro de coste estadísticamente significativo (p_adj < 0.05)."
            elif sig and diff > 0:
                return f"Coste significativamente mayor (p_adj < 0.05)."
            else:
                return f"Diferencia no estadísticamente significativa (IC95% [{ci_l:.4f}, {ci_h:.4f}]); NO implica equivalencia."
        return "Contraste evaluado."

    df_stats["scientific_interpretation"] = df_stats.apply(get_scientific_interpretation, axis=1)

    exp_dir.mkdir(parents=True, exist_ok=True)
    out_csv = exp_dir / "ESTADISTICA_INFERENCIAL_HOLM.csv"
    df_stats.to_csv(out_csv, index=False)
    df_stats.to_csv(exp_dir / "ESTADISTICA.csv", index=False)

    for alt_exp in [root / "EXPERIMENTOS", root / "05_EXPERIMENTOS", root / "build_investigacion_original" / "04_EXPERIMENTOS"]:
        alt_exp.mkdir(parents=True, exist_ok=True)
        df_stats.to_csv(alt_exp / "ESTADISTICA_INFERENCIAL_HOLM.csv", index=False)
        df_stats.to_csv(alt_exp / "ESTADISTICA.csv", index=False)
    
    auto_out_dir = root / "autonomous_reproduction_suite" / "output"
    auto_out_dir.mkdir(parents=True, exist_ok=True)
    df_stats.to_csv(auto_out_dir / "ESTADISTICA_REPRODUCIDA.csv", index=False)

    print("\n[research.statistics] RESULTADOS ESTADÍSTICOS CON CORRECCIÓN HOLM-BONFERRONI:")
    cols_display = ["cohort", "hypothesis_id", "metric", "mean_diff", "ci95_low", "ci95_high", "p_value_raw", "p_value_holm", "significant_at_05"]
    print(df_stats[cols_display].to_string(index=False))
    print("=" * 75)
    return df_stats

if __name__ == "__main__":
    run_hypothesis_tests()
