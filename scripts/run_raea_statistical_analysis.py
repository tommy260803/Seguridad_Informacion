"""Analisis estadistico riguroso, vectorizado y reproducible de RAEA-Phish (Fase 6).

Metodologia:
1. Intervalos de confianza al 95% mediante Bootstrap no parametrico (B=2,000 iteraciones, seed=42)
2. Bootstrap pareado para diferencias relativas:
   - Delta F1, Delta Recall, Delta Weighted Risk frente a B0, B2, B3, B4, B5
3. Pruebas de hipotesis de McNemar exactas (binomtest pareado de contingencias)
4. Correccion de comparaciones multiples mediante procedimiento secuencial de Holm-Bonferroni
5. Analisis de sensibilidad parametrica para gamma in [5, 30] y lambda in [0.05, 1.0]

Entregables:
- bootstrap_results.csv
- statistical_tests.csv
- confidence_intervals.csv
- sensitivity_analysis.csv
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.stats import binomtest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.run_raea_comparative_experiments import (
    load_evaluation_dataset,
    simulate_b3_entropy_cascade,
    simulate_b4_conservative,
    simulate_b5_simple_confidence_cost,
)
from phishguard_orchestrator.raea.models import RAEAConfig
from phishguard_orchestrator.raea.engine import run_raea

OUT_DIR = ROOT / "artifacts" / "raea"
OUT_DIR.mkdir(parents=True, exist_ok=True)
B_BOOTSTRAP = 2000
SEED = 42


def fast_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Tuple[float, float, float, float]:
    """Calcula accuracy, precision, recall y f1 vectorizados en microsegundos."""
    tp = np.sum((y_true == 1) & (y_pred == 1))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    
    n = len(y_true)
    acc = (tp + tn) / n if n > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return acc, prec, rec, f1


def fast_weighted_risk(y_true: np.ndarray, y_pred: np.ndarray, abstained: np.ndarray, gamma: float = 15.0, c_abst: float = 0.35) -> float:
    """Calcula la perdida esperada ponderada media vectorizada."""
    fn_loss = np.sum((y_true == 1) & (y_pred == 0) & (abstained == 0)) * gamma
    fp_loss = np.sum((y_true == 0) & (y_pred == 1) & (abstained == 0)) * 1.0
    abst_loss = np.sum(abstained == 1) * c_abst
    return float((fn_loss + fp_loss + abst_loss) / len(y_true))


def get_all_model_predictions(test_df: pd.DataFrame, gamma_risk: float = 15.0, lambda_cost: float = 0.25) -> Dict[str, Dict[str, np.ndarray]]:
    preds_dict: Dict[str, Dict[str, list]] = {
        "B0_M0": {"y_pred": [], "abstained": [], "costs": []},
        "B1_M1": {"y_pred": [], "abstained": [], "costs": []},
        "B2_M2": {"y_pred": [], "abstained": [], "costs": []},
        "B3_Entropy": {"y_pred": [], "abstained": [], "costs": []},
        "B4_Conservative": {"y_pred": [], "abstained": [], "costs": []},
        "B5_SimpleCost": {"y_pred": [], "abstained": [], "costs": []},
        "B6_RAEA": {"y_pred": [], "abstained": [], "costs": []},
    }
    
    cfg = RAEAConfig(gamma=gamma_risk, lambda_cost=lambda_cost)
    
    for idx, row in test_df.iterrows():
        p0 = float(row["p_m0"])
        p1 = float(row["p_m1"])
        p2 = float(row["p_m2"])
        
        preds_dict["B0_M0"]["y_pred"].append(1 if p0 >= 0.5 else 0)
        preds_dict["B0_M0"]["abstained"].append(0)
        preds_dict["B0_M0"]["costs"].append(0.0)
        
        preds_dict["B1_M1"]["y_pred"].append(1 if p1 >= 0.5 else 0)
        preds_dict["B1_M1"]["abstained"].append(0)
        preds_dict["B1_M1"]["costs"].append(0.20 if row["infra_status"] == "success" else 0.80)
        
        preds_dict["B2_M2"]["y_pred"].append(1 if p2 >= 0.5 else 0)
        preds_dict["B2_M2"]["abstained"].append(0)
        preds_dict["B2_M2"]["costs"].append(
            (0.20 if row["infra_status"] == "success" else 0.80) +
            (0.50 if row["content_status"] == "success" else 1.20)
        )
        
        p_b3, _, abs_b3, st_b3, _ = simulate_b3_entropy_cascade(p0, p1, p2)
        preds_dict["B3_Entropy"]["y_pred"].append(p_b3)
        preds_dict["B3_Entropy"]["abstained"].append(abs_b3)
        preds_dict["B3_Entropy"]["costs"].append(0.20 if st_b3 >= 1 else 0 + (0.50 if st_b3 >= 2 else 0))
        
        p_b4, _, abs_b4, st_b4, _ = simulate_b4_conservative(p0, p1, p2)
        preds_dict["B4_Conservative"]["y_pred"].append(p_b4)
        preds_dict["B4_Conservative"]["abstained"].append(abs_b4)
        preds_dict["B4_Conservative"]["costs"].append(0.20 if st_b4 >= 1 else 0 + (0.50 if st_b4 >= 2 else 0))
        
        p_b5, _, abs_b5, st_b5, _ = simulate_b5_simple_confidence_cost(p0, p1, p2)
        preds_dict["B5_SimpleCost"]["y_pred"].append(p_b5)
        preds_dict["B5_SimpleCost"]["abstained"].append(abs_b5)
        preds_dict["B5_SimpleCost"]["costs"].append(0.20 if st_b5 >= 1 else 0 + (0.50 if st_b5 >= 2 else 0))
        
        offline_item = {
            "infra_status": row["infra_status"],
            "content_status": row["content_status"],
            "p_m0": p0,
            "p_m1": p1,
            "p_m2": p2,
            "lat_infra_ms": float(row["lat_infra_ms"]),
            "lat_content_ms": float(row["lat_content_ms"]),
        }
        x0_dict = {
            "has_ip_host": 1.0 if "http://" in str(row["url"]) and any(c.isdigit() for c in str(row["url"]).split("/")[2].split(":")[0]) else 0.0,
            "uses_https": 1.0 if "https://" in str(row["url"]) else 0.0,
            "p_m0": p0,
            "url_length": float(len(str(row["url"]))),
            "host_length": float(len(str(row["url"]).split("/")[2].split(":")[0])),
        }
        res = run_raea(
            url=str(row["url"]),
            x0_features=x0_dict,
            initial_probability=p0,
            config=cfg,
            offline_data=offline_item,
        )
        preds_dict["B6_RAEA"]["y_pred"].append(1 if res.decision == "phishing" else 0)
        preds_dict["B6_RAEA"]["abstained"].append(1 if res.abstained else 0)
        preds_dict["B6_RAEA"]["costs"].append(res.total_cost)

    return {k: {k2: np.array(v2) for k2, v2 in v.items()} for k, v in preds_dict.items()}


def main():
    print("Iniciando Fase 6: Análisis Estadístico y Pruebas de Hipótesis...")
    test_df = load_evaluation_dataset()
    y_true = test_df["label_int"].values
    N = len(y_true)
    
    preds = get_all_model_predictions(test_df)
    np.random.seed(SEED)
    
    # 1. Intervalos de confianza bootstrap al 95%
    print(f"Generando {B_BOOTSTRAP} remuestreos bootstrap...")
    boot_indices = [np.random.choice(N, size=N, replace=True) for _ in range(B_BOOTSTRAP)]
    
    ci_rows = []
    for m_id, m_dict in preds.items():
        yp = m_dict["y_pred"]
        abs_arr = m_dict["abstained"]
        
        accs, precs, recs, f1s, risks = [], [], [], [], []
        for idxs in boot_indices:
            yt_b = y_true[idxs]
            yp_b = yp[idxs]
            abs_b = abs_arr[idxs]
            
            acc, prec, rec, f1 = fast_metrics(yt_b, yp_b)
            r = fast_weighted_risk(yt_b, yp_b, abs_b, gamma=15.0)
            
            accs.append(acc)
            precs.append(prec)
            recs.append(rec)
            f1s.append(f1)
            risks.append(r)
            
        ci_rows.append({
            "model_id": m_id,
            "metric": "accuracy",
            "point_estimate": float(np.mean(accs)),
            "ci_95_low": float(np.percentile(accs, 2.5)),
            "ci_95_high": float(np.percentile(accs, 97.5)),
            "std_error": float(np.std(accs)),
        })
        ci_rows.append({
            "model_id": m_id,
            "metric": "recall",
            "point_estimate": float(np.mean(recs)),
            "ci_95_low": float(np.percentile(recs, 2.5)),
            "ci_95_high": float(np.percentile(recs, 97.5)),
            "std_error": float(np.std(recs)),
        })
        ci_rows.append({
            "model_id": m_id,
            "metric": "f1_score",
            "point_estimate": float(np.mean(f1s)),
            "ci_95_low": float(np.percentile(f1s, 2.5)),
            "ci_95_high": float(np.percentile(f1s, 97.5)),
            "std_error": float(np.std(f1s)),
        })
        ci_rows.append({
            "model_id": m_id,
            "metric": "weighted_risk",
            "point_estimate": float(np.mean(risks)),
            "ci_95_low": float(np.percentile(risks, 2.5)),
            "ci_95_high": float(np.percentile(risks, 97.5)),
            "std_error": float(np.std(risks)),
        })
        
    ci_df = pd.DataFrame(ci_rows)
    ci_df.to_csv(OUT_DIR / "confidence_intervals.csv", index=False)
    ci_df.to_csv(ROOT / "confidence_intervals.csv", index=False)
    print("Guardado confidence_intervals.csv")

    # 2. Bootstrap Pareado
    print("Calculando diferencias relativas en Bootstrap pareado...")
    boot_diff_rows = []
    raea_pred = preds["B6_RAEA"]["y_pred"]
    raea_abs = preds["B6_RAEA"]["abstained"]
    
    comparators = ["B0_M0", "B1_M1", "B2_M2", "B3_Entropy", "B4_Conservative", "B5_SimpleCost"]
    for comp in comparators:
        comp_pred = preds[comp]["y_pred"]
        comp_abs = preds[comp]["abstained"]
        
        diff_f1, diff_rec, diff_acc, diff_risk = [], [], [], []
        for idxs in boot_indices:
            yt_b = y_true[idxs]
            r_yp_b = raea_pred[idxs]
            c_yp_b = comp_pred[idxs]
            
            _, _, r_rec, r_f1 = fast_metrics(yt_b, r_yp_b)
            _, _, c_rec, c_f1 = fast_metrics(yt_b, c_yp_b)
            r_acc = np.mean(yt_b == r_yp_b)
            c_acc = np.mean(yt_b == c_yp_b)
            
            r_risk = fast_weighted_risk(yt_b, r_yp_b, raea_abs[idxs], gamma=15.0)
            c_risk = fast_weighted_risk(yt_b, c_yp_b, comp_abs[idxs], gamma=15.0)
            
            diff_f1.append(r_f1 - c_f1)
            diff_rec.append(r_rec - c_rec)
            diff_acc.append(r_acc - c_acc)
            diff_risk.append(c_risk - r_risk) # Positivo = RAEA reduce el riesgo
            
        boot_diff_rows.append({
            "comparison": f"B6_RAEA_vs_{comp}",
            "delta_f1_mean": float(np.mean(diff_f1)),
            "delta_f1_ci_low": float(np.percentile(diff_f1, 2.5)),
            "delta_f1_ci_high": float(np.percentile(diff_f1, 97.5)),
            "delta_recall_mean": float(np.mean(diff_rec)),
            "delta_recall_ci_low": float(np.percentile(diff_rec, 2.5)),
            "delta_recall_ci_high": float(np.percentile(diff_rec, 97.5)),
            "delta_weighted_risk_reduction_mean": float(np.mean(diff_risk)),
            "delta_weighted_risk_ci_low": float(np.percentile(diff_risk, 2.5)),
            "delta_weighted_risk_ci_high": float(np.percentile(diff_risk, 97.5)),
            "p_value_bootstrap_risk_reduction": float(np.mean(np.array(diff_risk) <= 0)),
        })
        
    boot_df = pd.DataFrame(boot_diff_rows)
    boot_df.to_csv(OUT_DIR / "bootstrap_results.csv", index=False)
    boot_df.to_csv(ROOT / "bootstrap_results.csv", index=False)
    print("Guardado bootstrap_results.csv")

    # 3. Pruebas de McNemar Pareadas y Corrección de Holm-Bonferroni
    print("Ejecutando pruebas de McNemar pareadas y ajuste Holm-Bonferroni...")
    test_rows = []
    p_values = []
    
    for comp in comparators:
        comp_pred = preds[comp]["y_pred"]
        
        correct_raea = (raea_pred == y_true)
        correct_comp = (comp_pred == y_true)
        
        n_01 = int(np.sum((~correct_raea) & correct_comp))
        n_10 = int(np.sum(correct_raea & (~correct_comp)))
        
        total_discordant = n_01 + n_10
        if total_discordant > 0:
            res_binom = binomtest(n_10, total_discordant, 0.5, alternative="two-sided")
            raw_p = float(res_binom.pvalue)
        else:
            raw_p = 1.0
            
        test_rows.append({
            "comparison": f"B6_RAEA_vs_{comp}",
            "discordant_n10_raea_wins": n_10,
            "discordant_n01_comp_wins": n_01,
            "total_discordant": total_discordant,
            "raw_p_value": raw_p,
        })
        p_values.append(raw_p)

    m_tests = len(p_values)
    sorted_indices = np.argsort(p_values)
    holm_p = np.zeros(m_tests)
    
    running_max = 0.0
    for rank, idx in enumerate(sorted_indices):
        adjusted = min(1.0, p_values[idx] * (m_tests - rank))
        running_max = max(running_max, adjusted)
        holm_p[idx] = running_max
        
    for i, row in enumerate(test_rows):
        row["holm_bonferroni_p_value"] = float(holm_p[i])
        row["statistically_significant_005"] = bool(holm_p[i] < 0.05)

    test_df_out = pd.DataFrame(test_rows)
    test_df_out.to_csv(OUT_DIR / "statistical_tests.csv", index=False)
    test_df_out.to_csv(ROOT / "statistical_tests.csv", index=False)
    print("Guardado statistical_tests.csv")

    # 4. Análisis de Sensibilidad Paramétrica
    print("Ejecutando análisis de sensibilidad paramétrica...")
    sens_rows = []
    for g in [5.0, 10.0, 15.0, 20.0, 30.0]:
        for l in [0.10, 0.25, 0.50]:
            preds_sens = get_all_model_predictions(test_df, gamma_risk=g, lambda_cost=l)
            r_yp = preds_sens["B6_RAEA"]["y_pred"]
            r_abs = preds_sens["B6_RAEA"]["abstained"]
            r_costs = preds_sens["B6_RAEA"]["costs"]
            
            _, _, rec_g, f1_g = fast_metrics(y_true, r_yp)
            w_risk_g = fast_weighted_risk(y_true, r_yp, r_abs, gamma=g)
            
            sens_rows.append({
                "gamma_asymmetry": g,
                "lambda_cost_weight": l,
                "f1_score": f1_g,
                "recall": rec_g,
                "weighted_risk": w_risk_g,
                "mean_cost": float(np.mean(r_costs)),
                "pct_abstained": float(np.mean(r_abs) * 100.0),
            })
            
    sens_df = pd.DataFrame(sens_rows)
    sens_df.to_csv(OUT_DIR / "sensitivity_analysis.csv", index=False)
    sens_df.to_csv(ROOT / "sensitivity_analysis.csv", index=False)
    print("Guardado sensitivity_analysis.csv")

    print("\n=== RESUMEN DE PRUEBAS DE SIGNIFICANCIA (MCNEMAR + HOLM) ===")
    print(test_df_out[["comparison", "discordant_n10_raea_wins", "discordant_n01_comp_wins", "raw_p_value", "holm_bonferroni_p_value", "statistically_significant_005"]].to_string())

    print("\n=== RESUMEN DE BOOTSTRAP PAREADO (DELTA RISK REDUCTION) ===")
    print(boot_df[["comparison", "delta_weighted_risk_reduction_mean", "delta_weighted_risk_ci_low", "delta_weighted_risk_ci_high", "p_value_bootstrap_risk_reduction"]].to_string())

if __name__ == "__main__":
    main()
