"""
Script de Auditoría y Descomposición del Riesgo Ponderado para RAEA-Phish.

Genera:
1. artifacts/raea/risk_recalculation.csv (comparativa de todas las definiciones de riesgo)
2. artifacts/raea/risk_decomposition.csv (desglose de pérdida de clasificación, adquisición y abstención)
3. artifacts/raea/cost_sensitivity.csv (análisis de sensibilidad variando gamma y c_abst)
"""

from pathlib import Path
import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "artifacts" / "raea"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("Iniciando FASE 3: Auditoría y Descomposición Rigurosa del Riesgo...")

    # Cargar datos de predicciones selectivas reconciliadas
    pred_df = pd.read_csv(OUT_DIR / "selective_predictions.csv")
    base_df = pd.read_csv(OUT_DIR / "baseline_comparison.csv").set_index("model_id")

    N = len(pred_df)  # 300
    y_true = pred_df["ground_truth"].values

    gamma = 15.0
    c_fp = 1.0
    c_abst = 0.35
    lambda_c = 0.25

    # 1. Recalculación sistemática de definiciones de riesgo
    # Baselines
    models = [
        ("B0_M0_Fixed", "M0 Fijo", 0.0),
        ("B1_M1_Fixed", "M1 Fijo", 0.3800),
        ("B2_M2_Fixed", "M2 Fijo", 1.2860),
        ("B3_Entropy_Cascade", "Cascada Entropía", 0.3447),
        ("B4_Conservative", "Cascada Conservadora", 0.3447),
        ("B5_Simple_Cost", "Cascada Coste Simple", 0.1410),
    ]

    risk_rows = []

    for mid, mname, mean_acq_cost in models:
        row_b = base_df.loc[mid]
        tp = int(row_b["tp"])
        fp = int(row_b["fp"])
        tn = int(row_b["tn"])
        fn = int(row_b["fn"])
        cov = float(row_b["coverage"])
        pct_abs = float(row_b["pct_abstained"])
        n_abs = int(round(pct_abs * N / 100.0))
        n_dec = N - n_abs

        # Pérdida de clasificación pura (asumiendo 0 para aciertos)
        class_loss = (gamma * fn + c_fp * fp)
        r_class = class_loss / N

        # Riesgo selectivo con penalización de abstención
        # Para cascadas con abstención previa
        r_sel_pen = (class_loss + n_abs * c_abst) / N if n_abs > 0 else r_class
        r_cond = class_loss / n_dec if n_dec > 0 else float("nan")
        r_oper = r_sel_pen + lambda_c * mean_acq_cost

        risk_rows.append({
            "model_id": mid,
            "model_name": mname,
            "coverage": cov,
            "n_decided": n_dec,
            "n_abstained": n_abs,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "r_pure_class": r_class,
            "r_selective_penalty": r_sel_pen,
            "r_conditional": r_cond,
            "mean_acq_cost": mean_acq_cost,
            "r_operational": r_oper,
        })

    # RAEA Selectivo (con abstenciones reconocidas)
    dec_df = pred_df[pred_df["is_abstained"] == 0]
    n_abs_raea = int(pred_df["is_abstained"].sum())
    n_dec_raea = len(dec_df)
    tp_r_sel = int(((dec_df["ground_truth"] == 1) & (dec_df["pred_selective"] == 1)).sum())
    fp_r_sel = int(((dec_df["ground_truth"] == 0) & (dec_df["pred_selective"] == 1)).sum())
    tn_r_sel = int(((dec_df["ground_truth"] == 0) & (dec_df["pred_selective"] == 0)).sum())
    fn_r_sel = int(((dec_df["ground_truth"] == 1) & (dec_df["pred_selective"] == 0)).sum())

    raea_mean_cost = float(pred_df["total_cost"].mean())

    loss_dec = gamma * fn_r_sel + c_fp * fp_r_sel
    loss_abs = n_abs_raea * c_abst
    r_sel_pen_raea = (loss_dec + loss_abs) / N
    r_cond_raea = loss_dec / n_dec_raea
    r_oper_raea = r_sel_pen_raea + lambda_c * raea_mean_cost

    risk_rows.append({
        "model_id": "B6_RAEA_Selective",
        "model_name": "RAEA-Phish (Selectivo)",
        "coverage": n_dec_raea / N,
        "n_decided": n_dec_raea,
        "n_abstained": n_abs_raea,
        "tp": tp_r_sel,
        "fp": fp_r_sel,
        "tn": tn_r_sel,
        "fn": fn_r_sel,
        "r_pure_class": (gamma * fn_r_sel + c_fp * fp_r_sel) / N,
        "r_selective_penalty": r_sel_pen_raea,
        "r_conditional": r_cond_raea,
        "mean_acq_cost": raea_mean_cost,
        "r_operational": r_oper_raea,
    })

    # RAEA Políticas Forzadas a Cobertura 100%
    forced_variants = [
        ("B6_RAEA_Forced_FailOpen", "RAEA Forzado Fail-Open", "pred_fail_open"),
        ("B6_RAEA_Forced_FailClosed", "RAEA Forzado Fail-Closed", "pred_fail_closed"),
        ("B6_RAEA_Forced_Threshold05", "RAEA Forzado Umbral 0.5", "pred_forced_threshold_05"),
    ]

    for f_id, f_name, f_col in forced_variants:
        yp = pred_df[f_col].values
        tp_f = int(((y_true == 1) & (yp == 1)).sum())
        fp_f = int(((y_true == 0) & (yp == 1)).sum())
        tn_f = int(((y_true == 0) & (yp == 0)).sum())
        fn_f = int(((y_true == 1) & (yp == 0)).sum())

        loss_f = gamma * fn_f + c_fp * fp_f
        r_class_f = loss_f / N
        r_oper_f = r_class_f + lambda_c * raea_mean_cost

        risk_rows.append({
            "model_id": f_id,
            "model_name": f_name,
            "coverage": 1.0,
            "n_decided": N,
            "n_abstained": 0,
            "tp": tp_f,
            "fp": fp_f,
            "tn": tn_f,
            "fn": fn_f,
            "r_pure_class": r_class_f,
            "r_selective_penalty": r_class_f,
            "r_conditional": r_class_f,
            "mean_acq_cost": raea_mean_cost,
            "r_operational": r_oper_f,
        })

    risk_df = pd.DataFrame(risk_rows)
    risk_df.to_csv(OUT_DIR / "risk_recalculation.csv", index=False)
    print("-> Exportado: risk_recalculation.csv")

    # 2. Descomposición de Pérdida
    decomp_rows = []
    for _, r in risk_df.iterrows():
        loss_fn_total = gamma * r["fn"]
        loss_fp_total = c_fp * r["fp"]
        loss_abs_total = r["n_abstained"] * c_abst
        acq_cost_total = r["mean_acq_cost"] * N * lambda_c
        total_risk_scaled = loss_fn_total + loss_fp_total + loss_abs_total + acq_cost_total

        decomp_rows.append({
            "model_id": r["model_id"],
            "model_name": r["model_name"],
            "loss_fn_share_pct": (loss_fn_total / total_risk_scaled) * 100.0 if total_risk_scaled > 0 else 0,
            "loss_fp_share_pct": (loss_fp_total / total_risk_scaled) * 100.0 if total_risk_scaled > 0 else 0,
            "loss_abst_share_pct": (loss_abs_total / total_risk_scaled) * 100.0 if total_risk_scaled > 0 else 0,
            "acq_cost_share_pct": (acq_cost_total / total_risk_scaled) * 100.0 if total_risk_scaled > 0 else 0,
            "raw_total_loss_sum": (loss_fn_total + loss_fp_total + loss_abs_total),
            "normalized_mean_risk": (loss_fn_total + loss_fp_total + loss_abs_total) / N,
        })
    decomp_df = pd.DataFrame(decomp_rows)
    decomp_df.to_csv(OUT_DIR / "risk_decomposition.csv", index=False)
    print("-> Exportado: risk_decomposition.csv")

    # 3. Análisis de Sensibilidad (Barrido de gamma y c_abst)
    gammas = [1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 30.0, 50.0]
    c_absts = [0.10, 0.25, 0.35, 0.50, 1.00, 2.00, 5.00]

    sens_rows = []
    for g in gammas:
        for ca in c_absts:
            # Riesgo M1 Fijo (FN=25, FP=20, Abst=0)
            risk_m1 = (g * 25 + 1.0 * 20) / N
            # Riesgo RAEA Selectivo (FN=5, FP=20, Abst=60)
            risk_raea_sel = (g * 5 + 1.0 * 20 + 60 * ca) / N
            # Riesgo RAEA Fail-Closed (FN=5, FP=60, Abst=0)
            risk_raea_fc = (g * 5 + 1.0 * 60) / N
            # Riesgo RAEA Threshold 0.5 (FN=23, FP=22, Abst=0)
            risk_raea_th = (g * 23 + 1.0 * 22) / N

            sens_rows.append({
                "gamma": g,
                "c_abstain": ca,
                "risk_m1_fixed": risk_m1,
                "risk_raea_selective": risk_raea_sel,
                "risk_raea_fail_closed": risk_raea_fc,
                "risk_raea_threshold_05": risk_raea_th,
                "raea_selective_vs_m1_diff": risk_raea_sel - risk_m1,
                "raea_selective_advantage_pct": ((risk_m1 - risk_raea_sel) / risk_m1) * 100.0 if risk_m1 > 0 else 0,
            })
    sens_df = pd.DataFrame(sens_rows)
    sens_df.to_csv(OUT_DIR / "cost_sensitivity.csv", index=False)
    print("-> Exportado: cost_sensitivity.csv")

    print("\nRESUMEN DE RIESGO RECUPERADO:")
    for _, r in risk_df.iterrows():
        print(f"[{r['model_id']}] R_class={r['r_pure_class']:.4f} | R_selective_pen={r['r_selective_penalty']:.4f} | R_oper={r['r_operational']:.4f}")


if __name__ == "__main__":
    main()
