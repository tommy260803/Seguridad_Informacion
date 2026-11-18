"""
Script de ReconciliaciÃ³n CientÃ­fica de Abstenciones y Matrices de ConfusiÃ³n para RAEA-Phish.

Genera los artefactos requeridos por la Fase 2 de AuditorÃ­a:
1. artifacts/raea/selective_predictions.csv (N=300 granular, fila por fila)
2. artifacts/raea/abstention_by_class.csv
3. artifacts/raea/selective_metrics.csv
4. artifacts/raea/forced_decision_metrics.csv
"""

from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, brier_score_loss

from phishguard_orchestrator.raea.models import RAEAConfig
from phishguard_orchestrator.raea.engine import run_raea

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "artifacts" / "raea"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("Iniciando FASE 2: ReconciliaciÃ³n de Abstenciones y MÃ©tricas de ClasificaciÃ³n...")

    # 1. Cargar datos
    parts = pd.read_csv(OUT_DIR / "raea_partitions.csv").set_index("cohort2_id")
    preds = pd.read_csv(ROOT / "artifacts" / "corrections_phase2" / "eval" / "probe_predictions.csv").set_index("cohort2_id")
    df = parts.join(preds, lsuffix="_part", rsuffix="_pred")
    test_df = df[df["partition_raea"] == "test_eval"].copy()
    test_df["label_int"] = (test_df["label_part"] == "phishing").astype(int)

    # 2. Ejecutar RAEA sobre test_eval (N=300)
    raea_cfg = RAEAConfig()
    records = []

    for cid, row in test_df.iterrows():
        p0 = float(row["p_m0"])
        p1 = float(row["p_m1"])
        p2 = float(row["p_m2"])
        lat0 = float(row["lat_m0_ms"])
        lat1 = float(row["lat_infra_ms"])
        lat2 = float(row["lat_content_ms"])

        offline_item = {
            "infra_status": row["infra_status"],
            "content_status": row["content_status"],
            "p_m0": p0,
            "p_m1": p1,
            "p_m2": p2,
            "lat_infra_ms": lat1,
            "lat_content_ms": lat2,
        }
        x0_dict = {
            "has_ip_host": 1.0 if "http://" in str(row["url"]) and any(c.isdigit() for c in str(row["url"]).split("/")[2].split(":")[0]) else 0.0,
            "uses_https": 1.0 if "https://" in str(row["url"]) else 0.0,
            "p_m0": p0,
            "url_length": float(len(str(row["url"]))),
            "host_length": float(len(str(row["url"]).split("/")[2].split(":")[0])),
        }

        res = run_raea(str(row["url"]), x0_dict, p0, config=raea_cfg, offline_data=offline_item)

        lat_total = lat0 + (lat1 if "network" in res.modalities_consulted else 0) + (lat2 if "html" in res.modalities_consulted else 0)

        # Decisiones forzadas
        p_last = res.probability_phishing
        is_abs = res.abstained

        # Selectivo: None si se abstiene
        pred_selective = None if is_abs else (1 if res.decision == "phishing" else 0)
        
        # PolÃ­ticas forzadas a cobertura 100%
        pred_fail_open = 0 if is_abs else (1 if res.decision == "phishing" else 0)
        pred_fail_closed = 1 if is_abs else (1 if res.decision == "phishing" else 0)
        pred_forced_threshold = (1 if p_last >= 0.50 else 0) if is_abs else (1 if res.decision == "phishing" else 0)

        records.append({
            "cohort2_id": cid,
            "url": row["url"],
            "ground_truth": row["label_int"],
            "ground_truth_label": row["label_part"],
            "p_m0": p0,
            "p_m1": p1,
            "p_m2": p2,
            "raea_decision": res.decision,
            "raea_probability": p_last,
            "is_abstained": int(is_abs),
            "modalities_consulted": "|".join(res.modalities_consulted),
            "num_modalities": len(res.modalities_consulted),
            "total_cost": res.total_cost,
            "latency_ms": lat_total,
            "pred_selective": pred_selective,
            "pred_fail_open": pred_fail_open,
            "pred_fail_closed": pred_fail_closed,
            "pred_forced_threshold_05": pred_forced_threshold,
        })

    pred_df = pd.DataFrame(records)
    pred_df.to_csv(OUT_DIR / "selective_predictions.csv", index=False)
    print(f"-> Exportado: selective_predictions.csv (N={len(pred_df)})")

    # 3. Desglose de abstenciÃ³n por clase
    abs_df = pred_df[pred_df["is_abstained"] == 1]
    abst_by_class = abs_df.groupby("ground_truth_label").size().reset_index(name="count")
    abst_by_class["percentage_of_abstained"] = (abst_by_class["count"] / len(abs_df)) * 100.0
    abst_by_class["percentage_of_class_total"] = (abst_by_class["count"] / 150.0) * 100.0
    abst_by_class.to_csv(OUT_DIR / "abstention_by_class.csv", index=False)
    print(f"-> Exportado: abstention_by_class.csv (Abstenciones totales = {len(abs_df)})")

    # 4. MÃ©tricas en RÃ©gimen Selectivo (N=240)
    dec_df = pred_df[pred_df["is_abstained"] == 0].copy()
    y_true_sel = dec_df["ground_truth"].values
    y_pred_sel = dec_df["pred_selective"].astype(int).values

    cm_sel = confusion_matrix(y_true_sel, y_pred_sel, labels=[0, 1])
    tn_s, fp_s, fn_s, tp_s = cm_sel.ravel()

    selective_metrics = pd.DataFrame([{
        "regime": "Selective (Decided Subset)",
        "n_total": len(pred_df),
        "n_decided": len(dec_df),
        "n_abstained": len(abs_df),
        "coverage": len(dec_df) / len(pred_df),
        "abstention_rate": len(abs_df) / len(pred_df),
        "tp": int(tp_s),
        "fp": int(fp_s),
        "tn": int(tn_s),
        "fn": int(fn_s),
        "accuracy": accuracy_score(y_true_sel, y_pred_sel),
        "precision": precision_score(y_true_sel, y_pred_sel),
        "recall": recall_score(y_true_sel, y_pred_sel),
        "f1": f1_score(y_true_sel, y_pred_sel),
        "fpr": fp_s / (fp_s + tn_s) if (fp_s + tn_s) > 0 else 0.0,
        "fnr": fn_s / (fn_s + tp_s) if (fn_s + tp_s) > 0 else 0.0,
    }])
    selective_metrics.to_csv(OUT_DIR / "selective_metrics.csv", index=False)
    print("-> Exportado: selective_metrics.csv")

    # 5. MÃ©tricas bajo PolÃ­ticas Forzadas a Cobertura 100% (N=300)
    y_true_all = pred_df["ground_truth"].values
    forced_rows = []

    policies = [
        ("Forced Fail-Open (uncertain -> 0)", "pred_fail_open"),
        ("Forced Fail-Closed (uncertain -> 1)", "pred_fail_closed"),
        ("Forced Threshold at 0.5 (uncertain -> I(p>=0.5))", "pred_forced_threshold_05"),
    ]

    for pol_name, col_name in policies:
        yp = pred_df[col_name].values
        cm = confusion_matrix(y_true_all, yp, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        forced_rows.append({
            "policy_name": pol_name,
            "coverage": 1.0,
            "n_total": len(pred_df),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "accuracy": accuracy_score(y_true_all, yp),
            "precision": precision_score(y_true_all, yp),
            "recall": recall_score(y_true_all, yp),
            "f1": f1_score(y_true_all, yp),
            "fpr": fp / (fp + tn),
            "fnr": fn / (fn + tp),
        })

    forced_df = pd.DataFrame(forced_rows)
    forced_df.to_csv(OUT_DIR / "forced_decision_metrics.csv", index=False)
    print("-> Exportado: forced_decision_metrics.csv")

    print("\nRESUMEN DE RECONCILIACIÃ“N:")
    print("1. RÃ©gimen Selectivo (N=240):")
    print(f"   TP={tp_s}, FP={fp_s}, TN={tn_s}, FN={fn_s} | Acc={selective_metrics['accuracy'].iloc[0]:.4f}, F1={selective_metrics['f1'].iloc[0]:.4f}, Recall={selective_metrics['recall'].iloc[0]:.4f}")
    print("2. Despliegues Forzados (N=300):")
    for _, r in forced_df.iterrows():
        print(f"   - {r['policy_name']}: TP={r['tp']}, FP={r['fp']}, TN={r['tn']}, FN={r['fn']} | F1={r['f1']:.4f}, Acc={r['accuracy']:.4f}")


if __name__ == "__main__":
    main()

