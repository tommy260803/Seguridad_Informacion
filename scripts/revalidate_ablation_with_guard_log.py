"""
RevalidaciÃ³n del Estudio de AblaciÃ³n y Registro Granular de Guardas para RAEA-Phish.

Genera:
1. artifacts/raea/guard_activation_log.csv (registro fila por fila de activaciÃ³n de guardas en M0)
2. artifacts/raea/ablation_revalidated.csv (mÃ©tricas de ablaciÃ³n reconciliadas)
"""

from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from phishguard_orchestrator.raea.models import RAEAConfig
from phishguard_orchestrator.raea.engine import run_raea
from scripts.run_raea_comparative_experiments import (
    compute_weighted_risk,
    load_evaluation_dataset,
    simulate_b3_entropy_cascade,
)

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "artifacts" / "raea"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("Iniciando FASE 6: RevalidaciÃ³n de AblaciÃ³n y Registro Granular de Guardas...")

    test_df = load_evaluation_dataset()
    y_true = test_df["label_int"].values
    N = len(test_df)

    # 1. Registro granular de guardas benignas entre A5 (sin guarda) y A6 (con guarda)
    cfg_a5 = RAEAConfig(enforce_benign_guard=False)
    cfg_a6 = RAEAConfig(enforce_benign_guard=True)

    guard_logs = []

    for cid, row in test_df.iterrows():
        p0 = float(row["p_m0"])
        p1 = float(row["p_m1"])
        p2 = float(row["p_m2"])
        lat1 = float(row["lat_infra_ms"])
        lat2 = float(row["lat_content_ms"])
        y = int(row["label_int"])

        u = str(row["url"])
        has_ip = 1.0 if "http://" in u and any(c.isdigit() for c in u.split("/")[2].split(":")[0]) else 0.0
        uses_https = 1.0 if "https://" in u else 0.0
        url_len = float(len(u))
        host_len = float(len(u.split("/")[2].split(":")[0]))

        x0_dict = {
            "has_ip_host": has_ip,
            "uses_https": uses_https,
            "p_m0": p0,
            "url_length": url_len,
            "host_length": host_len,
        }
        offline_item = {
            "infra_status": row["infra_status"],
            "content_status": row["content_status"],
            "p_m0": p0,
            "p_m1": p1,
            "p_m2": p2,
            "lat_infra_ms": lat1,
            "lat_content_ms": lat2,
        }

        # ComprobaciÃ³n de condiciÃ³n de guarda en M0
        # Guarda activa si p0 > 0.02 o has_lexical_risk
        has_lexical_risk = (has_ip == 1.0) or (uses_https == 0.0) or (url_len > 75.0)
        guard_fired = (p0 > 0.02) or has_lexical_risk

        # EjecuciÃ³n A5 (sin guarda)
        res_a5 = run_raea(u, x0_dict, p0, config=cfg_a5, offline_data=offline_item)
        # EjecuciÃ³n A6 (con guarda)
        res_a6 = run_raea(u, x0_dict, p0, config=cfg_a6, offline_data=offline_item)

        guard_logs.append({
            "cohort2_id": cid,
            "url": u,
            "ground_truth": y,
            "p_m0": p0,
            "has_lexical_risk": int(has_lexical_risk),
            "guard_fired_in_A6": int(guard_fired),
            "decision_A5_no_guard": res_a5.decision,
            "decision_A6_full": res_a6.decision,
            "mods_A5": "|".join(res_a5.modalities_consulted),
            "mods_A6": "|".join(res_a6.modalities_consulted),
            "stage_A5": len(res_a5.modalities_consulted) - 1,
            "stage_A6": len(res_a6.modalities_consulted) - 1,
            "discrepancy": int(res_a5.decision != res_a6.decision or res_a5.modalities_consulted != res_a6.modalities_consulted),
        })

    guard_df = pd.DataFrame(guard_logs)
    guard_df.to_csv(OUT_DIR / "guard_activation_log.csv", index=False)
    print(f"-> Exportado: guard_activation_log.csv (N={len(guard_df)}, Discrepancias={guard_df['discrepancy'].sum()})")

    # 2. EvaluaciÃ³n sistemÃ¡tica de todas las variantes de ablaciÃ³n
    variants = [
        ("A0", "Cascada Original (EntropÃ­a M5)", None, True, False),
        ("A1", "RAEA sin Estimador de Disponibilidad", RAEAConfig(enable_availability=False), False, False),
        ("A2", "RAEA sin Costes AsimÃ©tricos (gamma=1)", RAEAConfig(enable_asymmetric_cost=False), False, False),
        ("A3", "RAEA sin Mecanismo de AbstenciÃ³n", RAEAConfig(enable_abstention=False), False, False),
        ("A4", "RAEA sin Beneficio Informativo Esperado", RAEAConfig(enable_information_value=False), False, False),
        ("A5", "RAEA sin Guarda Benigna en M0", cfg_a5, False, False),
        ("A6", "RAEA Completo", cfg_a6, False, False),
        ("A7", "M2 Forzado Completo", None, False, True),
    ]

    abl_rows = []

    for var_id, var_name, cfg, is_a0, is_a7 in variants:
        yp_list, abs_list, mods_list, cost_list, stage0_fn = [], [], [], [], 0

        for cid, row in test_df.iterrows():
            p0 = float(row["p_m0"])
            p1 = float(row["p_m1"])
            p2 = float(row["p_m2"])
            y = int(row["label_int"])

            if is_a0:
                pred, prob, abs_val, stage, mods = simulate_b3_entropy_cascade(p0, p1, p2)
                c = 0.0 + (0.20 if stage >= 1 else 0) + (0.50 if stage >= 2 else 0)
                yp_list.append(pred)
                abs_list.append(abs_val)
                mods_list.append(mods)
                cost_list.append(c)
                if y == 1 and pred == 0 and stage == 0:
                    stage0_fn += 1
            elif is_a7:
                pred = 1 if p2 >= 0.50 else 0
                c = (0.20 if row["infra_status"] == "success" else 0.80) + (0.50 if row["content_status"] == "success" else 1.20)
                yp_list.append(pred)
                abs_list.append(0)
                mods_list.append(["url", "network", "html"])
                cost_list.append(c)
            else:
                u = str(row["url"])
                x0 = {
                    "has_ip_host": 1.0 if "http://" in u and any(c.isdigit() for c in u.split("/")[2].split(":")[0]) else 0.0,
                    "uses_https": 1.0 if "https://" in u else 0.0,
                    "p_m0": p0,
                    "url_length": float(len(u)),
                    "host_length": float(len(u.split("/")[2].split(":")[0])),
                }
                offline = {
                    "infra_status": row["infra_status"],
                    "content_status": row["content_status"],
                    "p_m0": p0,
                    "p_m1": p1,
                    "p_m2": p2,
                    "lat_infra_ms": float(row["lat_infra_ms"]),
                    "lat_content_ms": float(row["lat_content_ms"]),
                }
                res = run_raea(u, x0, p0, config=cfg, offline_data=offline)
                pred = 1 if res.decision == "phishing" else 0
                yp_list.append(pred)
                abs_list.append(1 if res.abstained else 0)
                mods_list.append(res.modalities_consulted)
                cost_list.append(res.total_cost)
                if y == 1 and pred == 0 and len(res.modalities_consulted) == 1:
                    stage0_fn += 1

        yp_arr = np.array(yp_list)
        abs_arr = np.array(abs_list)

        cm = confusion_matrix(y_true, yp_arr, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        w_risk = compute_weighted_risk(y_true, yp_arr, abs_arr, gamma=15.0)

        # MÃ©tricas selectivas
        dec_mask = (abs_arr == 0)
        n_dec = int(dec_mask.sum())
        cov = n_dec / N
        f1_sel = f1_score(y_true[dec_mask], yp_arr[dec_mask]) if n_dec > 0 else 0.0

        abl_rows.append({
            "variant_id": var_id,
            "variant_name": var_name,
            "coverage": cov,
            "pct_abstained": float(np.mean(abs_arr) * 100.0),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "fn_stage0": stage0_fn,
            "accuracy": accuracy_score(y_true, yp_arr),
            "precision": precision_score(y_true, yp_arr, zero_division=0),
            "recall": recall_score(y_true, yp_arr, zero_division=0),
            "f1_full": f1_score(y_true, yp_arr, zero_division=0),
            "f1_selective": f1_sel,
            "mean_modalities": float(np.mean([len(m) for m in mods_list])),
            "mean_cost": float(np.mean(cost_list)),
            "weighted_risk": w_risk,
        })

    abl_df = pd.DataFrame(abl_rows)
    abl_df.to_csv(OUT_DIR / "ablation_revalidated.csv", index=False)
    print("-> Exportado: ablation_revalidated.csv")

    print("\nRESUMEN REVALIDADO DE ABLACIÃ“N:")
    for _, r in abl_df.iterrows():
        print(f"[{r['variant_id']}] {r['variant_name']} | F1_full={r['f1_full']:.4f} | F1_sel={r['f1_selective']:.4f} | FN_st0={r['fn_stage0']} | Risk={r['weighted_risk']:.4f}")


if __name__ == "__main__":
    main()

