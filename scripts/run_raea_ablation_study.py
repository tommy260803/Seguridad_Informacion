"""Estudio sistemático de ablación de componentes para RAEA-Phish (Fase 5).

Variantes evaluadas:
- A0: Cascada original (Entropía M5)
- A1: RAEA sin estimador de disponibilidad (enable_availability=False, asume 100%)
- A2: RAEA sin costes asimétricos (enable_asymmetric_cost=False, gamma=1.0)
- A3: RAEA sin abstención (enable_abstention=False)
- A4: RAEA sin beneficio informativo esperado (enable_information_value=False)
- A5: RAEA sin guarda contra salida benigna prematura (enforce_benign_guard=False)
- A6: RAEA Completo
- A7: M2 Forzado Completo
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.evaluation import expected_calibration_error
from phishguard_orchestrator.raea.models import RAEAConfig
from phishguard_orchestrator.raea.engine import run_raea
from scripts.run_raea_comparative_experiments import (
    compute_weighted_risk,
    load_evaluation_dataset,
    simulate_b3_entropy_cascade,
)

OUT_DIR = ROOT / "artifacts" / "raea"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def evaluate_variant(
    variant_id: str,
    variant_name: str,
    config: RAEAConfig | None,
    test_df: pd.DataFrame,
    is_a0: bool = False,
    is_a7: bool = False,
) -> Dict[str, Any]:
    y_true = test_df["label_int"].values
    y_preds, y_probs, abstained_list, stages_list, modalities_counts, costs_list = [], [], [], [], [], []

    for idx, row in test_df.iterrows():
        p0 = float(row["p_m0"])
        p1 = float(row["p_m1"])
        p2 = float(row["p_m2"])
        
        if is_a0:
            pred, prob, abs_val, stage, mods = simulate_b3_entropy_cascade(p0, p1, p2)
            c = 0.0 + (0.20 if stage >= 1 else 0) + (0.50 if stage >= 2 else 0)
            y_preds.append(pred)
            y_probs.append(prob)
            abstained_list.append(abs_val)
            stages_list.append(stage)
            modalities_counts.append(len(mods))
            costs_list.append(c)
        elif is_a7:
            y_preds.append(1 if p2 >= 0.5 else 0)
            y_probs.append(p2)
            abstained_list.append(0)
            stages_list.append(2)
            modalities_counts.append(3)
            c = (0.20 if row["infra_status"] == "success" else 0.80) + (0.50 if row["content_status"] == "success" else 1.20)
            costs_list.append(c)
        else:
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
                config=config,
                offline_data=offline_item,
            )
            pred = 1 if res.decision == "phishing" else 0
            y_preds.append(pred)
            y_probs.append(res.probability_phishing)
            abstained_list.append(1 if res.abstained else 0)
            stages_list.append(len(res.modalities_consulted) - 1)
            modalities_counts.append(len(res.modalities_consulted))
            costs_list.append(res.total_cost)

    y_p = np.array(y_preds)
    y_pr = np.array(y_probs)
    abs_arr = np.array(abstained_list)
    stages = np.array(stages_list)

    cm = confusion_matrix(y_true, y_p, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    
    # Falsos negativos en etapa 0
    fn_mask = (y_true == 1) & (y_p == 0)
    fn_stage0 = int(np.sum(fn_mask & (stages == 0)))

    return {
        "variant_id": variant_id,
        "variant_name": variant_name,
        "accuracy": accuracy_score(y_true, y_p),
        "precision": precision_score(y_true, y_p, zero_division=0),
        "recall": recall_score(y_true, y_p, zero_division=0),
        "f1": f1_score(y_true, y_p, zero_division=0),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "fn_at_stage0": fn_stage0,
        "pct_abstained": float(np.mean(abs_arr) * 100.0),
        "mean_modalities": float(np.mean(modalities_counts)),
        "mean_cost": float(np.mean(costs_list)),
        "weighted_risk": compute_weighted_risk(y_true, y_p, abs_arr, gamma=15.0),
    }


def main():
    print("Iniciando Fase 5: Estudio de Ablación de Componentes...")
    test_df = load_evaluation_dataset()
    
    variants = [
        ("A0", "Cascada Original (Entropía M5)", None, True, False),
        ("A1", "RAEA sin Estimador de Disponibilidad", RAEAConfig(enable_availability=False), False, False),
        ("A2", "RAEA sin Costes Asimétricos (gamma=1)", RAEAConfig(enable_asymmetric_cost=False), False, False),
        ("A3", "RAEA sin Mecanismo de Abstención", RAEAConfig(enable_abstention=False), False, False),
        ("A4", "RAEA sin Beneficio Informativo Esperado", RAEAConfig(enable_information_value=False), False, False),
        ("A5", "RAEA sin Guarda Benigna en M0", RAEAConfig(enforce_benign_guard=False), False, False),
        ("A6", "RAEA Completo", RAEAConfig(), False, False),
        ("A7", "M2 Ejecutado Completamente", None, False, True),
    ]

    results = []
    for var_id, var_name, cfg, is_a0, is_a7 in variants:
        print(f"Evaluando variante {var_id}: {var_name}...")
        res = evaluate_variant(var_id, var_name, cfg, test_df, is_a0=is_a0, is_a7=is_a7)
        results.append(res)

    res_df = pd.DataFrame(results)
    res_df.to_csv(OUT_DIR / "ablation_results.csv", index=False)
    res_df.to_csv(ROOT / "ablation_results.csv", index=False)
    print("Guardado ablation_results.csv")

    # Contribución relativa de cada componente frente a RAEA Completo (A6)
    a6_res = res_df[res_df["variant_id"] == "A6"].iloc[0]
    contrib_rows = []
    
    component_map = [
        ("Disponibilidad de Modalidades (pi_m)", "A1"),
        ("Costes Asimétricos (gamma=15)", "A2"),
        ("Mecanismo de Abstención", "A3"),
        ("Valor Informativo Esperado", "A4"),
        ("Guarda Benigna en M0", "A5"),
    ]
    
    for comp_name, var_id in component_map:
        var_res = res_df[res_df["variant_id"] == var_id].iloc[0]
        delta_f1 = float(a6_res["f1"] - var_res["f1"])
        delta_risk = float(var_res["weighted_risk"] - a6_res["weighted_risk"])
        delta_fn = int(var_res["fn"] - a6_res["fn"])
        delta_fn0 = int(var_res["fn_at_stage0"] - a6_res["fn_at_stage0"])
        delta_cost = float(var_res["mean_cost"] - a6_res["mean_cost"])
        
        contrib_rows.append({
            "component": comp_name,
            "ablated_variant": var_id,
            "delta_f1_gain": delta_f1,
            "delta_weighted_risk_reduction": delta_risk,
            "false_negatives_prevented": delta_fn,
            "premature_fn_prevented_stage0": delta_fn0,
            "cost_overhead_or_saving": delta_cost,
        })
        
    contrib_df = pd.DataFrame(contrib_rows)
    contrib_df.to_csv(OUT_DIR / "component_contribution.csv", index=False)
    contrib_df.to_csv(ROOT / "component_contribution.csv", index=False)
    print("Guardado component_contribution.csv")

    print("\n=== RESUMEN EJECUTIVO DE ABLACIONES ===")
    print(res_df[["variant_id", "variant_name", "f1", "recall", "fn", "fn_at_stage0", "weighted_risk", "mean_modalities", "mean_cost"]].to_string())

if __name__ == "__main__":
    main()
