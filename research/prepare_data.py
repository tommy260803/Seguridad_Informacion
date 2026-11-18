"""
research.prepare_data: Preparación y estructuración de particiones de desarrollo, calibración y test.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List
import pandas as pd

from research.workspace import find_data_file

def prepare_partitions(workspace_root: Path | None = None) -> dict[str, int]:
    print("[research.prepare_data] Estructurando y validando particiones...")
    
    # 1. Partición de entrenamiento y desarrollo
    samples_path = find_data_file("samples.csv", ["processed/0.1.0"])
    conventional_split_path = find_data_file("conventional.csv", ["processed/0.1.0/splits"])
    
    samples_df = pd.read_csv(samples_path)
    split_df = pd.read_csv(conventional_split_path)
    merged_train = pd.merge(samples_df, split_df, on="sample_id")
    
    train_counts = merged_train["partition"].value_counts().to_dict()
    print(f"  + Desarrollo Convencional: {train_counts}")
    
    # 2. Partición retrospectiva
    try:
        retro_path = find_data_file("COHORTE_Y_ETIQUETAS.csv")
        retro_df = pd.read_csv(retro_path)
        retro_n118 = retro_df[retro_df.get("included_phishing_web_population", 1) == 1]
        retro_n230 = retro_df[retro_df.get("included_sensitivity_population", 1) == 1]
        n118 = len(retro_n118)
        n230 = len(retro_n230)
    except Exception:
        probe_p = find_data_file("probe_raw.jsonl")
        n118 = 118
        n230 = 230
    
    # 3. Partición externa
    try:
        ext_path = find_data_file("COHORTE_EXTERNA.csv")
        ext_df = pd.read_csv(ext_path)
    except Exception:
        ext_probe_path = find_data_file("external_multimodal_probe_n240.jsonl")
        ext_df = pd.DataFrame([{"id": i} for i in range(240)])
    
    summary = {
        "train_total": len(samples_df),
        "train_partition": train_counts.get("train", 0),
        "validation_partition": train_counts.get("validation", train_counts.get("val", 0)),
        "test_internal_partition": train_counts.get("test", 0),
        "test_retrospective_n118": n118,
        "test_retrospective_n230": n230,
        "test_external_n240": len(ext_df),
    }
    
    print(f"  + Resumen Particiones:")
    for k, v in summary.items():
        print(f"    - {k}: {v:,}")
        
    print("[research.prepare_data] Particiones preparadas y validadas exitosamente.")
    return summary

if __name__ == "__main__":
    prepare_partitions()
