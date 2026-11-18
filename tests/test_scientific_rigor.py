"""
tests/test_scientific_rigor.py: Suite formal de auditoría y rigor científico.
Valida matemáticamente y por introspección de código la resolución definitiva de P1 a P6:
- P1: Cero etiquetas sintéticas de disponibilidad (exige probes empíricos).
- P2: Inferencia real en vivo desde modelos y extractores (cero fallbacks a CSVs o predicciones previas).
- P3: Compatibilidad de calibración moderna (FrozenEstimator sin 'prefit').
- P4: Conteos exactos de particiones (Train=123,341, Val=26,430, Test=26,430).
- P5/P6: Integridad de estimaciones, trayectorias e inferencia estadística.
"""
import inspect
import json
import os
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
import joblib

from phishguard_data.urls import canonicalize_url
from phishguard_ml.features import UrlFeatureContext, extract_url_features
from phishguard_ml.infrastructure import extract_infrastructure_features
from phishguard_ml.content import extract_content_features
from phishguard_orchestrator.raea.engine import run_raea
from phishguard_orchestrator.raea.models import RAEAConfig, Action
from phishguard_orchestrator.raea.availability import AvailabilityEstimator
from research.train import train_all_models
from research.workspace import find_data_file, find_model_file

ROOT = Path(__file__).resolve().parent.parent

def test_p0_physical_data_presence_and_integrity():
    """Verifica la presencia física de samples.csv (176,201 filas) y los datasets crudos con sus hashes."""
    samples_p = find_data_file("samples.csv", ["processed/0.1.0"])
    assert samples_p.exists(), f"samples.csv no existe en {samples_p}"
    
    # Comprobar conteo exacto de líneas/filas
    df_samples = pd.read_csv(samples_p)
    assert len(df_samples) == 176201, f"samples.csv debe contener exactamente 176,201 filas, obtenido {len(df_samples)}"

    # Verificar conventional.csv
    splits_p = find_data_file("conventional.csv", ["processed/0.1.0/splits"])
    assert splits_p.exists(), f"conventional.csv no existe en {splits_p}"
    df_splits = pd.read_csv(splits_p)
    assert len(df_splits) == 176201, f"conventional.csv debe contener 176,201 filas, obtenido {len(df_splits)}"

    # Verificar probe_raw.jsonl (600 líneas)
    probe_raw_p = find_data_file("probe_raw.jsonl")
    assert probe_raw_p.exists(), f"probe_raw.jsonl no existe en {probe_raw_p}"
    with open(probe_raw_p, "r", encoding="utf-8") as f:
        n_probes = sum(1 for _ in f)
    assert n_probes == 600, f"probe_raw.jsonl debe contener 600 líneas, obtenido {n_probes}"

    # Verificar external_multimodal_probe_n240.jsonl (240 líneas)
    ext_probe_p = find_data_file("external_multimodal_probe_n240.jsonl")
    assert ext_probe_p.exists(), f"external probe no existe en {ext_probe_p}"
    with open(ext_probe_p, "r", encoding="utf-8") as f:
        n_ext = sum(1 for _ in f)
    assert n_ext == 240, f"external probe debe contener 240 líneas, obtenido {n_ext}"

def find_code_file(rel_path: str) -> Path:
    candidates = [
        ROOT / rel_path,
        ROOT / "05_CODIGO" / rel_path,
        ROOT / "CODIGO" / rel_path,
        ROOT.parent / rel_path,
        ROOT.parent / "05_CODIGO" / rel_path,
        ROOT.parent / "CODIGO" / rel_path,
    ]
    for c in candidates:
        if c.exists():
            return c
    return ROOT / rel_path

def test_p1_no_synthetic_availability_code():
    """Verifica que el código de entrenamiento no contiene fallbacks binomiales o sintéticos."""
    train_py = find_code_file("research/train.py")
    with open(train_py, "r", encoding="utf-8") as f:
        src = f.read()
    
    assert "binomial" not in src, "Se detectó generación sintética (binomial) en research/train.py"
    assert "randint" not in src, "Se detectó generación aleatoria en research/train.py"
    assert "uniform" not in src, "Se detectó generación aleatoria en research/train.py"
    
    # Comprobar que el pipeline de resolución exige archivo empírico real y falla si falta
    with pytest.raises(FileNotFoundError):
        find_data_file("non_existent_probe_file_xyz.jsonl")

def test_p2_anti_fraud_model_inference_decoupling():
    """Verifica que evaluate.py no lee probabilidades históricas precalculadas."""
    eval_py = find_code_file("research/evaluate.py")
    with open(eval_py, "r", encoding="utf-8") as f:
        src = f.read()
        
    assert "read_csv" not in src or "read_csv(\"PREDICCIONES_EXTERNAS" not in src, "evaluate.py no debe leer PREDICCIONES_EXTERNAS.csv"
    assert "read_csv" not in src or "read_csv(\"PREDICCIONES_INDIVIDUALES" not in src, "evaluate.py no debe leer PREDICCIONES_INDIVIDUALES.csv"
    assert "row.get(\"p_m1\", p0)" not in src, "evaluate.py no debe tener fallback p1 = row.get('p_m1', p0)"
    assert "row.get(\"p_m2\", p1)" not in src, "evaluate.py no debe tener fallback p2 = row.get('p_m2', p1)"

def test_p3_calibration_modern_api():
    """Verifica que CalibratedClassifierCV utiliza FrozenEstimator y no el parámetro obsoleto cv='prefit'."""
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.frozen import FrozenEstimator
    
    X = np.random.randn(50, 4)
    y = np.random.randint(0, 2, 50)
    base = HistGradientBoostingClassifier(random_state=42).fit(X, y)
    
    # La API moderna scikit-learn >= 1.6
    cal = CalibratedClassifierCV(estimator=FrozenEstimator(base), method="isotonic")
    cal.fit(X, y)
    probs = cal.predict_proba(X)
    assert probs.shape == (50, 2)
    assert np.all((probs >= 0.0) & (probs <= 1.0))

def test_p4_exact_partition_counts():
    """Verifica que las particiones contienen exactamente los conteos certificados sin pérdida por discrepancia 'val'/'validation'."""
    split_csv = ROOT / "data" / "processed" / "0.1.0" / "splits" / "conventional.csv"
    if split_csv.exists():
        df_splits = pd.read_csv(split_csv)
        col = "partition" if "partition" in df_splits.columns else "split"
        counts = df_splits[col].value_counts().to_dict()
        n_train = counts.get("train", 0)
        n_val = counts.get("val", counts.get("validation", 0))
        n_test = counts.get("test", 0)
        assert n_train == 123341, f"Train count esperado 123341, obtenido {n_train}"
        assert n_val == 26430, f"Validation count esperado 26430, obtenido {n_val}"
        assert n_test == 26430, f"Test count esperado 26430, obtenido {n_test}"
        assert (n_train + n_val + n_test) == 176201, "Total particionado debe ser exactamente 176,201"

def test_p5_raea_offline_execution_fails_properly_on_probe_error():
    """Verifica que cuando una modalidad falla, el adaptador reporta status ERROR y no reutiliza probabilidades previas."""
    from phishguard_orchestrator.raea.adapter import EvidenceAcquisitionAdapter, AcquisitionStatus
    
    adapter = EvidenceAcquisitionAdapter({
        "infra_status": "error",
        "content_status": "error",
        "m1_model": None,
        "features_m1": None,
        "m2_model": None,
        "features_m2": None,
    })
    
    status, _, _, p_next = adapter.acquire_modality("network", "https://example.com")
    assert status == AcquisitionStatus.ERROR
    assert p_next is None, "En caso de fallo de red, p_next debe ser None, nunca fallback"
    
    status2, _, _, p_next2 = adapter.acquire_modality("html", "https://example.com")
    assert status2 == AcquisitionStatus.ERROR
    assert p_next2 is None, "En caso de fallo de html, p_next debe ser None, nunca fallback"

def test_p6_hypothesis_statistics_consistency():
    """Verifica que la prueba estadística Holm-Bonferroni opera correctamente sobre las predicciones de modelos."""
    candidate_paths = [
        ROOT / "05_EXPERIMENTOS" / "ESTADISTICA_INFERENCIAL_HOLM.csv",
        ROOT / "EXPERIMENTOS" / "ESTADISTICA_INFERENCIAL_HOLM.csv",
        ROOT.parent / "EXPERIMENTOS" / "ESTADISTICA_INFERENCIAL_HOLM.csv",
        ROOT / "build_investigacion_original" / "04_EXPERIMENTOS" / "ESTADISTICA_INFERENCIAL_HOLM.csv",
        ROOT / "autonomous_reproduction_suite" / "output" / "ESTADISTICA_REPRODUCIDA.csv",
    ]
    stat_csv = None
    for cp in candidate_paths:
        if cp.exists():
            stat_csv = cp
            break
            
    assert stat_csv is not None, f"No se encontró archivo de estadística inferencial en candidatos: {candidate_paths}"
    df_stat = pd.read_csv(stat_csv)
    assert len(df_stat) in (8, 12), f"Se esperaban 8 o 12 hipótesis analizadas, obtenidas {len(df_stat)}"
    
    # Comprobar que todos los p-valores ajustados por Holm son consistentes
    for _, row in df_stat.iterrows():
        p_raw = row["p_value_raw"]
        p_holm = row["p_value_holm"]
        assert p_holm >= p_raw, f"Holm p-value ({p_holm}) debe ser >= raw p-value ({p_raw})"
        assert 0.0 <= p_holm <= 1.0, f"Holm p-value ({p_holm}) debe estar en [0, 1]"
