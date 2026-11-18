"""
research.verify_all: Orquestador maestro de reproducibilidad científica integral (Niveles 1 a 4).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from research.verify_data import verify_all_datasets
from research.prepare_data import prepare_partitions
from research.train import train_all_models
from research.calibrate import run_calibration_audit
from research.freeze import freeze_models
from research.evaluate import run_evaluation
from research.statistics import run_hypothesis_tests
from research.generate_figures import generate_all_figures

def run_pipeline():
    t_start = time.time()
    print("=" * 78)
    print("EJECUCIÓN DEL PIPELINE CIENTÍFICO INTEGRAL RAEA-PHISH (NIVELES 1-4)")
    print("=" * 78)

    # 1. Verificación de datos
    print("\n>>> PASO 1: VERIFICACIÓN DE DATOS CRUDOS Y LEAKAGE")
    rep_data = verify_all_datasets()
    if rep_data["status"] != "PASS":
        print("ERROR en verificación de datos.")
        sys.exit(1)

    # 2. Preparación de particiones
    print("\n>>> PASO 2: PREPARACIÓN DE PARTICIONES")
    prepare_partitions()

    # 3. Entrenamiento reproducible
    print("\n>>> PASO 3: ENTRENAMIENTO DE MODELOS")
    train_all_models()

    # 4. Calibración
    print("\n>>> PASO 4: CALIBRACIÓN Y DERIVA PROBABILÍSTICA")
    run_calibration_audit()

    # 5. Congelamiento inmutable
    print("\n>>> PASO 5: CONGELAMIENTO DE MODELOS")
    freeze_models()

    # 6. Inferencia y evaluación de políticas
    print("\n>>> PASO 6: INFERENCIA Y EVALUACIÓN DE POLÍTICAS")
    run_evaluation()

    # 7. Estadística inferencial pareada
    print("\n>>> PASO 7: CONTRASTES DE HIPÓTESIS BOOTSTRAP")
    run_hypothesis_tests()

    # 8. Generación de figuras científicas
    print("\n>>> PASO 8: GENERACIÓN DE FIGURAS")
    generate_all_figures()

    total_time = time.time() - t_start
    print("\n" + "=" * 78)
    print(f"PIPELINE CIENTÍFICO COMPLETADO EXITOSAMENTE EN {total_time:.2f} SEGUNDOS (0 ERRORES)")
    print("=" * 78)

if __name__ == "__main__":
    run_pipeline()
