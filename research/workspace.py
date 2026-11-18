"""
research.workspace: Resolución unificada de rutas y artefactos para RAEA-Phish.
Funciona de forma transparente tanto en el repositorio de desarrollo como en la
carpeta raíz del ZIP extraído (autodetección de DATOS/, MODELOS/, CODIGO/, EXPERIMENTOS/).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional

def get_candidate_roots(anchor: Optional[Path] = None) -> List[Path]:
    """Retorna lista priorizada de posibles raíces del proyecto o ZIP extraído."""
    here = anchor or Path(__file__).resolve()
    raw_candidates = [
        Path.cwd(),
        Path.cwd().parent,
        here.parent.parent,         # Si estamos en CODIGO/research/ -> CODIGO/ o repo/
        here.parent.parent.parent,  # Si estamos en CODIGO/research/ -> ZIP_ROOT/
    ]
    seen = set()
    unique_roots = []
    for c in raw_candidates:
        try:
            res = c.resolve()
            if res not in seen and res.exists():
                seen.add(res)
                unique_roots.append(res)
        except Exception:
            pass

    # Priorizar raíces que son verdaderamente el contenedor del proyecto (tienen datos/modelos/experimentos)
    def root_priority(p: Path) -> int:
        score = 0
        if (p / "02_DATOS").exists() or (p / "DATOS").exists() or (p / "data").exists():
            score += 10
        if (p / "03_MODELOS").exists() or (p / "MODELOS").exists() or (p / "artifacts").exists():
            score += 5
        if (p / "04_EXPERIMENTOS").exists() or (p / "EXPERIMENTOS").exists():
            score += 2
        if p.name in ("05_CODIGO", "CODIGO", "research", "src"):
            score -= 20
        return score

    unique_roots.sort(key=root_priority, reverse=True)
    return unique_roots

def find_data_file(filename: str, subpaths: Optional[List[str]] = None) -> Path:
    """Localiza un archivo de datos buscando en DATOS/, data/ y 02_DATOS/."""
    subpaths = list(subpaths or [])
    if filename == "conventional.csv" and "splits" not in subpaths:
        subpaths.append("splits")
    if filename == "samples.csv" and "processed/0.1.0" not in subpaths:
        subpaths.append("processed/0.1.0")

    for root in get_candidate_roots():
        # 1. Búsqueda directa en raíz de datos
        for data_folder in ["DATOS", "02_DATOS", "data"]:
            p_direct = root / data_folder / filename
            if p_direct.exists():
                return p_direct
            for sp in subpaths:
                p_sub = root / data_folder / sp / filename
                if p_sub.exists():
                    return p_sub

        # 2. Carpeta suite
        p_suite = root / "autonomous_reproduction_suite" / "data" / filename
        if p_suite.exists():
            return p_suite

        # 3. Búsqueda recursiva en las carpetas de datos
        for data_folder in ["DATOS", "02_DATOS", "data"]:
            base_dir = root / data_folder
            if base_dir.is_dir():
                matches = list(base_dir.rglob(filename))
                if matches:
                    return matches[0]

    raise FileNotFoundError(
        f"No se encontró el archivo de datos '{filename}'. "
        f"Se buscó en DATOS/, data/ y 02_DATOS/ en raíces: {[str(r) for r in get_candidate_roots()]}"
    )

def find_model_file(model_key: str) -> Path:
    """Localiza un modelo serializado (M0, M1, M2, AVAILABILITY)."""
    key_upper = model_key.upper()
    for root in get_candidate_roots():
        # 1. Estructura modular: 03_MODELOS/<KEY>/model.joblib o MODELOS/<KEY>/model.joblib
        for folder_name in ["03_MODELOS", "MODELOS", "04_MODELOS"]:
            p_mod = root / folder_name / key_upper / "model.joblib"
            if p_mod.exists():
                return p_mod
            p_mod_avail = root / folder_name / key_upper / "availability_estimator.joblib"
            if p_mod_avail.exists():
                return p_mod_avail
            p_mod_gen = root / folder_name / key_upper / f"{key_upper.lower()}_reproduced.joblib"
            if p_mod_gen.exists():
                return p_mod_gen
            if key_upper in ("AVAILABILITY", "AVAIL"):
                p_avail_sub = root / folder_name / "DISPONIBILIDAD" / "availability_estimator.joblib"
                if p_avail_sub.exists():
                    return p_avail_sub

        # 2. Estructura del repositorio en artifacts/
        if key_upper == "M0":
            candidates = [
                root / "artifacts" / "models_reproduced" / "m0_reproduced.joblib",
                root / "artifacts" / "m0-real" / "model.joblib",
                root / "03_MODELOS" / "M0" / "model.joblib",
                root / "04_MODELOS" / "M0" / "model.joblib",
            ]
        elif key_upper == "M1":
            candidates = [
                root / "artifacts" / "m1-real" / "model.joblib",
                root / "03_MODELOS" / "M1" / "model.joblib",
                root / "04_MODELOS" / "M1" / "model.joblib",
            ]
        elif key_upper == "M2":
            candidates = [
                root / "artifacts" / "m2-real" / "model.joblib",
                root / "03_MODELOS" / "M2" / "model.joblib",
                root / "04_MODELOS" / "M2" / "model.joblib",
            ]
        elif key_upper in ("AVAILABILITY", "AVAIL"):
            candidates = [
                root / "artifacts" / "models_reproduced" / "availability_estimator.joblib",
                root / "artifacts" / "raea" / "availability_estimator.joblib",
                root / "03_MODELOS" / "DISPONIBILIDAD" / "availability_estimator.joblib",
                root / "04_MODELOS" / "availability" / "availability_estimator.joblib",
            ]
        else:
            candidates = []

        for c in candidates:
            if c.exists():
                return c

    raise FileNotFoundError(
        f"No se encontró el modelo '{model_key}'. "
        f"Se buscó en MODELOS/ y artifacts/ en raíces: {[str(r) for r in get_candidate_roots()]}"
    )

def get_experiments_dir() -> Path:
    """Retorna la carpeta de salida para experimentos (04_EXPERIMENTOS/ o EXPERIMENTOS/)."""
    for root in get_candidate_roots():
        for d_name in ["04_EXPERIMENTOS", "EXPERIMENTOS", "05_EXPERIMENTOS"]:
            d_cand = root / d_name
            if d_cand.exists():
                return d_cand
    # Por defecto, en la raíz actual
    d = Path.cwd() / "EXPERIMENTOS"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_figures_dir() -> Path:
    """Retorna la carpeta de figuras (06_FIGURAS/ o FIGURAS/)."""
    for root in get_candidate_roots():
        for f_name in ["06_FIGURAS", "FIGURAS"]:
            f_cand = root / f_name
            if f_cand.exists():
                return f_cand
    d = Path.cwd() / "FIGURAS"
    d.mkdir(parents=True, exist_ok=True)
    return d
    return d
