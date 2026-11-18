"""
research.freeze: Congelamiento inmutable de modelos, extractores, calibradores y configuración de hiperparámetros.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import List

def get_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def find_file(candidates: List[Path]) -> Path | None:
    for c in candidates:
        if c.exists():
            return c
    return None

def freeze_models(workspace_root: Path | None = None) -> dict[str, any]:
    here = Path(__file__).resolve()
    root = workspace_root or here.parent.parent
    
    models = {
        "M0_lexical": {
            "paths": [
                root / "artifacts" / "models_reproduced" / "m0_reproduced.joblib",
                root / "04_MODELOS" / "M0" / "model.joblib",
                root.parent / "04_MODELOS" / "M0" / "model.joblib",
                root / "artifacts" / "url-baseline-0.2.0" / "model.joblib",
                root.parent / "artifacts" / "url-baseline-0.2.0" / "model.joblib",
            ],
            "features_count": 11,
            "profile": "authority_only",
            "algorithm": "HistGradientBoostingClassifier + CalibratedClassifierCV (isotonic)",
            "threshold": 0.382667,
        },
        "M1_network": {
            "paths": [
                root / "04_MODELOS" / "M1" / "model.joblib",
                root.parent / "04_MODELOS" / "M1" / "model.joblib",
                root / "artifacts" / "m1-real" / "model.joblib",
                root.parent / "artifacts" / "m1-real" / "model.joblib",
            ],
            "features_count": 36,
            "profile": "authority_only + network_infrastructure (25 feats)",
            "algorithm": "HistGradientBoostingClassifier + CalibratedClassifierCV (sigmoid)",
            "threshold": 0.525014,
        },
        "M2_content": {
            "paths": [
                root / "04_MODELOS" / "M2" / "model.joblib",
                root.parent / "04_MODELOS" / "M2" / "model.joblib",
                root / "artifacts" / "m2-real" / "model.joblib",
                root.parent / "artifacts" / "m2-real" / "model.joblib",
            ],
            "features_count": 62,
            "profile": "authority_only + network + html_dom (26 feats)",
            "algorithm": "HistGradientBoostingClassifier + CalibratedClassifierCV (sigmoid)",
            "threshold": 0.394962,
        },
        "M3_visual": {
            "paths": [
                root / "04_MODELOS" / "M3" / "model.joblib",
                root.parent / "04_MODELOS" / "M3" / "model.joblib",
                root / "artifacts" / "m3-real" / "model.joblib",
                root.parent / "artifacts" / "m3-real" / "model.joblib",
            ],
            "features_count": 75,
            "profile": "authority + network + html + visual_cdp (13 feats)",
            "algorithm": "HistGradientBoostingClassifier + CalibratedClassifierCV (sigmoid)",
            "threshold": 0.434336,
        },
        "Availability_Estimator": {
            "paths": [
                root / "04_MODELOS" / "availability" / "availability_estimator.joblib",
                root.parent / "04_MODELOS" / "availability" / "availability_estimator.joblib",
                root / "artifacts" / "models_reproduced" / "availability_reproduced.joblib",
                root / "artifacts" / "raea" / "availability_estimator.joblib",
                root.parent / "artifacts" / "raea" / "availability_estimator.joblib",
            ],
            "features_count": 9,
            "profile": "empirical_channel_availability (9 feats)",
            "algorithm": "CalibratedClassifierCV(LogisticRegression, sigmoid)",
            "threshold": 0.25,
        }
    }
    
    manifest = {
        "frozen_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "project": "RAEA-Phish",
        "models": {}
    }
    
    print("="*70)
    print("[research.freeze] CONGELAMIENTO INMUTABLE DE MODELOS Y ARTEFACTOS")
    print("="*70)
    
    lines_hashes = []
    for name, info in models.items():
        p = find_file(info["paths"])
        if p and p.exists():
            h = get_sha256(p)
            size = p.stat().st_size
            rel_str = str(p.relative_to(root)) if root in p.parents or p == root else str(p.name)
            manifest["models"][name] = {
                "artifact": rel_str,
                "sha256": h,
                "size_bytes": size,
                "features_count": info["features_count"],
                "profile": info["profile"],
                "algorithm": info["algorithm"],
                "threshold": info["threshold"],
            }
            lines_hashes.append(f"{h}  {name} ({p.name})")
            print(f"  + {name}: {size:,} bytes | SHA256: {h[:16]}... [OK]")
        else:
            print(f"  - {name}: NO ENCONTRADO")
            
    print("="*70)
    return manifest

if __name__ == "__main__":
    freeze_models()
