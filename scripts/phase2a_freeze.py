"""Fase 2 - PASO A: CONGELACIÓN del experimento ANTES de consultar etiquetas finales.

Genera:
  artifacts/corrections_phase2/freeze_manifest.json   -> hashes SHA-256 de código,
     modelos, umbrales, normalización, configuración y scripts de evaluación.
  artifacts/corrections_phase2/baseline_original/**   -> copia inmutable de los
     archivos del commit base ceb0c9e (Configuración A/B original) para poder
     comparar original vs corregido sin reconstruir nada.

Protocolo:
  1) python scripts/phase2a_freeze.py            (EJECUTAR ANTES de phase2b/phase2c)
  2) python scripts/phase2b_acquire_cohort2.py   (consulta etiquetas externas)
  3) python scripts/phase2c_evaluate_cohort2.py  (evaluación)
Ninguna corrección de modelo/umbral/normalización debe cambiar tras este paso.
Si algo cambia, se debe regenerar el manifiesto y documentar el motivo.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "artifacts" / "corrections_phase2"
BASE_COMMIT = "ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7"
BASELINE_FILES = [
    "extension/background.js",
    "src/phishguard_ml/features.py",
    "src/phishguard_ml/homoglyphs.py",
    "src/phishguard_ml/detection_rules.py",
    "src/phishguard_ml/hybrid_model.py",
    "src/phishguard_orchestrator/engine.py",
    "src/phishguard_orchestrator/models.py",
    "src/phishguard_api/worker.py",
    "src/phishguard_api/inference.py",
    "src/phishguard_infra/policy.py",
]
MODEL_FILES = [
    "artifacts/url-baseline-0.2.0/model.joblib",
    "artifacts/m0-real/model.joblib",
    "artifacts/m0-ite-real/model.joblib",
    "artifacts/m1-real/model.joblib",
    "artifacts/m1-ite-real/model.joblib",
    "artifacts/m2-real/model.joblib",
    "artifacts/m2-ite-real/model.joblib",
    "artifacts/m3-real/model.joblib",
    "artifacts/corrected_audit/m3-authentic-cdp/model.joblib",
    "artifacts/m4-real/model.joblib",
    "artifacts/m5-real/model.joblib",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, errors="replace").strip()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "baseline_original").mkdir(exist_ok=True)

    # 0) Preservación: archivar el manifiesto vigente ANTES de sobrescribirlo
    #    (los freezes #1 y #2 se perdieron por sobrescritura — hallazgo B-05;
    #    a partir de este punto cada manifiesto queda archivado junto a
    #    FREEZE_HISTORY.md como freeze_manifest_00N_<sha8>.json).
    out_path = OUT / "freeze_manifest.json"
    if out_path.exists():
        prev_sha = sha256_file(out_path)
        archive = OUT / f"freeze_manifest_prev_{prev_sha[:8]}.json"
        if not archive.exists():
            archive.write_bytes(out_path.read_bytes())
            print(f"  manifiesto anterior preservado -> {archive.name}")

    # 1) Copia inmutable de la Configuración original (commit base)
    baseline_hashes: dict[str, str] = {}
    for rel in BASELINE_FILES:
        dest = OUT / "baseline_original" / rel.replace("/", "__")
        raw = subprocess.check_output(["git", "show", f"{BASE_COMMIT}:{rel}"], cwd=ROOT)
        dest.write_bytes(raw)
        baseline_hashes[rel] = hashlib.sha256(raw).hexdigest()

    # 2) Hashes del código actual (corregido)
    code_hashes: dict[str, str] = {}
    for path in sorted((ROOT / "src").rglob("*.py")):
        code_hashes[str(path.relative_to(ROOT)).replace("\\", "/")] = sha256_file(path)
    for path in sorted((ROOT / "extension").glob("*")):
        if path.is_file():
            code_hashes[str(path.relative_to(ROOT)).replace("\\", "/")] = sha256_file(path)
    for rel in ("tests/test_corrections_phase2.py",):
        p = ROOT / rel
        if p.exists():
            code_hashes[rel] = sha256_file(p)

    # 3) Scripts de este experimento (los que se congelan antes de las etiquetas)
    script_hashes: dict[str, str] = {}
    for path in sorted((ROOT / "scripts").glob("phase2*.py")):
        script_hashes[str(path.relative_to(ROOT)).replace("\\", "/")] = sha256_file(path)

    # 4) Modelos congelados + umbrales declarados dentro de cada artefacto
    model_info: dict[str, dict] = {}
    import joblib

    for rel in MODEL_FILES:
        p = ROOT / rel
        if not p.exists():
            model_info[rel] = {"status": "missing"}
            continue
        entry: dict = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
        try:
            obj = joblib.load(p)
            if isinstance(obj, dict):
                for key in ("selected_threshold", "low_fpr_threshold", "threshold", "feature_version",
                            "feature_profile", "experiment_version", "selected_candidate"):
                    if key in obj:
                        entry[key] = obj[key]
                if "feature_names" in obj:
                    entry["n_features"] = len(obj["feature_names"])
        except Exception as exc:  # pragma: no cover
            entry["load_error"] = str(exc)[:200]
        model_info[rel] = entry

    # 5) Umbrales de la cascada corregida (BUG-04) y normalización (BUG-07)
    from phishguard_ml.features import _strip_www
    from phishguard_orchestrator.models import AdaptivePolicy

    pol = AdaptivePolicy()
    thresholds = {
        "adaptive_policy": {
            "uncertainty_threshold_early_stop": pol.uncertainty_threshold,
            "abstention_threshold_final": pol.abstention_threshold,
            "minimum_confidence": pol.minimum_confidence,
            "budget": pol.budget,
            "costs": pol.costs,
        },
        "strip_www_normalization": {
            "enabled": True,
            "function_present": callable(_strip_www),
            "examples": {
                "www.google.com": _strip_www("www.google.com"),
                "google.com": _strip_www("google.com"),
                "www2.example.com": _strip_www("www2.example.com"),
            },
        },
        "client_timeout_ms": 8000,
        "llm_blend": {"llm_weight": 0.3, "cascade_weight": 0.7},
    }

    # 6) Estado de git y entorno
    try:
        git_state = {
            "commit": git("rev-parse", "HEAD"),
            "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
            "base_commit_original": BASE_COMMIT,
            "working_tree_dirty": bool(git("status", "--porcelain")),
            "status_porcelain_n_entries": len(git("status", "--porcelain").splitlines()),
        }
    except Exception as exc:
        git_state = {"error": str(exc)}

    manifest = {
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "protocol_order": [
            "1. phase2a_freeze.py (este archivo) - ANTES de consultar etiquetas",
            "2. phase2b_acquire_cohort2.py - adquisicion de la cohorte externa nueva",
            "3. phase2c_evaluate_cohort2.py - evaluacion unica con modelos/umbrales congelados",
        ],
        "git": git_state,
        "baseline_original_config_A_B": baseline_hashes,
        "corrected_code_sha256": code_hashes,
        "experiment_scripts_sha256": script_hashes,
        "models": model_info,
        "thresholds_and_normalization": thresholds,
        "python_version": sys.version,
        "note": "Este manifiesto se genera ANTES de consultar las etiquetas de la evaluacion final. "
                "Cualquier cambio posterior a codigo, modelos, umbrales o normalizacion invalida el freeze "
                "y debe regenerarlo con motivo documentado.",
    }
    out_path = OUT / "freeze_manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"FREEZE OK -> {out_path}")
    print(f"  code files hashed : {len(code_hashes)}")
    print(f"  models hashed     : {len([m for m in model_info.values() if m.get('sha256')])}")
    print(f"  baseline snapshots: {len(baseline_hashes)}")
    print(f"  experiment scripts: {len(script_hashes)}")
    print(f"  git commit        : {git_state.get('commit')} dirty={git_state.get('working_tree_dirty')}")
    print(f"  manifest sha256   : {sha256_file(out_path)}")


if __name__ == "__main__":
    main()
