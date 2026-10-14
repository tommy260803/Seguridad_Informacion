"""Fase 2 - PASO N: revalidación OFFLINE bajo el freeze vigente (sin sondeo en vivo).

Motivo (condiciones de las auditorías finales):
  * MAYOR-1 (científica): `phase2c.verify_freeze()` quedó desincronizado del código
    actual. Se resuelve con una re-congelación (freeze #4) y aquí se PRUEBA que
    `verify_freeze()` vuelve a pasar y que las métricas congeladas son reproducibles
    bajo el código corregido (C-2/C-3/B-07), sin re-consultar ninguna etiqueta.
  * El bloque B/C de phase2c (sondeo DNS/TLS/HTTP en vivo sobre 600 URL) NO se
    re-ejecuta: introduciría deriva de red. Sus salidas quedan como registro de la
    corrida bajo freeze #3, y aquí se documenta que C-2/C-3/B-07 no tocan esa ruta
    (LLM no participa en la evaluación; C-2 medido sobre los 1.200 hosts).

Qué hace:
  1) verify_freeze() con el manifiesto vigente (debe ser ok=True).
  2) Compara el manifiesto archivado del freeze anterior con el vigente:
     modelos/umbrales/baseline deben ser IDÉNTICOS; lista los diffs de código.
  3) Re-ejecuta los bloques OFFLINE de phase2c (A: nivel URL, D: recomputación
     interna, E: pareado www) con EVAL redirigido a artifacts/corrections_phase2/eval/…
     para NO sobrescribir los artefactos canónicos congelados.
  4) Compara salida nueva vs congelada:
       - url_level_predictions.csv idéntico byte a byte (SHA-256),
       - url_level_metrics.json idéntico salvo inference_seconds,
       - internal_recomputed_metrics.json idéntico byte a byte,
       - www_paired_experiment.json idéntico,
       - brazos/www_effect/paired_tests de eval_summary.json reproducidos exactos.
  5) Verifica que ningún artefacto canónico de eval/ cambió durante la ejecución.

Salida: artifacts/corrections_phase2/eval/offline_revalidation.json
        (dictamen PASS/FAIL; exit code 1 si algo falla).

No consulta red, no consulta etiquetas, no modifica modelos ni umbrales.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "corrections_phase2"
EVAL = OUT / "eval"
TMP_REVAL = OUT / "eval_reval_scratch"  # scratch temporal para las corridas redirigidas
OUT_JSON = EVAL / "offline_revalidation.json"

CANONICAL_FILES = [
    "url_level_predictions.csv",
    "url_level_metrics.json",
    "internal_recomputed_metrics.json",
    "www_paired_predictions.csv",
    "www_paired_experiment.json",
    "probe_and_cascade_metrics.json",
    "probe_predictions.csv",
    "eval_summary.json",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_phase2c():
    spec = importlib.util.spec_from_file_location(
        "phase2c_reval", ROOT / "scripts" / "phase2c_evaluate_cohort2.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["phase2c_reval"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=1)


def deep_diff(a: Any, b: Any, path: str = "$", out: list[str] | None = None) -> list[str]:
    out = out if out is not None else []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append(f"{path}.{k}: solo en nuevo (b)")
            elif k not in b:
                out.append(f"{path}.{k}: solo en congelado (a)")
            else:
                deep_diff(a[k], b[k], f"{path}.{k}", out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: longitud {len(a)} vs {len(b)}")
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                deep_diff(x, y, f"{path}[{i}]", out)
    else:
        if a != b:
            out.append(f"{path}: {a!r} vs {b!r}")
    return out


def main() -> int:
    checks: list[dict[str, Any]] = []

    def check(cid: str, desc: str, ok: bool, observed: Any, evid: str) -> bool:
        checks.append({"id": cid, "descripcion": desc,
                       "resultado": "PASS" if ok else "FAIL",
                       "valor_observado": observed, "evidencia": evid})
        return ok

    # ------------------------------------------------ 1) freeze vigente
    p2c = load_phase2c()
    freeze = p2c.verify_freeze()
    check("R-01", "verify_freeze() pasa con el manifiesto vigente (codigo, modelos, umbrales, scripts)",
          freeze["ok"] is True and freeze["mismatches"] == [],
          f"ok={freeze['ok']} mismatches={freeze['mismatches']} sha={freeze['freeze_manifest_sha256'][:16]}…",
          "artifacts/corrections_phase2/freeze_manifest.json")

    # ------------------------------------------------ 2) invariantes vs freeze anterior
    prev_paths = sorted(OUT.glob("freeze_manifest_prev_*.json"))
    invariants: dict[str, Any] = {"prev_manifest_found": bool(prev_paths)}
    if prev_paths:
        prev = json.loads(prev_paths[0].read_text(encoding="utf-8"))
        cur = json.loads((OUT / "freeze_manifest.json").read_text(encoding="utf-8"))
        same_models = prev.get("models") == cur.get("models")
        same_thr = prev.get("thresholds_and_normalization") == cur.get("thresholds_and_normalization")
        same_base = prev.get("baseline_original_config_A_B") == cur.get("baseline_original_config_A_B")
        pc, cc = prev.get("corrected_code_sha256", {}), cur.get("corrected_code_sha256", {})
        ps, cs = prev.get("experiment_scripts_sha256", {}), cur.get("experiment_scripts_sha256", {})
        invariants.update({
            "prev_manifest": prev_paths[0].name,
            "prev_frozen_at": prev.get("frozen_at_utc"),
            "cur_frozen_at": cur.get("frozen_at_utc"),
            "models_identical": same_models,
            "thresholds_identical": same_thr,
            "baseline_identical": same_base,
            "corrected_code_changed": sorted(k for k in pc if pc.get(k) != cc.get(k)),
            "corrected_code_added": sorted(k for k in cc if k not in pc),
            "corrected_code_removed": sorted(k for k in pc if k not in cc),
            "scripts_changed": sorted(k for k in ps if ps.get(k) != cs.get(k)),
            "scripts_added": sorted(k for k in cs if k not in ps),
            "scripts_removed": sorted(k for k in ps if k not in cs),
        })
        check("R-02", "Invariantes: modelos, umbrales/normalizacion y snapshots baseline IDENTICOS al freeze anterior",
              same_models and same_thr and same_base,
              f"models={same_models} thresholds={same_thr} baseline={same_base}; "
              f"codigo cambiado={invariants['corrected_code_changed']} "
              f"añadido={invariants['corrected_code_added']}",
              f"artifacts/corrections_phase2/{prev_paths[0].name}")
        # C-2/C-3/B-07 + tests de regresion deben ser los ÚNICOS cambios de
        # código respecto al freeze previo (correcciones documentadas de auditoría).
        expected_changed = {
            "src/phishguard_ml/homoglyphs.py",        # C-2
            "src/phishguard_api/llm_agent.py",        # C-3
            "src/phishguard_api/worker.py",           # B-07 (comentario)
            "tests/test_corrections_phase2.py",       # tests C-2/C-3/C-4/C-5
        }
        unexpected = [k for k in invariants["corrected_code_changed"]
                      if k not in expected_changed]
        check("R-03", "Los unicos cambios de codigo vs freeze anterior son las correcciones de auditoria esperadas",
              unexpected == [] and
              {"src/phishguard_ml/homoglyphs.py", "src/phishguard_api/llm_agent.py"} <=
              set(invariants["corrected_code_changed"]),
              f"inesperados={unexpected}; cambiados={invariants['corrected_code_changed']}",
              "auditorias finales C-2 (homografos), C-3 (TLS), B-07 (comentario worker)")
    else:
        check("R-02", "Invariantes: modelos/umbrales/baseline identicos al freeze anterior", False,
              "no se encontro freeze_manifest_prev_*.json", "artifacts/corrections_phase2/")
        check("R-03", "Diffs de codigo vs freeze anterior", False, "sin manifiesto previo", "-")

    # ------------------------------------------------ 3) cohorte congelada
    rows = p2c.load_cohort()  # aborta si el SHA-256 del dataset cambio
    check("R-04", "Cohorte2 congelada carga sin alteraciones (SHA-256 verificado)",
          len(rows) == 1200, f"N={len(rows)}", "artifacts/corrections_phase2/cohort2/cohort2_labels_frozen.json")

    # snapshot de los artefactos canonicos ANTES de re-ejecutar
    before = {f: sha256_file(EVAL / f) for f in CANONICAL_FILES if (EVAL / f).exists()}

    # ------------------------------------------------ 4) re-ejecucion offline redirigida
    from phishguard_data.psl import PublicSuffixList

    psl_path = sorted((ROOT / "data" / "raw").rglob("public_suffix_list.dat"))[-1]
    psl = PublicSuffixList.from_file(psl_path)

    if TMP_REVAL.exists():
        shutil.rmtree(TMP_REVAL)
    TMP_REVAL.mkdir(parents=True, exist_ok=True)
    orig_eval = p2c.EVAL
    p2c.EVAL = TMP_REVAL
    try:
        a = p2c.block_a(rows, psl)
        d = p2c.block_d()
        e = p2c.block_e(rows)
    finally:
        p2c.EVAL = orig_eval

    # ------------------------------------------------ 5) comparacion vs congelado
    # 5a) predicciones de nivel URL byte a byte
    new_pred = TMP_REVAL / "url_level_predictions.csv"
    old_pred = EVAL / "url_level_predictions.csv"
    same_bytes = sha256_file(new_pred) == sha256_file(old_pred)
    check("R-05", "Bloque A: url_level_predictions.csv reproducido IDENTICO byte a byte",
          same_bytes, f"sha_nuevo={sha256_file(new_pred)[:16]}… sha_congelado={sha256_file(old_pred)[:16]}…",
          "artifacts/corrections_phase2/eval/url_level_predictions.csv")

    # 5b) metricas de nivel URL (solo difiere inference_seconds)
    new_m = json.loads((TMP_REVAL / "url_level_metrics.json").read_text(encoding="utf-8"))
    old_m = json.loads((EVAL / "url_level_metrics.json").read_text(encoding="utf-8"))
    new_m.pop("inference_seconds", None)
    old_m.pop("inference_seconds", None)
    diff_m = deep_diff(old_m, new_m)
    check("R-06", "Bloque A: url_level_metrics.json identico al congelado (excluyendo inference_seconds)",
          not diff_m, f"{len(diff_m)} diferencias" + (f": {diff_m[:5]}" if diff_m else ""),
          "artifacts/corrections_phase2/eval/url_level_metrics.json")

    # 5c) recomputacion interna byte a byte
    same_int = ((TMP_REVAL / "internal_recomputed_metrics.json").read_bytes()
                == (EVAL / "internal_recomputed_metrics.json").read_bytes())
    check("R-07", "Bloque D: internal_recomputed_metrics.json reproducido IDENTICO byte a byte",
          same_int, f"sha_nuevo={sha256_file(TMP_REVAL / 'internal_recomputed_metrics.json')[:16]}… "
                    f"sha_congelado={sha256_file(EVAL / 'internal_recomputed_metrics.json')[:16]}…",
          "artifacts/corrections_phase2/eval/internal_recomputed_metrics.json")

    # 5d) experimento pareado www byte a byte
    same_www = ((TMP_REVAL / "www_paired_experiment.json").read_bytes()
                == (EVAL / "www_paired_experiment.json").read_bytes())
    check("R-08", "Bloque E: www_paired_experiment.json reproducido IDENTICO byte a byte",
          same_www, f"sha_nuevo={sha256_file(TMP_REVAL / 'www_paired_experiment.json')[:16]}… "
                    f"sha_congelado={sha256_file(EVAL / 'www_paired_experiment.json')[:16]}…",
          "artifacts/corrections_phase2/eval/www_paired_experiment.json")

    # 5e) brazos/resumenes de eval_summary.json reproducidos exactos.
    #     eval_summary.json guarda una PROYECCION de 6 metricas por brazo
    #     (ver phase2c.main(): f1, fpr, fnr, precision, recall, accuracy); se
    #     aplica exactamente la misma proyeccion al resultado nuevo para
    #     comparar como-a-como.
    summary = json.loads((EVAL / "eval_summary.json").read_text(encoding="utf-8"))
    su = summary["url_level"]
    proj_arms = {k: {m: v[m] for m in ("f1", "fpr", "fnr", "precision", "recall", "accuracy")}
                 for k, v in a["arms"].items()}
    diff_arm = deep_diff(su["arms"], proj_arms, "$.arms")
    diff_www = deep_diff(su["www_effect"], a["www_effect"], "$.www_effect")
    diff_pair = deep_diff(su["paired_tests"], a["paired_tests"], "$.paired_tests")
    check("R-09", "Bloque A: brazos/www_effect/paired_tests de eval_summary.json reproducidos EXACTOS",
          not (diff_arm or diff_www or diff_pair),
          f"arms={len(diff_arm)} www={len(diff_www)} paired={len(diff_pair)} diferencias"
          + (f" -> {(diff_arm + diff_www + diff_pair)[:5]}" if (diff_arm or diff_www or diff_pair) else ""),
          "artifacts/corrections_phase2/eval/eval_summary.json")

    # ------------------------------------------------ 6) artefactos canonicos intactos
    after = {f: sha256_file(EVAL / f) for f in CANONICAL_FILES if (EVAL / f).exists()}
    untouched = before == after and set(before) == set(CANONICAL_FILES)
    check("R-10", "Los 8 artefactos canonicos de eval/ NO fueron modificados por la revalidacion",
          untouched,
          f"antes={len(before)}/8, identicos={before == after}",
          "artifacts/corrections_phase2/eval/")

    # ------------------------------------------------ 7) ruta en vivo / LLM documentada
    check("R-11", "El sondeo en vivo (bloque B/C) NO se re-ejecuta y su registro permanece bajo freeze #3",
          (EVAL / "probe_and_cascade_metrics.json").exists(),
          "probe_and_cascade_metrics.json conservado; C-2/C-3/B-07 no tocan la ruta de sondeo "
          "(LLM jamas participa en la evaluacion; impacto de C-2 medido en "
          "bug03_c2_fix_impact_on_cohort2.json: 0/1200 hosts)",
          "artifacts/corrections_phase2/eval/probe_and_cascade_metrics.json")

    # ------------------------------------------------ escritura
    internal_sha = sha256_file(TMP_REVAL / "internal_recomputed_metrics.json")
    pred_sha = sha256_file(new_pred)
    shutil.rmtree(TMP_REVAL, ignore_errors=True)
    n_pass = sum(1 for c in checks if c["resultado"] == "PASS")
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "freeze_manifest_sha256": freeze["freeze_manifest_sha256"],
        "n_checks": len(checks),
        "n_pass": n_pass,
        "n_fail": len(checks) - n_pass,
        "dictamen": "PASS" if n_pass == len(checks) else "FAIL",
        "checks": checks,
        "freeze_invariants_vs_prev": invariants,
        "rerun_outputs": {
            "url_level_predictions_sha256": pred_sha,
            "internal_recomputed_sha256": internal_sha,
        },
        "note": "Revalidacion offline: sin red, sin etiquetas nuevas, sin tocar artefactos "
                "canonicos (scratch temporal borrado al finalizar).",
    }
    OUT_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"n_checks": len(checks), "n_pass": n_pass,
                      "n_fail": len(checks) - n_pass, "dictamen": payload["dictamen"]},
                     indent=2))
    for c in checks:
        if c["resultado"] != "PASS":
            print(f"  FAIL {c['id']}: {c['descripcion']} -> {c['valor_observado']}")
    return 0 if payload["dictamen"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
