"""Fase 2 - PASO C: evaluación con modelos/umbrales congelados sobre la cohorte2.

Bloques:
  A) Nivel URL sobre N=1200 (cohort2 congelada):
       M0_original (sin normalización www) vs M0_normalizado (BUG-07),
       Config_A_original (extensión original /predict_hybrid con código base ceb0c9e)
       vs Config_C_corregido (código actual), homógrafos/Punycode incluidos.
  B) Sondeo multimodal en vivo (DNS/TLS/HTTP/HTML) sobre subcohorte estratificada:
       Intention-to-Evaluate (todos los intentos) vs Complete-Case (separados),
       estrategia de respaldo M0-only, errores de adquisición por clase/fuente,
       disponibilidad legítimo vs phishing, falsos negativos silenciosos.
  C) Cascada: M2 sin cascada, M4 original forzada, M5 selectiva (H_abs=0.50),
       cascada conservadora (salida benigna temprana solo p<=0.02),
       Config_C corregida usando decide_next real con umbrales BUG-04
       (early stop 0.15 / abstención 0.20) y políticas fail-open/fail-closed/
       forced-threshold sobre las abstenciones. Abstenciones NUNCA cuentan como acierto.
  D) Recomputación interna desde los predictions.csv congelados (test partition).
  E) Experimento pareado www./non-www (BUG-07 directo).
  Estadística: IC95 bootstrap, McNemar exacto, Holm, Brier/ECE, riesgo-cobertura/AURC.

Todas las salidas quedan en artifacts/corrections_phase2/eval/.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import sys
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "artifacts" / "corrections_phase2"
EVAL = OUT / "eval"
SEED = 42
N_PROBE_PER_CLASS = 300


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


f2_02 = load_module("fase2_02", ROOT / "scripts" / "fase2_02_build_and_evaluate_external.py")
f2_05 = load_module("fase2_05", ROOT / "scripts" / "fase2_05_cascada_ablaciones.py")

from scipy.stats import binomtest  # noqa: E402
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, roc_auc_score  # noqa: E402

from phishguard_data.psl import PublicSuffixList  # noqa: E402
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features  # noqa: E402
from phishguard_ml.evaluation import expected_calibration_error, shannon_entropy  # noqa: E402
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features  # noqa: E402
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features  # noqa: E402

compute_metrics_with_ci = f2_02.compute_metrics_with_ci
probe_single_external_url = f2_02.probe_single_external_url
no_op_geo = f2_02.no_op_geo
no_op_age = f2_02.no_op_age
simulate_cascade_policy = f2_05.simulate_cascade_policy
compute_basic_metrics = f2_05.compute_basic_metrics
compute_aurc = f2_05.compute_aurc


# --------------------------------------------------------------------- utilidades
def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_freeze() -> dict[str, Any]:
    manifest_path = OUT / "freeze_manifest.json"
    if not manifest_path.exists():
        raise SystemExit("ABORT: falta freeze_manifest.json; ejecute scripts/phase2a_freeze.py primero")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mismatches: list[str] = []
    for rel, expected in manifest["corrected_code_sha256"].items():
        p = ROOT / rel
        if not p.exists():
            mismatches.append(f"missing:{rel}")
        elif sha256_file(p) != expected:
            mismatches.append(f"changed:{rel}")
    for rel, expected in manifest["models"].items():
        if expected.get("sha256"):
            p = ROOT / rel
            if not p.exists() or sha256_file(p) != expected["sha256"]:
                mismatches.append(f"model_changed:{rel}")
    for rel, expected in manifest.get("experiment_scripts_sha256", {}).items():
        p = ROOT / rel
        if rel.endswith("phase2c_evaluate_cohort2.py"):
            continue  # este propio script se congela a sí mismo en phase2a
        if not p.exists() or sha256_file(p) != expected:
            mismatches.append(f"script_changed:{rel}")
    return {"freeze_manifest_sha256": sha256_file(manifest_path),
            "frozen_at_utc": manifest["frozen_at_utc"],
            "mismatches": mismatches, "ok": not mismatches}


def load_cohort() -> list[dict[str, Any]]:
    frozen = json.loads((OUT / "cohort2" / "cohort2_labels_frozen.json").read_text(encoding="utf-8"))
    ds = OUT / "cohort2" / "cohort2_dataset.csv"
    actual = sha256_file(ds)
    if actual != frozen["dataset_sha256"]:
        raise SystemExit(f"ABORT: la cohorte congelada cambió ({actual} != {frozen['dataset_sha256']})")
    rows = []
    with open(ds, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            r["label_int"] = 1 if r["label"] == "phishing" else 0
            r["has_www"] = int(r["has_www"])
            r["is_idn_punycode"] = int(r["is_idn_punycode"])
            r["has_subdomain"] = int(r["has_subdomain"])
            r["has_path"] = int(r["has_path"])
            r["has_params"] = int(r["has_params"])
            r["is_shortener"] = int(r["is_shortener"])
            rows.append(r)
    return rows


def mcnemar_exact(y: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray) -> dict[str, Any]:
    a_ok_b_wrong = int(((pred_a == y) & (pred_b != y)).sum())
    a_wrong_b_ok = int(((pred_a != y) & (pred_b == y)).sum())
    n_disc = a_ok_b_wrong + a_wrong_b_ok
    p = float(binomtest(a_wrong_b_ok, n_disc, 0.5).pvalue) if n_disc else 1.0
    return {
        "a_correct_b_wrong": a_ok_b_wrong,
        "a_wrong_b_correct": a_wrong_b_ok,
        "discordant": n_disc,
        "mcnemar_exact_two_sided_p": round(p, 8),
        "significant_alpha_0_05": bool(p < 0.05),
    }


def holm_adjust(pvals: dict[str, float]) -> dict[str, float]:
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    out: dict[str, float] = {}
    max_adj = 0.0
    for i, (k, p) in enumerate(items):
        adj = min(1.0, (m - i) * p)
        max_adj = max(max_adj, adj)
        out[k] = round(max_adj, 8)
    return out


def risk_coverage(y: np.ndarray, prob: np.ndarray, pred: np.ndarray) -> dict[str, Any]:
    """Curva riesgo-cobertura usando la confianza 1-H(p) como score de rechazo."""
    conf = 1.0 - np.array([float(shannon_entropy(np.array([p]))[0]) for p in prob])
    order = np.argsort(-conf)
    ys, ps = y[order], pred[order]
    risks, coverages = [], []
    for k in range(1, len(ys) + 1):
        mistakes = (ps[:k] != ys[:k]).mean()
        risks.append(float(mistakes))
        coverages.append(k / len(ys))
    aurc = float(np.trapezoid(risks, coverages)) if hasattr(np, "trapezoid") else float(np.trapz(risks, coverages))
    return {"aurc": round(aurc, 6), "risk_at_full_coverage": round(risks[-1], 6),
            "n_curve_points": len(risks)}


def safe_metrics(y: np.ndarray, prob: np.ndarray, tau: Any, *,
                 y_pred_override: np.ndarray | None = None, n_boot: int = 2000) -> dict[str, Any]:
    """compute_metrics_with_ci con salvaguarda para subconjuntos de una sola clase
    (los bootstrap quedarían vacíos y np.percentile fallaría)."""
    y = np.asarray(y)
    prob = np.asarray(prob)
    if len(y) == 0:
        return {"n": 0, "note": "empty_subset"}
    if len(np.unique(y)) < 2 or len(y) < 5:
        pred = y_pred_override if y_pred_override is not None else (prob >= float(np.asarray(tau).reshape(-1)[0])).astype(int)
        m = compute_basic_metrics(y, pred, prob)
        m["threshold"] = round(float(np.asarray(tau).reshape(-1)[0]), 6)
        m["note"] = "subset without both classes: bootstrap CI not computed (point estimates only)"
        return m
    return compute_metrics_with_ci(y, prob, tau, y_pred_override=y_pred_override, n_boot=n_boot)


def slice_metrics(y: np.ndarray, prob: np.ndarray, tau: float, mask: np.ndarray) -> dict[str, Any] | None:
    if mask.sum() < 10 or len(np.unique(y[mask])) < 1:
        return None
    m = safe_metrics(y[mask], prob[mask], tau, n_boot=500)
    return {k: m[k] for k in m if k in ("n", "note", "confusion_matrix", "accuracy", "precision", "recall",
                                        "f1", "fpr", "fnr", "threshold")}


# --------------------------------------------------------------------- Bloque A
def block_a(rows: list[dict[str, Any]], psl: PublicSuffixList) -> dict[str, Any]:
    print("\n=== BLOQUE A: nivel URL sobre la cohorte2 (N=%d) ===" % len(rows), flush=True)
    import joblib

    from phishguard_ml import features as feat_mod

    tau_m0 = float(joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")["threshold"])
    m0 = joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")
    clf = m0["model"]
    names = list(m0["feature_names"])
    y = np.array([r["label_int"] for r in rows], dtype=int)

    # --- M0 original (sin strip_www) vs M0 normalizado (BUG-07) --------------
    feats_orig, feats_norm = [], []
    for r in rows:
        ctx = UrlFeatureContext(r["canonical_url"], r["registered_domain"])
        f_norm = extract_url_features(ctx)
        feats_norm.append([f_norm[k] for k in names])
    with patch.object(feat_mod, "_strip_www", lambda h: h):
        for r in rows:
            ctx = UrlFeatureContext(r["canonical_url"], r["registered_domain"])
            f_org = extract_url_features(ctx)
            feats_orig.append([f_org[k] for k in names])
    X_orig = np.array(feats_orig, dtype=np.float64)
    X_norm = np.array(feats_norm, dtype=np.float64)
    t0 = time.perf_counter()
    p_m0_orig = clf.predict_proba(X_orig)[:, 1]
    t_orig = time.perf_counter() - t0
    t0 = time.perf_counter()
    p_m0_norm = clf.predict_proba(X_norm)[:, 1]
    t_norm = time.perf_counter() - t0

    # --- Config A (código base) vs Config C (código corregido) ---------------
    baseline_hg = load_module("baseline_homoglyphs",
                              OUT / "baseline_original" / "src__phishguard_ml__homoglyphs.py")
    from phishguard_ml import hybrid_model as hm_mod
    from phishguard_ml.detection_rules import DetectionRules
    from phishguard_ml.hybrid_model import HybridM0Model

    hybrid = HybridM0Model()
    probs_a, probs_c, dec_a, dec_c = [], [], [], []
    with ExitStack() as st:
        st.enter_context(patch.object(DetectionRules, "_check_server_geolocation", no_op_geo))
        st.enter_context(patch.object(DetectionRules, "_check_domain_age", no_op_age))
        # --- Config A: comportamiento original (ceb0c9e) ---
        st.enter_context(patch.object(feat_mod, "_strip_www", lambda h: h))
        st.enter_context(patch.object(hm_mod, "analyze_homoglyphs", baseline_hg.analyze_homoglyphs))
        for r in rows:
            res = hybrid.predict(r["canonical_url"], user_country="EC")
            probs_a.append(float(res["probability"]))
            dec_a.append(res["decision"])
    # al salir del bloque ExitStack los parches se revierten: Config C usa el código actual
    with ExitStack() as st:
        st.enter_context(patch.object(DetectionRules, "_check_server_geolocation", no_op_geo))
        st.enter_context(patch.object(DetectionRules, "_check_domain_age", no_op_age))
        for r in rows:
            res = hybrid.predict(r["canonical_url"], user_country="EC")
            probs_c.append(float(res["probability"]))
            dec_c.append(res["decision"])

    p_a = np.array(probs_a)
    p_c = np.array(probs_c)
    # decisión binaria del pipeline híbrido (warning -> phishing cautelar? se reporta como decisión operativa)
    d_a = np.array([1 if d == "phishing" else 0 for d in dec_a])
    d_c = np.array([1 if d == "phishing" else 0 for d in dec_c])

    arms = {
        "M0_original_sin_normalizacion": safe_metrics(y, p_m0_orig, tau_m0),
        "M0_normalizado_strip_www": safe_metrics(y, p_m0_norm, tau_m0),
        "Config_A_extension_original": safe_metrics(y, p_a, 0.5, y_pred_override=d_a),
        "Config_C_extension_corregida": safe_metrics(y, p_c, 0.5, y_pred_override=d_c),
    }

    # slices por característica estructural
    slices: dict[str, Any] = {}
    for slice_name, mask in {
        "con_www": np.array([r["has_www"] == 1 for r in rows]),
        "sin_www": np.array([r["has_www"] == 0 for r in rows]),
        "idn_punycode": np.array([r["is_idn_punycode"] == 1 for r in rows]),
        "con_subdominio": np.array([r["has_subdomain"] == 1 for r in rows]),
        "con_ruta": np.array([r["has_path"] == 1 for r in rows]),
        "con_parametros": np.array([r["has_params"] == 1 for r in rows]),
        "acortadores": np.array([r["is_shortener"] == 1 for r in rows]),
    }.items():
        slices[slice_name] = {
            "n": int(mask.sum()),
            "M0_original": slice_metrics(y, p_m0_orig, tau_m0, mask),
            "M0_normalizado": slice_metrics(y, p_m0_norm, tau_m0, mask),
        }
    by_source: dict[str, Any] = {}
    for src in sorted({r["source"] for r in rows}):
        mask = np.array([r["source"] == src for r in rows])
        by_source[src] = {
            "n": int(mask.sum()),
            "label": rows[int(np.where(mask)[0][0])]["label"],
            "M0_original": slice_metrics(y, p_m0_orig, tau_m0, mask),
            "M0_normalizado": slice_metrics(y, p_m0_norm, tau_m0, mask),
        }

    # Predicciones individuales (recomputables)
    with open(EVAL / "url_level_predictions.csv", "w", encoding="utf-8", newline="") as f:
        fields = ["cohort2_id", "canonical_url", "registered_domain", "label", "source", "has_www",
                  "is_idn_punycode", "prob_M0_original", "prob_M0_normalizado",
                  "prob_configA", "decision_configA", "prob_configC", "decision_configC"]
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for i, r in enumerate(rows):
            w.writerow({
                "cohort2_id": r["cohort2_id"], "canonical_url": r["canonical_url"],
                "registered_domain": r["registered_domain"], "label": r["label"], "source": r["source"],
                "has_www": r["has_www"], "is_idn_punycode": r["is_idn_punycode"],
                "prob_M0_original": f"{p_m0_orig[i]:.6f}", "prob_M0_normalizado": f"{p_m0_norm[i]:.6f}",
                "prob_configA": f"{p_a[i]:.6f}", "decision_configA": dec_a[i],
                "prob_configC": f"{p_c[i]:.6f}", "decision_configC": dec_c[i],
            })

    # Comparaciones pareadas
    preds = {
        "M0_original_sin_normalizacion": (p_m0_orig >= tau_m0).astype(int),
        "M0_normalizado_strip_www": (p_m0_norm >= tau_m0).astype(int),
        "Config_A_extension_original": d_a,
        "Config_C_extension_corregida": d_c,
    }
    pairs = [
        ("M0_original_sin_normalizacion", "M0_normalizado_strip_www"),
        ("Config_A_extension_original", "Config_C_extension_corregida"),
        ("M0_normalizado_strip_www", "Config_C_extension_corregida"),
    ]
    paired = {f"{a}__vs__{b}": mcnemar_exact(y, preds[a], preds[b]) for a, b in pairs}
    pvals = {k: v["mcnemar_exact_two_sided_p"] for k, v in paired.items()}
    holm = holm_adjust(pvals)
    for k, v in paired.items():
        v["holm_adjusted_p"] = holm[k]
        v["significant_after_holm_alpha_0_05"] = bool(holm[k] < 0.05)

    # Efecto del tamaño (diferencia de FPR con IC normal)
    fpr_o = arms["M0_original_sin_normalizacion"]["fpr"]
    fpr_n = arms["M0_normalizado_strip_www"]["fpr"]
    n_neg = int((y == 0).sum())
    se = float(np.sqrt(fpr_o * (1 - fpr_o) / n_neg + fpr_n * (1 - fpr_n) / n_neg))
    effect = {
        "fpr_M0_original": fpr_o,
        "fpr_M0_normalizado": fpr_n,
        "delta_fpr_absolute": round(fpr_o - fpr_n, 6),
        "delta_fpr_95ci": [round(fpr_o - fpr_n - 1.96 * se, 6), round(fpr_o - fpr_n + 1.96 * se, 6)],
        "n_legitimos": n_neg,
    }

    out = {
        "n_total": len(rows),
        "n_phishing": int(y.sum()),
        "n_legitimate": int((1 - y).sum()),
        "threshold_M0": tau_m0,
        "arms": arms,
        "slices": slices,
        "by_source": by_source,
        "paired_tests": paired,
        "www_effect": effect,
        "inference_seconds": {"m0_original": round(t_orig, 3), "m0_normalizado": round(t_norm, 3)},
        "predictions_file": "artifacts/corrections_phase2/eval/url_level_predictions.csv",
        "predictions_sha256": sha256_file(EVAL / "url_level_predictions.csv"),
    }
    (EVAL / "url_level_metrics.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  M0 original  F1={arms['M0_original_sin_normalizacion']['f1']:.4f} "
          f"FPR={arms['M0_original_sin_normalizacion']['fpr']:.4f}", flush=True)
    print(f"  M0 normalizado F1={arms['M0_normalizado_strip_www']['f1']:.4f} "
          f"FPR={arms['M0_normalizado_strip_www']['fpr']:.4f}", flush=True)
    print(f"  Config A F1={arms['Config_A_extension_original']['f1']:.4f} | "
          f"Config C F1={arms['Config_C_extension_corregida']['f1']:.4f}", flush=True)
    return out


# --------------------------------------------------------------------- Bloque B/C
def block_b_c(rows: list[dict[str, Any]], psl: PublicSuffixList) -> dict[str, Any]:
    import joblib

    print("\n=== BLOQUE B: sondeo multimodal en vivo ===", flush=True)
    rng = np.random.default_rng(SEED)
    phish = [r for r in rows if r["label"] == "phishing"]
    legit = [r for r in rows if r["label"] == "legitimate"]
    idx_p = rng.choice(len(phish), size=min(N_PROBE_PER_CLASS, len(phish)), replace=False)
    idx_l = rng.choice(len(legit), size=min(N_PROBE_PER_CLASS, len(legit)), replace=False)
    probe_rows = [phish[i] for i in idx_p] + [legit[i] for i in idx_l]
    for r in probe_rows:  # el probe de fase2_02 espera la clave external_id
        r["external_id"] = r["cohort2_id"]
    ids = {r["cohort2_id"] for r in rows}
    assert len({r["cohort2_id"] for r in probe_rows}) == len(probe_rows)
    assert set(r["cohort2_id"] for r in probe_rows) <= ids

    base_cfg = f2_02.load_infrastructure_config(ROOT / "configs" / "infrastructure-analyzer.json")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    probe_map: dict[str, Any] = {}
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=32) as pool:
        futs = {pool.submit(probe_single_external_url, r, psl, base_cfg): r["cohort2_id"] for r in probe_rows}
        done = 0
        for fut in as_completed(futs):
            res = fut.result()
            probe_map[res["external_id"]] = res
            done += 1
            if done % 50 == 0 or done == len(probe_rows):
                print(f"  {done}/{len(probe_rows)} sonded ({time.perf_counter()-t0:.0f}s)", flush=True)
    probe_seconds = round(time.perf_counter() - t0, 1)

    with open(EVAL / "probe_raw.jsonl", "w", encoding="utf-8") as f:
        for r in probe_rows:
            f.write(json.dumps({"sample": r, "probe": probe_map[r["cohort2_id"]]}, ensure_ascii=False) + "\n")

    m0_cc = joblib.load(ROOT / "artifacts" / "m0-real" / "model.joblib")
    m1_cc = joblib.load(ROOT / "artifacts" / "m1-real" / "model.joblib")
    m2_cc = joblib.load(ROOT / "artifacts" / "m2-real" / "model.joblib")

    X0, X1, X2, y, cc, lat0, lat1, lat2, status = [], [], [], [], [], [], [], [], []
    for r in probe_rows:
        pr = probe_map[r["cohort2_id"]]
        inf_r, cnt_r = pr["infra"], pr["content"]
        t_a = time.perf_counter()
        uf = extract_url_features(UrlFeatureContext(r["canonical_url"], r["registered_domain"]))
        v0 = np.array([uf[k] for k in AUTHORITY_FEATURE_NAMES], dtype=np.float64)
        lat0.append((time.perf_counter() - t_a) * 1000.0)
        inf_f = extract_infrastructure_features(inf_r)
        cnt_f = extract_content_features(cnt_r)
        v1 = np.concatenate([v0, [inf_f[k] for k in INFRA_FEATURE_NAMES]])
        v2 = np.concatenate([v1, [cnt_f[k] for k in CONTENT_FEATURE_NAMES]])
        X0.append(v0); X1.append(v1); X2.append(v2)
        y.append(r["label_int"])
        cc.append(bool(inf_r.get("status") == "success" and cnt_r.get("status") == "success"))
        lat1.append(pr["infra_elapsed_ms"])
        lat2.append(pr["http_download_ms"] + pr["dom_parse_ms"])
        status.append({
            "label": r["label"], "source": r["source"],
            "infra_status": inf_r.get("status"), "infra_error": inf_r.get("error_code"),
            "content_status": cnt_r.get("status"), "content_error": cnt_r.get("error_code"),
        })
    X0 = np.array(X0); X1 = np.array(X1); X2 = np.array(X2)
    y = np.array(y, dtype=int)
    cc = np.array(cc, dtype=bool)
    lat0 = np.array(lat0); lat1 = np.array(lat1); lat2 = np.array(lat2)

    t0 = time.perf_counter()
    p0 = m0_cc["model"].predict_proba(X0)[:, 1]
    p1 = m1_cc["model"].predict_proba(X1)[:, 1]
    p2 = m2_cc["model"].predict_proba(X2)[:, 1]
    infer_seconds = round(time.perf_counter() - t0, 3)
    tau0, tau1, tau2 = (float(m0_cc["selected_threshold"]), float(m1_cc["selected_threshold"]),
                        float(m2_cc["selected_threshold"]))

    # ---------------- Bloque C: cascadas ----------------
    print("\n=== BLOQUE C: cascadas sobre el sondeo ===", flush=True)
    lats = [lat0, lat1, lat2]
    probs_stages = [p0, p1, p2]
    taus = [tau0, tau1, tau2]

    casc: dict[str, Any] = {}

    # 1) M2 sin cascada (fuerza todas las modalidades, sin salida temprana)
    casc["M2_sin_cascada"] = safe_metrics(y, p2, tau2)

    # 2) M4 original: cascada forzada de 3 etapas sin abstención (usa M2 al final)
    cas_forced = simulate_cascade_policy(probs_stages, taus, lats, y, h_esc=0.15, h_abs=0.50,
                                         policy_type="symmetric_entropy")
    casc["M4_original_forzada"] = {
        "metrics_full_coverage": cas_forced["forced_full_coverage_metrics"],
        "stopping_counts": cas_forced["stopping_counts"],
        "avg_modalities": cas_forced["avg_modalities"],
        "early_exit_errors": cas_forced["early_exit_errors"],
        "latency_ms_real": cas_forced["latency_ms"],
    }
    # M4 forzada sin salida temprana (todas las etapas siempre)
    n = len(y)
    casc["M4_forzada_sin_salida_temprana"] = safe_metrics(y, p2, tau2)

    # 3) M5 selectiva (parámetros originales: H_esc=0.15, H_abs=0.50)
    casc["M5_selectivo_original"] = {
        "coverage_policy": cas_forced["selective_metrics"],
        "note": "Abstenciones NO contabilizadas como aciertos; se reporta cobertura y métricas sobre decididos",
        "risk_coverage_full": risk_coverage(y, cas_forced["_arrays"]["final_prob"],
                                            cas_forced["_arrays"]["final_pred"]),
    }

    # 4) Cascada conservadora: salida benigna temprana solo p<=0.02 (prohibe FN temprano benigno)
    cons = simulate_cascade_policy(probs_stages, taus, lats, y, h_esc=0.15, h_abs=0.50,
                                   policy_type="conservative_no_early_benign", conservative_legit_max_prob=0.02)
    casc["Cascada_conservadora_M1_obligatorio"] = {
        "metrics_full_coverage": cons["forced_full_coverage_metrics"],
        "selective": cons["selective_metrics"],
        "stopping_counts": cons["stopping_counts"],
        "avg_modalities": cons["avg_modalities"],
        "early_exit_errors": cons["early_exit_errors"],
        "latency_ms_real": cons["latency_ms"],
    }

    # 5) Config C corregida: usa decide_next REAL con umbrales separados BUG-04
    from phishguard_orchestrator.engine import decide_next
    from phishguard_orchestrator.models import AdaptivePolicy

    from dataclasses import replace as _replace

    def run_config_c(abstention_threshold: float) -> dict[str, Any]:
        """Cascada corregida usando decide_next() REAL (BUG-04). Replica el contrato de
        run_adaptive: el presupuesto se descuenta (gasto) y las modalidades no adquiribles
        (M3 visual no disponible en el sondeo externo) se marcan como consultadas para que
        el orquestador avance a la etapa siguiente o aplique la abstención final."""
        pol = AdaptivePolicy(budget=2.0, abstention_threshold=abstention_threshold)
        c_prob = np.zeros(n); c_pred = np.zeros(n, dtype=int); c_abst = np.zeros(n, dtype=bool)
        c_stage = np.zeros(n, dtype=int); c_reason: list[str] = []
        for i in range(n):
            consulted = ["url"]
            prob = float(p0[i])
            stage = 0
            spent = 0.0
            while True:
                pol_i = _replace(pol, budget=pol.budget - spent)
                action, reason, _conf, _unc = decide_next(prob, tuple(consulted), pol_i)
                if action in ("decide", "abstain"):
                    c_reason.append(reason)
                    if action == "abstain":
                        c_abst[i] = True
                    break
                if action == "visual":
                    consulted.append("visual")  # M3 no disponible externamente -> fallback: se omite
                    c_reason.append("visual_unavailable_fallback")
                    continue
                if action == "infrastructure":
                    prob = float(p1[i]); stage = 1; spent += pol.costs["infrastructure"]
                elif action == "content":
                    prob = float(p2[i]); stage = 2; spent += pol.costs["content"]
                consulted.append(action)
            c_prob[i] = prob
            c_stage[i] = stage
            c_pred[i] = 1 if prob >= (tau0 if stage == 0 else tau1 if stage == 1 else tau2) else 0
        return {"prob": c_prob, "pred": c_pred, "abst": c_abst, "stage": c_stage, "reasons": c_reason,
                "policy": pol}

    cfg_c = run_config_c(0.20)
    c_prob, c_pred, c_abst, c_stage, c_reason = (cfg_c["prob"], cfg_c["pred"], cfg_c["abst"],
                                                 cfg_c["stage"], cfg_c["reasons"])
    pol = cfg_c["policy"]
    dec = ~c_abst
    casc["Config_C_cascada_corregida_BUG04"] = {
        "policy": {"uncertainty_threshold_early_stop": pol.uncertainty_threshold,
                   "abstention_threshold_final": pol.abstention_threshold,
                   "minimum_confidence": pol.minimum_confidence, "budget": pol.budget},
        "metrics_full_coverage_abstain_as_positive": compute_basic_metrics(y, np.where(c_abst, 1, c_pred), c_prob),
        "selective_metrics_decided_only": compute_basic_metrics(y[dec], c_pred[dec], c_prob[dec]) if dec.any() else {},
        "coverage": round(float(dec.mean()), 6),
        "abstained_total": int(c_abst.sum()),
        "abstained_phishing": int(y[c_abst].sum()),
        "abstained_legitimate": int((1 - y[c_abst]).sum()),
        "stopping_counts": {f"M{k}": int((c_stage == k).sum()) for k in range(3)},
        "avg_modalities": round(float((c_stage + 1).mean()), 4),
        "early_exit_errors": {
            "fn_at_M0": int(((c_stage == 0) & (y == 1) & (c_pred == 0)).sum()),
            "fn_at_M1": int(((c_stage == 1) & (y == 1) & (c_pred == 0)).sum()),
            "silent_fn_total": int(((y == 1) & (c_pred == 0) & (~c_abst)).sum()),
        },
        "decision_reasons": dict(__import__("collections").Counter(c_reason)),
        "risk_coverage": risk_coverage(y, c_prob, c_pred),
    }

    # 5b) Regresión BUG-04 sobre datos EXTERNOS: el umbral de abstención final debe
    #     gobernar realmente la decisión (antes era ignorado por el motor).
    sweep: dict[str, Any] = {}
    for thr in (0.01, 0.20, 0.99):
        run = run_config_c(thr)
        dec = ~run["abst"]
        sweep[f"abstention_threshold={thr}"] = {
            "uncertainty_threshold_early_stop": 0.15,
            "abstention_threshold_final": thr,
            "abstained_total": int(run["abst"].sum()),
            "abstained_phishing": int(y[run["abst"]].sum()),
            "abstained_legitimate": int((1 - y[run["abst"]]).sum()),
            "coverage": round(float(dec.mean()), 6),
            "f1_decided_only": (compute_basic_metrics(y[dec], run["pred"][dec], run["prob"][dec]).get("f1")
                                 if dec.any() else None),
            "f1_abstain_as_positive_full_denominator": compute_basic_metrics(
                y, np.where(run["abst"], 1, run["pred"]), run["prob"]).get("f1"),
        }
    sweep["assertion_threshold_has_effect"] = bool(
        sweep["abstention_threshold=0.01"]["abstained_total"]
        != sweep["abstention_threshold=0.99"]["abstained_total"])
    casc["sensibilidad_abstention_threshold_BUG04"] = sweep

    # 6) Políticas operativas sobre las abstenciones de M5 original (fail-open/closed/forced)
    mp = cas_forced["_arrays"]
    abst = mp["abstained"]
    fp_pred, fc_pred, ft_pred = mp["final_pred"].copy(), mp["final_pred"].copy(), mp["final_pred"].copy()
    fc_pred[abst] = 1                      # fail-closed: bloquear/incriminar abstención
    fp_pred[abst] = 0                      # fail-open: pasar abstención como legítima
    ft_pred[abst] = (mp["final_prob"][abst] >= tau2).astype(int)  # forced-threshold
    casc["politicas_sobre_abstenciones"] = {
        "n_abstained": int(abst.sum()),
        "fail_closed_bloquear": compute_basic_metrics(y, fc_pred, mp["final_prob"]),
        "fail_open_permitir": compute_basic_metrics(y, fp_pred, mp["final_prob"]),
        "forced_threshold": compute_basic_metrics(y, ft_pred, mp["final_prob"]),
        "note": "Ninguna política cuenta las abstenciones como clasificación correcta; "
                "se muestran los tres tratamientos explícitos sobre el mismo denominador total.",
    }

    # Paired McNemar entre cascadas (sobre predicciones forzadas, mismo denominador)
    cascade_preds = {
        "M2_sin_cascada": (p2 >= tau2).astype(int),
        "M4_original_forzada": mp["final_pred"],
        "Cascada_conservadora": cons["_arrays"]["final_pred"],
        "Config_C_corregida": c_pred,
    }
    pair_names = [("M2_sin_cascada", "Cascada_conservadora"),
                  ("M2_sin_cascada", "Config_C_corregida"),
                  ("M4_original_forzada", "Cascada_conservadora"),
                  ("M4_original_forzada", "Config_C_corregida")]
    cascade_paired = {f"{a}__vs__{b}": mcnemar_exact(y, cascade_preds[a], cascade_preds[b]) for a, b in pair_names}
    hp = holm_adjust({k: v["mcnemar_exact_two_sided_p"] for k, v in cascade_paired.items()})
    for k, v in cascade_paired.items():
        v["holm_adjusted_p"] = hp[k]

    # ---------------- ITE vs Complete-Case ----------------
    from collections import Counter

    def avail_by(mask_key: str) -> dict[str, float]:
        out = {}
        for lbl in ("phishing", "legitimate"):
            sel = [s for s in status if s["label"] == lbl]
            if not sel:
                continue
            if mask_key == "infra":
                out[lbl] = round(float(np.mean([s["infra_status"] == "success" for s in sel])), 4)
            elif mask_key == "content":
                out[lbl] = round(float(np.mean([s["content_status"] == "success" for s in sel])), 4)
            else:
                out[lbl] = round(float(cc[np.array([s["label"] == lbl for s in status])].mean()), 4)
        return out

    # Estrategia de respaldo: si la modalidad no está disponible, usar M0 (URL solamente)
    fb_prob = np.where(cc, p2, p0)
    fb_pred = (fb_prob >= np.where(cc, tau2, tau0)).astype(int)
    silent_fn_fb = int(((y == 1) & (fb_pred == 0)).sum())
    silent_fn_cc = int(((y == 1) & (cc) & ((p2 >= tau2).astype(int) == 0)).sum())

    ite = {
        "n_attempted": int(len(y)),
        "n_phishing": int(y.sum()),
        "n_legitimate": int((1 - y).sum()),
        "infra_availability": avail_by("infra"),
        "content_availability": avail_by("content"),
        "complete_case_availability": avail_by("cc"),
        "n_complete_case": int(cc.sum()),
        "n_incomplete": int((~cc).sum()),
        "incomplete_rate": round(float((~cc).mean()), 4),
        "acquisition_errors_by_class": {
            lbl: dict(Counter(f"{s['infra_status']}/{s['infra_error']}|{s['content_status']}/{s['content_error']}"
                              for s in status if s["label"] == lbl))
            for lbl in ("phishing", "legitimate")
        },
        "M0_fallback_on_incomplete": {
            "n": int((~cc).sum()),
            "metrics": safe_metrics(y[~cc], p0[~cc], tau0) if (~cc).sum() >= 10 else {},
        },
        "strategy_fallback_M0_when_modality_missing_ITE": safe_metrics(y, fb_prob, float(tau2),
                                                                                  y_pred_override=fb_pred),
        "silent_false_negatives": {
            "fallback_strategy_total": silent_fn_fb,
            "complete_case_only": silent_fn_cc,
            "note": "Falsos negativos sin abstención (decisión legítima incorrecta) sobre el denominador correspondiente",
        },
        "latency_ms_measured": {
            "m0_feature_extraction_p50": round(float(np.percentile(lat0, 50)), 3),
            "m0_feature_extraction_p95": round(float(np.percentile(lat0, 95)), 3),
            "infra_dns_tls_http_p50": round(float(np.percentile(lat1, 50)), 2),
            "infra_dns_tls_http_p95": round(float(np.percentile(lat1, 95)), 2),
            "http_download_p50": round(float(np.percentile(lat2, 50)), 2),
            "http_download_p95": round(float(np.percentile(lat2, 95)), 2),
            "probe_wall_seconds_total": probe_seconds,
            "model_inference_batch_seconds": infer_seconds,
        },
        "inference_note": "Tiempos medidos con reloj monotónico sobre peticiones HTTP/DNS reales; "
                          "no son sumas de medianas ni simulaciones.",
    }

    complete_case = {
        "n_cc": int(cc.sum()),
        "n_cc_phishing": int(y[cc].sum()),
        "n_cc_legitimate": int((1 - y[cc]).sum()),
        "models": {
            "M0_cc": safe_metrics(y[cc], p0[cc], tau0),
            "M1_cc": safe_metrics(y[cc], p1[cc], tau1),
            "M2_cc": safe_metrics(y[cc], p2[cc], tau2),
        },
        "warning": "Resultados complete-case (N=%d) NO representan a los %d intentos; reportar ambos." % (int(cc.sum()), int(len(y))),
    }
    # Same models evaluated over ITE (all attempts, without filtering)
    complete_case["models_ite_denominator"] = {
        "M0_ite_all_attempts": safe_metrics(y, p0, tau0),
        "M1_ite_all_attempts": safe_metrics(y, p1, tau1),
        "M2_ite_all_attempts": safe_metrics(y, p2, tau2),
    }

    out = {
        "probe_config": {"n_per_class": N_PROBE_PER_CLASS, "n_total": int(len(y)), "seed": SEED},
        "cascade_results": casc,
        "cascade_paired_tests": cascade_paired,
        "intention_to_evaluate": ite,
        "complete_case": complete_case,
        "raw_probe_file": "artifacts/corrections_phase2/eval/probe_raw.jsonl",
        "raw_probe_sha256": sha256_file(EVAL / "probe_raw.jsonl"),
    }
    (EVAL / "probe_and_cascade_metrics.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    # Predicciones individuales del sondeo (recomputables)
    with open(EVAL / "probe_predictions.csv", "w", encoding="utf-8", newline="") as f:
        fields = ["cohort2_id", "canonical_url", "label", "source", "infra_status", "content_status",
                  "complete_case", "p_m0", "p_m1", "p_m2", "m5_final_prob", "m5_pred", "m5_abstained",
                  "m5_stop_stage", "conservative_prob", "conservative_pred", "configC_prob", "configC_pred",
                  "configC_abstained", "configC_stage", "lat_m0_ms", "lat_infra_ms", "lat_content_ms"]
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for i, r in enumerate(probe_rows):
            pr = probe_map[r["cohort2_id"]]
            w.writerow({
                "cohort2_id": r["cohort2_id"], "canonical_url": r["canonical_url"], "label": r["label"],
                "source": r["source"], "infra_status": pr["infra"].get("status"),
                "content_status": pr["content"].get("status"), "complete_case": int(cc[i]),
                "p_m0": f"{p0[i]:.6f}", "p_m1": f"{p1[i]:.6f}", "p_m2": f"{p2[i]:.6f}",
                "m5_final_prob": f"{mp['final_prob'][i]:.6f}", "m5_pred": int(mp["final_pred"][i]),
                "m5_abstained": int(abst[i]), "m5_stop_stage": int(mp["stop_stage"][i]),
                "conservative_prob": f"{cons['_arrays']['final_prob'][i]:.6f}",
                "conservative_pred": int(cons["_arrays"]["final_pred"][i]),
                "configC_prob": f"{c_prob[i]:.6f}", "configC_pred": int(c_pred[i]),
                "configC_abstained": int(c_abst[i]), "configC_stage": int(c_stage[i]),
                "lat_m0_ms": f"{lat0[i]:.3f}", "lat_infra_ms": f"{lat1[i]:.3f}", "lat_content_ms": f"{lat2[i]:.3f}",
            })
    out["probe_predictions_sha256"] = sha256_file(EVAL / "probe_predictions.csv")
    (EVAL / "probe_and_cascade_metrics.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Complete-case {int(cc.sum())}/{int(len(y))} | abstenciones ConfigC="
          f"{int(c_abst.sum())} | conservadora FN@M0={cons['early_exit_errors']['fn_at_M0']}", flush=True)
    return out


# --------------------------------------------------------------------- Bloque D
def block_d() -> dict[str, Any]:
    """Recomputa las métricas internas desde los predictions.csv congelados (test)."""
    print("\n=== BLOQUE D: recomputación interna desde predicciones congeladas ===", flush=True)
    targets = {
        "M0_url_baseline": "artifacts/url-baseline-0.2.0/predictions.csv",
        "M0_cc": "artifacts/m0-real/predictions.csv",
        "M1": "artifacts/m1-real/predictions.csv",
        "M2": "artifacts/m2-real/predictions.csv",
        "M3": "artifacts/m3-real/predictions.csv",
        "M4": "artifacts/m4-real/predictions.csv",
        "M5": "artifacts/m5-real/predictions.csv",
    }
    out: dict[str, Any] = {}
    arrays: dict[str, tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]] = {}
    for name, rel in targets.items():
        p = ROOT / rel
        if not p.exists():
            out[name] = {"status": "missing", "path": rel}
            continue
        ys, ps, pr, ab = [], [], [], []
        with open(p, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                part = (r.get("partition") or r.get("split") or "test").strip()
                if part != "test":
                    continue
                ys.append(1 if str(r.get("label", "0")).lower() in ("1", "phishing", "true") else 0)
                ps.append(float(r.get("probability_phishing", r.get("probability", 0.0))))
                pr.append(1 if str(r.get("prediction", r.get("predicted_label", "0"))).lower() in ("1", "phishing", "true") else 0)
                ab.append(str(r.get("abstained", "0")).strip().lower() in ("true", "1"))
        y = np.array(ys); prob = np.array(ps); pred = np.array(pr); abst = np.array(ab)
        m = compute_basic_metrics(y, pred, prob)
        m["n_abstained"] = int(abst.sum())
        m["coverage"] = round(float((~abst).mean()), 6) if abst.any() else 1.0
        m["source_file"] = rel
        m["source_sha256"] = sha256_file(p)
        out[name] = m
        arrays[name] = (y, prob, pred, abst)

    paired = {}
    if "M4" in arrays and "M5" in arrays:
        y4, _, p4, _ = arrays["M4"]
        y5, _, p5, _ = arrays["M5"]
        if len(y4) == len(y5):
            paired["M4_vs_M5"] = mcnemar_exact(y4, p4, p5)
    (EVAL / "internal_recomputed_metrics.json").write_text(
        json.dumps({"models": out, "paired_tests": paired}, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"models": out, "paired_tests": paired}


# --------------------------------------------------------------------- Bloque E
def block_e(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Experimento pareado directo de la normalización www. (BUG-07)."""
    print("\n=== BLOQUE E: experimento pareado www. vs sin www. ===", flush=True)
    import joblib

    from phishguard_ml import features as feat_mod

    m0 = joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")
    clf, names, tau = m0["model"], list(m0["feature_names"]), float(m0["threshold"])
    rng = np.random.default_rng(SEED)
    phish = [r for r in rows if r["label"] == "phishing"]
    legit = [r for r in rows if r["label"] == "legitimate"]
    sample = ([phish[i] for i in rng.choice(len(phish), 150, replace=False)]
              + [legit[i] for i in rng.choice(len(legit), 150, replace=False)])

    variants: list[dict[str, Any]] = []
    for r in sample:
        base = r["host"]
        no_www = base[4:] if base.lower().startswith("www.") else base
        with_www = no_www if no_www.lower().startswith("www.") else "www." + no_www
        for v in (no_www, with_www):
            variants.append({"cohort2_id": r["cohort2_id"], "label": r["label_int"],
                             "registered_domain": r["registered_domain"], "host_variant": v})

    def probs_with(normalized: bool) -> np.ndarray:
        ctxs = []
        for v in variants:
            ctxs.append(extract_url_features(UrlFeatureContext("https://" + v["host_variant"] + "/",
                                                               v["registered_domain"])))
        X = np.array([[f[k] for k in names] for f in ctxs], dtype=np.float64)
        return clf.predict_proba(X)[:, 1]

    p_norm = probs_with(True)
    with patch.object(feat_mod, "_strip_www", lambda h: h):
        p_orig = probs_with(False)

    yv = np.array([v["label"] for v in variants])
    hosts = np.array([v["host_variant"] for v in variants])
    is_www = np.array([h.lower().startswith("www.") for h in hosts])
    ids = np.array([v["cohort2_id"] for v in variants])

    res = {
        "n_urls": len(variants),
        "n_unique_samples": len({v['cohort2_id'] for v in variants}),
        "FPR_M0_original_on_www_legit": round(float(((p_orig >= tau) & (yv == 0) & is_www).sum() /
                                                    max(1, ((yv == 0) & is_www).sum())), 6),
        "FPR_M0_normalizado_on_www_legit": round(float(((p_norm >= tau) & (yv == 0) & is_www).sum() /
                                                       max(1, ((yv == 0) & is_www).sum())), 6),
        "FPR_M0_original_on_nonwww_legit": round(float(((p_orig >= tau) & (yv == 0) & ~is_www).sum() /
                                                       max(1, ((yv == 0) & ~is_www).sum())), 6),
        "FPR_M0_normalizado_on_nonwww_legit": round(float(((p_norm >= tau) & (yv == 0) & ~is_www).sum() /
                                                          max(1, ((yv == 0) & ~is_www).sum())), 6),
        "mean_abs_prob_shift_normalization": round(float(np.abs(p_orig - p_norm).mean()), 6),
        "max_abs_prob_shift_normalization": round(float(np.abs(p_orig - p_norm).max()), 6),
        "threshold": tau,
    }
    # pareado por muestra: predicción con/www vs sin/www bajo cada brazo
    by_id: dict[str, dict[str, Any]] = {}
    for i, v in enumerate(variants):
        by_id.setdefault(v["cohort2_id"], {"y": v["label"], "www": {}, "nowww": {}})
        key = "www" if is_www[i] else "nowww"
        by_id[v["cohort2_id"]][key] = {"orig": p_orig[i], "norm": p_norm[i]}
    flips = {"original_www_vs_nonwww": 0, "normalizado_www_vs_nonwww": 0, "n_pairs": 0}
    for sid, d in by_id.items():
        if not d["www"] or not d["nowww"]:
            continue
        flips["n_pairs"] += 1
        if (d["www"]["orig"] >= tau) != (d["nowww"]["orig"] >= tau):
            flips["original_www_vs_nonwww"] += 1
        if (d["www"]["norm"] >= tau) != (d["nowww"]["norm"] >= tau):
            flips["normalizado_www_vs_nonwww"] += 1
    res["paired_flips"] = flips
    with open(EVAL / "www_paired_predictions.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cohort2_id", "label", "host_variant", "prob_original", "prob_normalizado"],
                           lineterminator="\n")
        w.writeheader()
        for i, v in enumerate(variants):
            w.writerow({"cohort2_id": v["cohort2_id"], "label": v["label"], "host_variant": v["host_variant"],
                        "prob_original": f"{p_orig[i]:.6f}", "prob_normalizado": f"{p_norm[i]:.6f}"})
    res["predictions_sha256"] = sha256_file(EVAL / "www_paired_predictions.csv")
    (EVAL / "www_paired_experiment.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(res, indent=2, ensure_ascii=False), flush=True)
    return res


# --------------------------------------------------------------------- main
def main() -> None:
    EVAL.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()

    freeze = verify_freeze()
    print(f"FREEZE: ok={freeze['ok']} mismatches={freeze['mismatches']}", flush=True)
    if not freeze["ok"]:
        raise SystemExit("ABORT: el freeze no coincide con el código actual")

    psl_path = sorted((ROOT / "data" / "raw").rglob("public_suffix_list.dat"))[-1]
    psl = PublicSuffixList.from_file(psl_path)
    rows = load_cohort()
    print(f"Cohorte2 congelada: {len(rows)} URL", flush=True)

    a = block_a(rows, psl)
    bc = block_b_c(rows, psl)
    d = block_d()
    e = block_e(rows)

    summary = {
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "freeze": freeze,
        "url_level": {
            "n": a["n_total"], "arms": {k: {m: v[m] for m in ("f1", "fpr", "fnr", "precision", "recall", "accuracy")}
                                         for k, v in a["arms"].items()},
            "www_effect": a["www_effect"],
            "paired_tests": a["paired_tests"],
        },
        "probe": {
            "n": bc["probe_config"]["n_total"],
            "complete_case": bc["complete_case"]["n_cc"],
            "ite_fallback_strategy": {k: v for k, v in bc["intention_to_evaluate"]["strategy_fallback_M0_when_modality_missing_ITE"].items()
                                      if k in ("n", "f1", "fpr", "fnr", "precision", "recall")},
            "cascade_f1": {k: (v.get("metrics_full_coverage") or v).get("f1", (v.get("metrics_full_coverage_abstain_as_positive") or {}).get("f1"))
                           for k, v in bc["cascade_results"].items() if isinstance(v, dict)},
        },
        "internal_recomputed": {k: {m: v.get(m) for m in ("n", "f1", "fpr", "fnr")} for k, v in d["models"].items()
                                if isinstance(v, dict)},
        "www_paired_experiment": e,
        "outputs": sorted(str(p.relative_to(ROOT)) for p in EVAL.glob("*")),
    }
    (EVAL / "eval_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n=== EVALUACIÓN COMPLETADA ===", flush=True)
    print(json.dumps(summary["url_level"]["arms"], indent=2), flush=True)
    print(f"Outputs en {EVAL}", flush=True)


if __name__ == "__main__":
    main()
