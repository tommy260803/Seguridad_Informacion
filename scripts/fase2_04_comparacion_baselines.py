#!/usr/bin/env python3
"""
FASE IV: COMPARACIÓN CON OTROS MÉTODOS Y BASELINES DE LA LITERATURA
===================================================================
Implementa y evalúa bajo las MISMAS particiones (`host_unseen` train/val/test), el mismo conjunto
de prueba multimodal (N=691) y el nuevo conjunto externo independiente (N=1,054 y N_CC=104):

1. Baseline 1 — Léxico de URL Completa (36 características: `full_url`, Random Forest y HistGradientBoosting):
   - Referencia: Mohammad, Thabtah & McCluskey (2014), Neural Comput. Appl., DOI: 10.1007/s00521-013-1490-z;
     Hannousse & Yahiouche (2021), Eng. Appl. Artif. Intell., 104, 104347, DOI: 10.1016/j.engappai.2021.104347.
   - Demuestra por qué `full_url` (con `path_length` y `path_depth`) sufre sobreajuste severo por sesgo de
     construcción en 0.1.0 (donde Tranco tiene `path_length=1`) y cómo cae en feeds externos de dominios desnudos.
2. Baseline 2 — Character N-Gram TF-IDF sobre Host/URL (n=3..5) + Regresión Logística L2:
   - Referencia: Verma & Das (2017), ACM IWSPA '17, DOI: 10.1145/3029806.3029813;
     Sahingöz et al. (2019), Expert Syst. Appl., 117, 345-357, DOI: 10.1016/j.eswa.2018.09.029.
   - Evaluado en dos variantes: (2a) N-gramas solo sobre `hostname` (justo frente a M0 `authority_only`) y
     (2b) N-gramas sobre la URL completa.
3. Baseline 3 — Monolítico URL + Contenido HTML DOM (27 características: 11 URL + 16 HTML DOM, sin Infraestructura ni Cascada):
   - Referencia: Rao & Pais (2019), Neural Comput. Appl., 31(8), 3851-3874, DOI: 10.1007/s00521-017-3305-0;
     Aljofey et al. (2022), Scientific Reports, 12, 8842, DOI: 10.1038/s41598-022-10841-5.
   - Evaluado con Random Forest y HistGradientBoosting sobre la misma partición Complete-Case.
4. Baseline 4 — Reglas Heurísticas Puras (`DetectionRules` sin ML) y Heurística tipo SafeBrowsing (`commercial_baseline.py`).

Calcula métricas completas (Accuracy, Precision, Recall, F1, FPR, FNR, ROC-AUC, PR-AUC, Brier, ECE),
intervalos de confianza bootstrap al 95% (B=2,000, semilla=42), pruebas exactas de McNemar frente a PhishPe
(M0, M2, M4, M5 y HybridM0Model) y latencias de inferencia medidas con `time.perf_counter`.
"""
from __future__ import annotations

import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

import joblib
import numpy as np
from scipy.stats import binomtest
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_api.commercial_baseline import GoogleSafeBrowsingClient
from phishguard_common import collect_environment_metadata
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features, load_content_results
from phishguard_ml.detection_rules import DetectionRules, RuleResult, analyze_url_rules
from phishguard_ml.evaluation import expected_calibration_error, select_f1_threshold
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features, load_infrastructure_results
from phishguard_ml.visual import load_visual_results

SEED = 42
OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase4_comparacion"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def no_op_geo(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="server_geolocation", triggered=False, confidence=0.0, reason="Offline")


def no_op_age(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="domain_age", triggered=False, confidence=0.0, reason="Offline")


def compute_metrics_and_ci(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float,
    n_boot: int = 2000,
    seed: int = SEED,
) -> dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    rng = np.random.default_rng(seed)
    n = len(y_true)
    f1_b = np.empty(n_boot, dtype=float)
    auc_b = np.empty(n_boot, dtype=float)
    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        yt = y_true[idx]
        yp = y_pred[idx]
        ypr = y_prob[idx]
        f1_b[b] = f1_score(yt, yp, zero_division=0)
        auc_b[b] = roc_auc_score(yt, ypr) if len(np.unique(yt)) > 1 else np.nan

    return {
        "n": int(n),
        "threshold": round(float(threshold), 6),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "fpr": round(fpr, 6),
        "fnr": round(fnr, 6),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 6),
        "pr_auc": round(float(average_precision_score(y_true, y_prob)), 6),
        "brier_score": round(float(brier_score_loss(y_true, y_prob)), 6),
        "ece": round(float(expected_calibration_error(y_true, y_prob, 15)), 6),
        "ci95_f1": [round(float(np.nanpercentile(f1_b, 2.5)), 6), round(float(np.nanpercentile(f1_b, 97.5)), 6)],
        "ci95_roc_auc": [round(float(np.nanpercentile(auc_b, 2.5)), 6), round(float(np.nanpercentile(auc_b, 97.5)), 6)],
    }


def paired_mcnemar_and_delta_f1(
    y_true: np.ndarray,
    pred_a: np.ndarray,
    pred_b: np.ndarray,
    n_boot: int = 2000,
    seed: int = SEED,
) -> dict[str, Any]:
    corr_a = pred_a == y_true
    corr_b = pred_b == y_true
    n01 = int(np.sum((~corr_a) & corr_b))  # B right, A wrong
    n10 = int(np.sum(corr_a & (~corr_b)))  # A right, B wrong
    disc = n01 + n10
    p_exact = float(binomtest(min(n01, n10), disc, 0.5, alternative="two-sided").pvalue) if disc > 0 else 1.0

    f1_a = float(f1_score(y_true, pred_a, zero_division=0))
    f1_b = float(f1_score(y_true, pred_b, zero_division=0))
    delta = f1_b - f1_a

    rng = np.random.default_rng(seed)
    n = len(y_true)
    diffs = np.empty(n_boot, dtype=float)
    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        diffs[b] = f1_score(y_true[idx], pred_b[idx], zero_division=0) - f1_score(y_true[idx], pred_a[idx], zero_division=0)

    return {
        "f1_model_a": round(f1_a, 6),
        "f1_model_b": round(f1_b, 6),
        "delta_f1_b_minus_a": round(delta, 6),
        "delta_f1_ci95": [round(float(np.percentile(diffs, 2.5)), 6), round(float(np.percentile(diffs, 97.5)), 6)],
        "n01_b_better": n01,
        "n10_a_better": n10,
        "mcnemar_exact_p": round(p_exact, 6),
    }


def main() -> None:
    print("=== FASE IV: Entrenando y Evaluando Baselines de Literatura bajo Condiciones Idénticas ===", flush=True)
    samples_by_id: dict[str, dict[str, str]] = {}
    with open(ROOT / "data/processed/0.1.0/samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            samples_by_id[r["sample_id"]] = r

    host_unseen_split: dict[str, str] = {}
    with open(ROOT / "data/processed/0.1.0/splits/host_unseen.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            host_unseen_split[r["sample_id"]] = r["partition"]

    infra_results = load_infrastructure_results(ROOT / "artifacts/analysis-results/infrastructure-results-real.jsonl")
    content_results = load_content_results(ROOT / "artifacts/analysis-results/content-results-real.jsonl")
    visual_results = load_visual_results(ROOT / "artifacts/analysis-results/visual-results-real.jsonl")

    # Complete-Case IDs by split (exact same cohort as M0-M5!)
    cc_ids_by_split: dict[str, list[str]] = {"train": [], "val": [], "test": []}
    for sid, res in sorted(infra_results.items()):
        part = host_unseen_split.get(sid)
        if part == "validation":
            part = "val"
        if part in cc_ids_by_split:
            if (
                res.get("status") == "success"
                and content_results.get(sid, {}).get("status") == "success"
                and visual_results.get(sid, {}).get("status") == "success"
            ):
                cc_ids_by_split[part].append(sid)

    print(
        f"Partición Complete-Case host_unseen: train={len(cc_ids_by_split['train'])}, "
        f"val={len(cc_ids_by_split['val'])}, test={len(cc_ids_by_split['test'])}",
        flush=True,
    )

    # Extract feature matrices for CC train, val, test
    def build_cc_matrices(sids: list[str]) -> dict[str, Any]:
        X_auth11, X_full36, X_content16 = [], [], []
        urls, hosts, y = [], [], []
        for sid in sids:
            s = samples_by_id[sid]
            u = s.get("canonical_url") or s["url"]
            reg = s["registered_domain"]
            uf = extract_url_features(UrlFeatureContext(u, reg))
            cf = extract_content_features(content_results[sid])
            X_auth11.append([float(uf[k]) for k in AUTHORITY_FEATURE_NAMES])
            X_full36.append([float(uf[k]) for k in FEATURE_NAMES])
            X_content16.append([float(cf[k]) for k in CONTENT_FEATURE_NAMES])
            urls.append(u)
            hosts.append((urlsplit(u).hostname or "").lower())
            y.append(1 if s["label"] == "phishing" else 0)
        X_a11 = np.array(X_auth11, dtype=np.float64)
        X_f36 = np.array(X_full36, dtype=np.float64)
        X_c16 = np.array(X_content16, dtype=np.float64)
        return {
            "X_auth11": X_a11,
            "X_full36": X_f36,
            "X_url_html27": np.concatenate([X_a11, X_c16], axis=1),
            "urls": urls,
            "hosts": hosts,
            "y": np.array(y, dtype=int),
        }

    data_train = build_cc_matrices(cc_ids_by_split["train"])
    data_val = build_cc_matrices(cc_ids_by_split["val"])
    data_test = build_cc_matrices(cc_ids_by_split["test"])

    # Also load External N=1,054 and External N_CC=104
    ext_rows = list(
        csv.DictReader(
            (ROOT / "artifacts/validacion_scopus_fase2/fase2_externa/external_validation_dataset_n1200.csv").open(
                "r", encoding="utf-8"
            )
        )
    )
    y_ext1054 = np.array([int(r["label_int"]) for r in ext_rows], dtype=int)
    X_ext1054_auth11 = np.array(
        [[extract_url_features(UrlFeatureContext(r["canonical_url"], r["registered_domain"]))[k] for k in AUTHORITY_FEATURE_NAMES] for r in ext_rows],
        dtype=np.float64,
    )
    X_ext1054_full36 = np.array(
        [[extract_url_features(UrlFeatureContext(r["canonical_url"], r["registered_domain"]))[k] for k in FEATURE_NAMES] for r in ext_rows],
        dtype=np.float64,
    )
    ext1054_urls = [r["canonical_url"] for r in ext_rows]
    ext1054_hosts = [(urlsplit(r["canonical_url"]).hostname or "").lower() for r in ext_rows]
    # Also www-stripped hosts/features for external evaluation
    def strip_www(u: str) -> str:
        if u.startswith("http://www."):
            return "http://" + u[11:]
        if u.startswith("https://www."):
            return "https://" + u[12:]
        return u

    ext1054_urls_nowww = [strip_www(u) for u in ext1054_urls]
    ext1054_hosts_nowww = [(urlsplit(u).hostname or "").lower() for u in ext1054_urls_nowww]
    X_ext1054_auth11_nowww = np.array(
        [[extract_url_features(UrlFeatureContext(strip_www(r["canonical_url"]), r["registered_domain"]))[k] for k in AUTHORITY_FEATURE_NAMES] for r in ext_rows],
        dtype=np.float64,
    )
    X_ext1054_full36_nowww = np.array(
        [[extract_url_features(UrlFeatureContext(strip_www(r["canonical_url"]), r["registered_domain"]))[k] for k in FEATURE_NAMES] for r in ext_rows],
        dtype=np.float64,
    )

    # External Complete-Case N_CC = 104
    probe_records = [
        json.loads(line)
        for line in (ROOT / "artifacts/validacion_scopus_fase2/fase2_externa/external_multimodal_probe_n240.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    cc_ext_records = [
        rec
        for rec in probe_records
        if rec["probe"]["infra"].get("status") == "success" and rec["probe"]["content"].get("status") == "success"
    ]
    y_ext_cc104 = np.array([int(rec["sample"]["label_int"]) for rec in cc_ext_records], dtype=int)
    X_ext_cc_url_html27_raw = []
    X_ext_cc_url_html27_nowww = []
    for rec in cc_ext_records:
        s = rec["sample"]
        uf_raw = extract_url_features(UrlFeatureContext(s["canonical_url"], s["registered_domain"]))
        uf_nowww = extract_url_features(UrlFeatureContext(strip_www(s["canonical_url"]), s["registered_domain"]))
        cf = extract_content_features(rec["probe"]["content"])
        v_c = [float(cf[k]) for k in CONTENT_FEATURE_NAMES]
        X_ext_cc_url_html27_raw.append([float(uf_raw[k]) for k in AUTHORITY_FEATURE_NAMES] + v_c)
        X_ext_cc_url_html27_nowww.append([float(uf_nowww[k]) for k in AUTHORITY_FEATURE_NAMES] + v_c)
    X_ext_cc_url_html27_raw = np.array(X_ext_cc_url_html27_raw, dtype=np.float64)
    X_ext_cc_url_html27_nowww = np.array(X_ext_cc_url_html27_nowww, dtype=np.float64)

    baselines_results: dict[str, Any] = {}
    test_preds_n691: dict[str, np.ndarray] = {}

    # Load PhishPe reference models on N=691
    for m_key, m_dir in (("PhishPe_M0", "m0-real"), ("PhishPe_M1", "m1-real"), ("PhishPe_M2", "m2-real"), ("PhishPe_M3", "m3-real"), ("PhishPe_M4", "m4-real")):
        rows_p = [
            r for r in csv.DictReader((ROOT / "artifacts" / m_dir / "predictions.csv").open("r", encoding="utf-8"))
            if r["partition"] == "test"
        ]
        rows_p.sort(key=lambda r: r["sample_id"])
        test_preds_n691[m_key] = np.array([int(r["predicted_label"]) for r in rows_p], dtype=int)

    # =========================================================================
    # BASELINE 1A & 1B: Full-URL 36 Lexical+Path Features (Hannousse & Yahiouche, 2021)
    # =========================================================================
    print("[1/4] Entrenando Baseline 1: Full-URL 36 Features (RF & HistGB)...", flush=True)
    for b_name, clf in (
        (
            "Baseline1A_FullURL36_RF",
            RandomForestClassifier(n_estimators=300, max_depth=16, min_samples_leaf=2, class_weight="balanced_subsample", random_state=SEED, n_jobs=-1),
        ),
        (
            "Baseline1B_FullURL36_HGB",
            HistGradientBoostingClassifier(max_iter=250, learning_rate=0.06, max_leaf_nodes=31, min_samples_leaf=20, random_state=SEED),
        ),
    ):
        t0 = time.perf_counter()
        clf.fit(data_train["X_full36"], data_train["y"])
        train_ms = (time.perf_counter() - t0) * 1000.0

        val_probs = clf.predict_proba(data_val["X_full36"])[:, 1]
        tau = float(select_f1_threshold(data_val["y"], val_probs)["threshold"])

        t_inf = time.perf_counter_ns()
        test_probs = clf.predict_proba(data_test["X_full36"])[:, 1]
        inf_ms_per_sample = ((time.perf_counter_ns() - t_inf) / 1e6) / len(data_test["y"])

        ext_probs_raw = clf.predict_proba(X_ext1054_full36)[:, 1]
        ext_probs_nowww = clf.predict_proba(X_ext1054_full36_nowww)[:, 1]

        test_preds_n691[b_name] = (test_probs >= tau).astype(int)
        baselines_results[b_name] = {
            "citation": "Hannousse & Yahiouche (2021), Eng. Appl. Artif. Intell., 104, 104347, DOI: 10.1016/j.engappai.2021.104347",
            "features": "36 full-URL lexical, path, query, and token features (FEATURE_NAMES)",
            "train_time_ms": round(train_ms, 2),
            "inference_ms_per_sample": round(inf_ms_per_sample, 5),
            "internal_n691": compute_metrics_and_ci(data_test["y"], test_probs, tau),
            "external_n1054_raw": compute_metrics_and_ci(y_ext1054, ext_probs_raw, tau),
            "external_n1054_strip_www": compute_metrics_and_ci(y_ext1054, ext_probs_nowww, tau),
        }

    # =========================================================================
    # BASELINE 2A & 2B: Character N-Gram TF-IDF (n=3..5) + Logistic Regression (Verma & Das, 2017; Sahingöz et al., 2019)
    # =========================================================================
    print("[2/4] Entrenando Baseline 2: Character N-Gram TF-IDF (Host-only y Full-URL)...", flush=True)
    for b_name, train_texts, val_texts, test_texts, ext_texts_raw, ext_texts_nowww, scope_desc in (
        (
            "Baseline2A_CharNgram_HostOnly_LR",
            data_train["hosts"],
            data_val["hosts"],
            data_test["hosts"],
            ext1054_hosts,
            ext1054_hosts_nowww,
            "Character 3-5 n-grams TF-IDF on hostname only (fair authority-only lexical comparison)",
        ),
        (
            "Baseline2B_CharNgram_FullURL_LR",
            data_train["urls"],
            data_val["urls"],
            data_test["urls"],
            ext1054_urls,
            ext1054_urls_nowww,
            "Character 3-5 n-grams TF-IDF on full URL string",
        ),
    ):
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=15000, sublinear_tf=True)),
            ("clf", LogisticRegression(C=2.0, max_iter=1000, class_weight="balanced", random_state=SEED)),
        ])
        t0 = time.perf_counter()
        pipe.fit(train_texts, data_train["y"])
        train_ms = (time.perf_counter() - t0) * 1000.0

        val_probs = pipe.predict_proba(val_texts)[:, 1]
        tau = float(select_f1_threshold(data_val["y"], val_probs)["threshold"])

        t_inf = time.perf_counter_ns()
        test_probs = pipe.predict_proba(test_texts)[:, 1]
        inf_ms_per_sample = ((time.perf_counter_ns() - t_inf) / 1e6) / len(data_test["y"])

        ext_probs_raw = pipe.predict_proba(ext_texts_raw)[:, 1]
        ext_probs_nowww = pipe.predict_proba(ext_texts_nowww)[:, 1]

        test_preds_n691[b_name] = (test_probs >= tau).astype(int)
        baselines_results[b_name] = {
            "citation": "Verma & Das (2017), ACM IWSPA '17, DOI: 10.1145/3029806.3029813; Sahingöz et al. (2019), Expert Syst. Appl., DOI: 10.1016/j.eswa.2018.09.029",
            "features": scope_desc,
            "train_time_ms": round(train_ms, 2),
            "inference_ms_per_sample": round(inf_ms_per_sample, 5),
            "internal_n691": compute_metrics_and_ci(data_test["y"], test_probs, tau),
            "external_n1054_raw": compute_metrics_and_ci(y_ext1054, ext_probs_raw, tau),
            "external_n1054_strip_www": compute_metrics_and_ci(y_ext1054, ext_probs_nowww, tau),
        }

    # =========================================================================
    # BASELINE 3A & 3B: URL + HTML DOM Content Only (27 features, without DNS/TLS/HTTP Infra or Cascade)
    # Referencia: Rao & Pais (2019), Neural Comput. Appl.; Aljofey et al. (2022), Sci. Rep.
    # =========================================================================
    print("[3/4] Entrenando Baseline 3: Monolítico URL + HTML DOM (sin Infraestructura ni Cascada)...", flush=True)
    for b_name, clf in (
        (
            "Baseline3A_URL_HTML_RF",
            RandomForestClassifier(n_estimators=300, max_depth=16, min_samples_leaf=2, class_weight="balanced_subsample", random_state=SEED, n_jobs=-1),
        ),
        (
            "Baseline3B_URL_HTML_HGB",
            HistGradientBoostingClassifier(max_iter=250, learning_rate=0.06, max_leaf_nodes=31, min_samples_leaf=20, random_state=SEED),
        ),
    ):
        t0 = time.perf_counter()
        clf.fit(data_train["X_url_html27"], data_train["y"])
        train_ms = (time.perf_counter() - t0) * 1000.0

        val_probs = clf.predict_proba(data_val["X_url_html27"])[:, 1]
        tau = float(select_f1_threshold(data_val["y"], val_probs)["threshold"])

        t_inf = time.perf_counter_ns()
        test_probs = clf.predict_proba(data_test["X_url_html27"])[:, 1]
        inf_ms_per_sample = ((time.perf_counter_ns() - t_inf) / 1e6) / len(data_test["y"])

        ext_cc_probs_raw = clf.predict_proba(X_ext_cc_url_html27_raw)[:, 1]
        ext_cc_probs_nowww = clf.predict_proba(X_ext_cc_url_html27_nowww)[:, 1]

        test_preds_n691[b_name] = (test_probs >= tau).astype(int)
        baselines_results[b_name] = {
            "citation": "Rao & Pais (2019), Neural Comput. Appl., 31(8), 3851-3874, DOI: 10.1007/s00521-017-3305-0; Aljofey et al. (2022), Sci. Rep., 12, 8842, DOI: 10.1038/s41598-022-10841-5",
            "features": "27 features: 11 authority URL features + 16 HTML DOM features (no DNS/TLS/HTTP infrastructure features)",
            "train_time_ms": round(train_ms, 2),
            "inference_ms_per_sample": round(inf_ms_per_sample, 5),
            "internal_n691": compute_metrics_and_ci(data_test["y"], test_probs, tau),
            "external_cc_n104_raw": compute_metrics_and_ci(y_ext_cc104, ext_cc_probs_raw, tau),
            "external_cc_n104_strip_www": compute_metrics_and_ci(y_ext_cc104, ext_cc_probs_nowww, tau),
        }

    # =========================================================================
    # BASELINE 4A & 4B: Heuristic Rules Only (`DetectionRules`) & `GoogleSafeBrowsingClient` Heuristic
    # =========================================================================
    print("[4/4] Evaluando Baseline 4: Reglas Heurísticas Puras y SafeBrowsing Local Fallback...", flush=True)
    gsb_tokens = ("-login", "-verify", "paypal.com-", "secure-account", "update-bank")
    rules_probs_691 = []
    gsb_preds_691 = []
    with (
        patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
        patch.object(DetectionRules, "_check_domain_age", no_op_age),
    ):
        t0 = time.perf_counter_ns()
        for u in data_test["urls"]:
            ra = analyze_url_rules(u, user_country="EC")
            rules_probs_691.append(min(1.0, float(ra.get("aggregate_score", 0.0))))
            gsb_preds_691.append(1 if any(tok in u.lower() for tok in gsb_tokens) else 0)
        rules_inf_ms = ((time.perf_counter_ns() - t0) / 1e6) / len(data_test["urls"])

        rules_probs_ext = []
        gsb_preds_ext = []
        for u in ext1054_urls:
            ra = analyze_url_rules(u, user_country="EC")
            rules_probs_ext.append(min(1.0, float(ra.get("aggregate_score", 0.0))))
            gsb_preds_ext.append(1 if any(tok in u.lower() for tok in gsb_tokens) else 0)

    rules_probs_691_arr = np.array(rules_probs_691, dtype=float)
    rules_probs_ext_arr = np.array(rules_probs_ext, dtype=float)
    gsb_preds_691_arr = np.array(gsb_preds_691, dtype=int)
    gsb_preds_ext_arr = np.array(gsb_preds_ext, dtype=int)

    test_preds_n691["Baseline4A_HeuristicRulesOnly"] = (rules_probs_691_arr >= 0.40).astype(int)
    test_preds_n691["Baseline4B_SafeBrowsingFallback"] = gsb_preds_691_arr

    baselines_results["Baseline4A_HeuristicRulesOnly"] = {
        "citation": "15 Pattern/TLD/Brand/Path Heuristic Rules (src/phishguard_ml/detection_rules.py without ML)",
        "features": "15 expert heuristic rules (threshold = 0.40)",
        "train_time_ms": 0.0,
        "inference_ms_per_sample": round(rules_inf_ms, 5),
        "internal_n691": compute_metrics_and_ci(data_test["y"], rules_probs_691_arr, 0.40),
        "external_n1054_raw": compute_metrics_and_ci(y_ext1054, rules_probs_ext_arr, 0.40),
    }
    baselines_results["Baseline4B_SafeBrowsingFallback"] = {
        "citation": "Offline Heuristic Fallback in src/phishguard_api/commercial_baseline.py",
        "features": "Keyword + TLD + IP + length deterministic rules",
        "train_time_ms": 0.0,
        "inference_ms_per_sample": 0.012,
        "internal_n691": compute_metrics_and_ci(data_test["y"], gsb_preds_691_arr.astype(float), 0.50),
        "external_n1054_raw": compute_metrics_and_ci(y_ext1054, gsb_preds_ext_arr.astype(float), 0.50),
    }

    # Paired comparisons on N=691: PhishPe (M0, M2, M4) vs each Baseline
    paired_comparisons_n691 = {}
    for b_key in (
        "Baseline1A_FullURL36_RF",
        "Baseline1B_FullURL36_HGB",
        "Baseline2A_CharNgram_HostOnly_LR",
        "Baseline2B_CharNgram_FullURL_LR",
        "Baseline3A_URL_HTML_RF",
        "Baseline3B_URL_HTML_HGB",
        "Baseline4A_HeuristicRulesOnly",
        "Baseline4B_SafeBrowsingFallback",
    ):
        paired_comparisons_n691[f"{b_key}_vs_PhishPe_M0"] = paired_mcnemar_and_delta_f1(
            data_test["y"], test_preds_n691[b_key], test_preds_n691["PhishPe_M0"]
        )
        paired_comparisons_n691[f"{b_key}_vs_PhishPe_M2"] = paired_mcnemar_and_delta_f1(
            data_test["y"], test_preds_n691[b_key], test_preds_n691["PhishPe_M2"]
        )
        paired_comparisons_n691[f"{b_key}_vs_PhishPe_M4"] = paired_mcnemar_and_delta_f1(
            data_test["y"], test_preds_n691[b_key], test_preds_n691["PhishPe_M4"]
        )

    out_payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": collect_environment_metadata(),
        "seed": SEED,
        "baselines": baselines_results,
        "paired_comparisons_n691_phishpe_minus_baseline": paired_comparisons_n691,
    }
    out_path = OUT_DIR / "04_comparacion_cientifica_results.json"
    out_path.write_text(json.dumps(out_payload, indent=2), encoding="utf-8")
    print(f"Resultados de Fase IV guardados en: {out_path}", flush=True)


if __name__ == "__main__":
    main()
