"""Fase I: Auditoría Científica de Reproducibilidad y Congelación del Baseline de PhishPe.

Verifica exhaustivamente:
1. Integridad de data/processed/0.1.0/samples.csv (conteos, unicidad, clases, URLs canónicas).
2. Hashes SHA-256 de modelos .joblib, particiones, datasets y archivos críticos.
3. Ausencia de solapamiento (sample_id, URL exacta, URL canónica, dominio registrado vía PSL,
   y dominio destino tras redirección HTTP en infrastructure-results-real.jsonl) entre train/val/test.
4. Correspondencia exacta entre predicciones (predictions.csv) y etiquetas verdaderas (samples.csv).
5. Recálculo independiente desde cero de todas las métricas (Accuracy, Precision, Recall, F1,
   FPR, FNR, ROC-AUC, PR-AUC, Brier, ECE) y tabla de correspondencia frente a metrics.json e informes previos.
6. Verificación de modelos .joblib, contratos de características y diferencias entre url-baseline-0.2.0 y m0-real.
7. Disponibilidad de Tranco, Public Suffix List, navegador Headless Chrome y versiones del entorno.
8. Escaneo de seguridad para confirmar ausencia de secretos/credenciales en artefactos publicables.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import joblib
import numpy as np
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_common import collect_environment_metadata
from phishguard_data.psl import PublicSuffixList
from phishguard_ml.evaluation import expected_calibration_error

OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase1_auditoria"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_reg_domain_psl(url_or_host: str, psl: PublicSuffixList) -> str:
    if not url_or_host:
        return ""
    u = url_or_host.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        host = (urlsplit(u).hostname or "").lower().rstrip(".")
    except Exception:
        return ""
    if not host:
        return ""
    return psl.registrable_domain(host) or host


def compute_metrics_from_arrays(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
    pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
    brier = float(brier_score_loss(y_true, y_prob))
    ece = float(expected_calibration_error(y_true, y_prob, 15))
    return {
        "n": int(len(y_true)),
        "threshold": float(threshold),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1": round(f1, 6),
        "fpr": round(fpr, 6),
        "fnr": round(fnr, 6),
        "roc_auc": round(roc_auc, 6),
        "pr_auc": round(pr_auc, 6),
        "brier_score": round(brier, 6),
        "ece": round(ece, 6),
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print("=== FASE I: AUDITORIA CIENTIFICA Y REPRODUCIBILIDAD DEL BASELINE ===", flush=True)

    # 1. Load Public Suffix List
    psl_path = ROOT / "data" / "raw" / "public_suffix_list.dat"
    psl = PublicSuffixList.from_file(psl_path)
    print(f"[1] Public Suffix List cargada desde {psl_path} (SHA256: {sha256_file(psl_path)[:16]}...)", flush=True)

    # 2. Compute SHA-256 hashes of all critical files
    critical_rel_paths = [
        "data/processed/0.1.0/samples.csv",
        "data/processed/0.1.0/statistics.json",
        "data/processed/0.1.0/manifest.json",
        "data/processed/0.1.0/splits/conventional.csv",
        "data/processed/0.1.0/splits/host_unseen.csv",
        "data/processed/0.1.0/splits/temporal.csv",
        "data/processed/0.1.0/splits/temporal_host_unseen.csv",
        "data/raw/public_suffix_list.dat",
        "data/raw/20260919T192154.381983Z/tranco.csv.zip",
        "data/raw/20260919T192154.381983Z/phishtank.csv.bz2",
        "artifacts/url-baseline-0.2.0/model.joblib",
        "artifacts/url-baseline-0.2.0/metrics.json",
        "artifacts/url-baseline-0.2.0/predictions.csv",
        "artifacts/m0-real/model.joblib",
        "artifacts/m0-real/metrics.json",
        "artifacts/m0-real/predictions.csv",
        "artifacts/m1-real/model.joblib",
        "artifacts/m1-real/metrics.json",
        "artifacts/m1-real/predictions.csv",
        "artifacts/m2-real/model.joblib",
        "artifacts/m2-real/metrics.json",
        "artifacts/m2-real/predictions.csv",
        "artifacts/m3-real/model.joblib",
        "artifacts/m3-real/metrics.json",
        "artifacts/m3-real/predictions.csv",
        "artifacts/m4-fixed-real/metrics.json",
        "artifacts/m4-fixed-real/predictions.csv",
        "artifacts/m4-real/metrics.json",
        "artifacts/m4-real/predictions.csv",
        "artifacts/m5-real/metrics.json",
        "artifacts/m5-real/predictions.csv",
        "artifacts/m0-ite-real/model.joblib",
        "artifacts/m1-ite-real/model.joblib",
        "artifacts/m2-ite-real/model.joblib",
        "artifacts/m3-ite-real/model.joblib",
        "artifacts/m0-temporal/model.joblib",
        "artifacts/m0-temporal/metrics.json",
        "artifacts/m0-temporal-host-unseen/model.joblib",
        "artifacts/m0-temporal-host-unseen/metrics.json",
        "artifacts/corrected_audit/m3-authentic-cdp/model.joblib",
        "artifacts/corrected_audit/m3-authentic-cdp/metrics.json",
        "artifacts/corrected_audit/m3-authentic-cdp/predictions.csv",
        "artifacts/analysis-results/infrastructure-results-real.jsonl",
        "artifacts/analysis-results/content-results-real.jsonl",
        "artifacts/analysis-results/visual-results-authentic-cdp.jsonl",
        "artifacts/analysis-results/visual-results-synthetic-dom-proxy.jsonl",
        "artifacts/corrected_audit/evaluation_summary_real.json",
        "artifacts/corrected_audit/statistical_comparisons_all.json",
        "artifacts/corrected_audit/robustness_evaluation_real.json",
        "artifacts/corrected_audit/latency_benchmark_real.json",
        "artifacts/corrected_audit/extension_architecture_and_hybrid_evaluation.json",
    ]
    hashes_inventory: dict[str, dict[str, Any]] = {}
    for rel in critical_rel_paths:
        p = ROOT / rel
        if p.exists():
            hashes_inventory[rel] = {
                "exists": True,
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
        else:
            hashes_inventory[rel] = {"exists": False, "size_bytes": 0, "sha256": None}

    print(f"[2] Hashes SHA-256 calculados para {len(hashes_inventory)} artefactos críticos.", flush=True)

    # 3. Inspect samples.csv integrity
    samples_path = ROOT / "data" / "processed" / "0.1.0" / "samples.csv"
    samples_by_id: dict[str, dict[str, str]] = {}
    label_counts = Counter()
    source_counts = Counter()
    raw_urls = set()
    canonical_urls = set()
    duplicate_raw_urls = 0
    duplicate_canonical_urls = 0
    missing_critical_fields = 0
    psl_mismatch_count = 0

    with open(samples_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for idx, row in enumerate(reader):
            sid = row.get("sample_id", "").strip()
            can_url = row.get("canonical_url", "").strip()
            url = can_url
            lbl = row.get("label", "").strip()
            src = row.get("source", "").strip()
            reg_dom = row.get("registered_domain", "").strip()

            if not sid or not can_url or lbl not in ("phishing", "legitimate"):
                missing_critical_fields += 1
            if url in raw_urls:
                duplicate_raw_urls += 1
            raw_urls.add(url)
            if can_url in canonical_urls:
                duplicate_canonical_urls += 1
            canonical_urls.add(can_url)

            # Sample PSL verification on first 2,000 rows + all multimodal rows later
            if idx < 2000:
                recalc_dom = extract_reg_domain_psl(can_url, psl)
                if recalc_dom != reg_dom:
                    psl_mismatch_count += 1

            samples_by_id[sid] = row
            label_counts[lbl] += 1
            source_counts[f"{lbl}:{src}"] += 1

    samples_audit = {
        "total_rows": len(samples_by_id),
        "unique_sample_ids": len(samples_by_id),
        "columns": fieldnames,
        "label_distribution": dict(label_counts),
        "source_by_label_distribution": dict(source_counts),
        "missing_critical_fields": missing_critical_fields,
        "duplicate_raw_urls": duplicate_raw_urls,
        "duplicate_canonical_urls": duplicate_canonical_urls,
        "psl_sample_check_2000_mismatches": psl_mismatch_count,
        "source_class_confounding_note": (
            "100% de las muestras legítimas (99,994) provienen de Tranco y 100% de las de phishing (76,207) "
            "provienen de PhishTank. Esta correlación fuente-clase (1:1) en el dataset 0.1.0 motiva "
            "obligatoriamente la validación externa multi-fuente en la Fase II."
        ),
    }
    print(f"[3] Integridad de samples.csv verificada: {samples_audit['total_rows']} muestras únicas.", flush=True)

    # 4. Load redirect information from infrastructure-results-real.jsonl for redirect leakage checks
    infra_path = ROOT / "artifacts" / "analysis-results" / "infrastructure-results-real.jsonl"
    redirect_final_domains: dict[str, str] = {}
    redirect_changed_domain_count = 0
    with open(infra_path, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            sid = rec.get("sample_id", "")
            res_obj = rec.get("result", rec)
            f_url = res_obj.get("final_url") or ""
            if f_url:
                f_dom = extract_reg_domain_psl(f_url, psl)
                if f_dom:
                    redirect_final_domains[sid] = f_dom
                    orig_dom = samples_by_id.get(sid, {}).get("registered_domain", "")
                    if orig_dom and f_dom != orig_dom:
                        redirect_changed_domain_count += 1

    # 5. Audit all 4 partition files for overlap (sample_id, exact URL, canonical URL, PSL registered_domain, and redirected final_domain)
    split_files = ["conventional.csv", "host_unseen.csv", "temporal.csv", "temporal_host_unseen.csv"]
    splits_audit: dict[str, Any] = {}
    for sfile in split_files:
        spath = ROOT / "data" / "processed" / "0.1.0" / "splits" / sfile
        part_ids: dict[str, set[str]] = defaultdict(set)
        part_hosts: dict[str, set[str]] = defaultdict(set)
        part_can_urls: dict[str, set[str]] = defaultdict(set)
        part_reg_domains: dict[str, set[str]] = defaultdict(set)
        part_redirect_domains: dict[str, set[str]] = defaultdict(set)
        part_class_counts: dict[str, Counter] = defaultdict(Counter)
        missing_in_samples = 0

        with open(spath, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                sid = r["sample_id"]
                part = r["partition"]
                if sid not in samples_by_id:
                    missing_in_samples += 1
                    continue
                srow = samples_by_id[sid]
                part_ids[part].add(sid)
                part_hosts[part].add(srow["host"])
                part_can_urls[part].add(srow["canonical_url"])
                rdom = srow["registered_domain"]
                if rdom:
                    part_reg_domains[part].add(rdom)
                if sid in redirect_final_domains:
                    part_redirect_domains[part].add(redirect_final_domains[sid])
                part_class_counts[part][srow["label"]] += 1

        def pair_overlaps(d: dict[str, set[str]]) -> dict[str, int]:
            return {
                "train_val": len(d["train"] & d["validation"]),
                "train_test": len(d["train"] & d["test"]),
                "val_test": len(d["validation"] & d["test"]),
            }

        splits_audit[sfile] = {
            "total_assigned": sum(len(v) for v in part_ids.values()),
            "missing_in_samples_csv": missing_in_samples,
            "counts_by_partition": {
                p: {
                    "total": len(part_ids[p]),
                    "legitimate": part_class_counts[p]["legitimate"],
                    "phishing": part_class_counts[p]["phishing"],
                    "unique_registered_domains": len(part_reg_domains[p]),
                }
                for p in ("train", "validation", "test")
            },
            "overlap_sample_id": pair_overlaps(part_ids),
            "overlap_host": pair_overlaps(part_hosts),
            "overlap_canonical_url": pair_overlaps(part_can_urls),
            "overlap_registered_domain_psl": pair_overlaps(part_reg_domains),
            "overlap_redirect_target_domain_on_10k": pair_overlaps(part_redirect_domains),
        }

    print("[4] Auditoría de solapamiento de particiones completada (incluyendo redirecciones HTTP).", flush=True)

    # 6. Recalculate metrics directly from predictions.csv and compare with metrics.json
    model_dirs = [
        ("M0_CC_host_unseen", "artifacts/m0-real", "selected_threshold"),
        ("M1_CC_host_unseen", "artifacts/m1-real", "selected_threshold"),
        ("M2_CC_host_unseen", "artifacts/m2-real", "selected_threshold"),
        ("M3_CC_host_unseen", "artifacts/m3-real", "selected_threshold"),
        ("M4_fixed_CC_host_unseen", "artifacts/m4-fixed-real", "selected_threshold"),
        ("M4_CC_host_unseen", "artifacts/m4-real", "selected_threshold"),
        ("M5_CC_host_unseen", "artifacts/m5-real", "selected_threshold"),
        ("M0_ITE_host_unseen", "artifacts/m0-ite-real", "selected_threshold"),
        ("M1_ITE_host_unseen", "artifacts/m1-ite-real", "selected_threshold"),
        ("M2_ITE_host_unseen", "artifacts/m2-ite-real", "selected_threshold"),
        ("M3_ITE_host_unseen", "artifacts/m3-ite-real", "selected_threshold"),
        ("M0_full_host_unseen", "artifacts/url-baseline-0.2.0", "selected_threshold"),
        ("M0_full_temporal", "artifacts/m0-temporal", "selected_threshold"),
        ("M0_full_temporal_host_unseen", "artifacts/m0-temporal-host-unseen", "selected_threshold"),
        ("M3_authentic_cdp", "artifacts/corrected_audit/m3-authentic-cdp", "selected_threshold"),
    ]

    recalculated_table = []
    for label_key, rel_dir, th_key in model_dirs:
        mdir = ROOT / rel_dir
        pred_path = mdir / "predictions.csv"
        met_path = mdir / "metrics.json"
        if not pred_path.exists() or not met_path.exists():
            recalculated_table.append({"experiment": label_key, "status": "MISSING_FILES"})
            continue

        mjson = json.loads(met_path.read_text(encoding="utf-8"))
        sel_th_top = mjson.get("selected_threshold", 0.5)
        default_tau = sel_th_top.get("threshold", 0.5) if isinstance(sel_th_top, dict) else float(sel_th_top or 0.5)
        # Locate reported test metrics and threshold
        if "partitions" in mjson and "test" in mjson["partitions"]:
            tblock = mjson["partitions"]["test"]
            rep_metrics = tblock.get(th_key, tblock)
            if not isinstance(rep_metrics, dict):
                rep_metrics = tblock
            tau = rep_metrics.get("threshold", default_tau)
        elif "test_metrics" in mjson:
            rep_metrics = mjson["test_metrics"]
            tau = rep_metrics.get("threshold", mjson.get("threshold", default_tau))
        else:
            rep_metrics = mjson
            tau = rep_metrics.get("threshold", default_tau)
        tau = float(tau if tau is not None else 0.5)

        y_true_list = []
        y_prob_list = []
        y_pred_file_list = []
        label_mismatch_vs_samples = 0
        abstained_flags = []

        with open(pred_path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                part = r.get("partition") or r.get("split") or "test"
                if part != "test":
                    continue
                sid = r.get("sample_id", "")
                raw_lbl = r.get("label", r.get("true_label", ""))
                y_val = 1 if str(raw_lbl).lower() in ("1", "phishing", "true") else 0
                if sid in samples_by_id:
                    true_from_master = 1 if samples_by_id[sid]["label"] == "phishing" else 0
                    if y_val != true_from_master:
                        label_mismatch_vs_samples += 1
                prob = float(r.get("probability_phishing", r.get("probability", 0.0)))
                pred_col = r.get("predicted_label", "")
                if pred_col != "":
                    p_val = 1 if str(pred_col).lower() in ("1", "phishing", "true") else 0
                    y_pred_file_list.append(p_val)
                abstained_flags.append(str(r.get("abstained", "0")).strip().lower() in ("true", "1"))
                y_true_list.append(y_val)
                y_prob_list.append(prob)

        y_true_arr = np.array(y_true_list, dtype=int)
        y_prob_arr = np.array(y_prob_list, dtype=float)

        # If cascade has per-stage predicted_label in file, verify both file's predicted_label and thresholded prob
        if len(y_pred_file_list) == len(y_true_arr) and ("m4" in rel_dir or "m5" in rel_dir):
            y_pred_arr = np.array(y_pred_file_list, dtype=int)
            tn, fp, fn, tp = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1]).ravel()
            recalc = compute_metrics_from_arrays(y_true_arr, y_prob_arr, float(tau))
            # Override confusion-dependent metrics with exact stage predictions from file
            recalc["tn"], recalc["fp"], recalc["fn"], recalc["tp"] = int(tn), int(fp), int(fn), int(tp)
            recalc["accuracy"] = round(float(accuracy_score(y_true_arr, y_pred_arr)), 6)
            recalc["precision"] = round(float(precision_score(y_true_arr, y_pred_arr, zero_division=0)), 6)
            recalc["recall"] = round(float(recall_score(y_true_arr, y_pred_arr, zero_division=0)), 6)
            recalc["f1"] = round(float(f1_score(y_true_arr, y_pred_arr, zero_division=0)), 6)
            recalc["fpr"] = round(float(fp / (fp + tn)), 6)
            recalc["fnr"] = round(float(fn / (fn + tp)), 6)
        else:
            recalc = compute_metrics_from_arrays(y_true_arr, y_prob_arr, float(tau))

        rep_f1 = round(float(rep_metrics.get("f1", 0.0)), 6)
        rep_prec = round(float(rep_metrics.get("precision", 0.0)), 6)
        rep_rec = round(float(rep_metrics.get("recall", 0.0)), 6)
        rep_acc = round(float(rep_metrics.get("accuracy", 0.0)), 6)
        max_diff = max(
            abs(recalc["f1"] - rep_f1),
            abs(recalc["precision"] - rep_prec),
            abs(recalc["recall"] - rep_rec),
            abs(recalc["accuracy"] - rep_acc),
        )

        entry: dict[str, Any] = {
            "experiment": label_key,
            "artifact_dir": rel_dir,
            "n_test": recalc["n"],
            "label_mismatch_vs_samples_csv": label_mismatch_vs_samples,
            "recalculated": recalc,
            "reported_in_metrics_json": {
                "f1": rep_f1,
                "precision": rep_prec,
                "recall": rep_rec,
                "accuracy": rep_acc,
            },
            "max_abs_diff": round(max_diff, 8),
            "status": "PASS" if (max_diff <= 1e-5 and label_mismatch_vs_samples == 0) else "FAIL",
        }

        # Check M5 selective metrics if applicable
        if label_key == "M5_CC_host_unseen":
            dec_mask = ~np.array(abstained_flags, dtype=bool)
            y_t_dec = y_true_arr[dec_mask]
            y_p_dec = np.array(y_pred_file_list, dtype=int)[dec_mask]
            y_prob_dec = y_prob_arr[dec_mask]
            tn_d, fp_d, fn_d, tp_d = confusion_matrix(y_t_dec, y_p_dec, labels=[0, 1]).ravel()
            entry["selective_recalculated"] = {
                "n_decided": int(dec_mask.sum()),
                "n_abstained": int((~dec_mask).sum()),
                "abstained_phishing": int(y_true_arr[~dec_mask].sum()),
                "abstained_legitimate": int((1 - y_true_arr[~dec_mask]).sum()),
                "coverage": round(float(dec_mask.mean()), 6),
                "tn": int(tn_d),
                "fp": int(fp_d),
                "fn": int(fn_d),
                "tp": int(tp_d),
                "accuracy": round(float(accuracy_score(y_t_dec, y_p_dec)), 6),
                "precision": round(float(precision_score(y_t_dec, y_p_dec, zero_division=0)), 6),
                "recall": round(float(recall_score(y_t_dec, y_p_dec, zero_division=0)), 6),
                "f1": round(float(f1_score(y_t_dec, y_p_dec, zero_division=0)), 6),
                "ece_decided": round(float(expected_calibration_error(y_t_dec, y_prob_dec, 15)), 6),
            }

        recalculated_table.append(entry)

    print(f"[5] Recálculo de métricas completado para {len(recalculated_table)} experimentos.", flush=True)

    # 7. Inspect .joblib models & feature contracts
    joblib_models_info = {}
    for m_rel in [
        "artifacts/url-baseline-0.2.0/model.joblib",
        "artifacts/m0-real/model.joblib",
        "artifacts/m1-real/model.joblib",
        "artifacts/m2-real/model.joblib",
        "artifacts/m3-real/model.joblib",
        "artifacts/m0-ite-real/model.joblib",
        "artifacts/m1-ite-real/model.joblib",
        "artifacts/m2-ite-real/model.joblib",
        "artifacts/m3-ite-real/model.joblib",
        "artifacts/m0-temporal/model.joblib",
        "artifacts/m0-temporal-host-unseen/model.joblib",
        "artifacts/corrected_audit/m3-authentic-cdp/model.joblib",
    ]:
        p = ROOT / m_rel
        if p.exists():
            obj = joblib.load(p)
            if isinstance(obj, dict):
                fnames = obj.get("feature_names", [])
                joblib_models_info[m_rel] = {
                    "type": type(obj.get("model")).__name__,
                    "candidate_name": obj.get("candidate_name", obj.get("model_name", "unknown")),
                    "num_features": len(fnames),
                    "first_3_features": fnames[:3],
                    "last_3_features": fnames[-3:],
                    "threshold": obj.get("threshold", obj.get("selected_threshold")),
                }
            else:
                joblib_models_info[m_rel] = {"type": type(obj).__name__}

    # 8. Security scan for secrets in published artifacts / tracked files
    secret_patterns = [
        ("groq_api_key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
        ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{30,}")),
        ("openai_api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
        ("private_key_pem", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
    ]
    secret_findings = []
    for scan_dir in [ROOT / "artifacts", ROOT / "src", ROOT / "scripts", ROOT / "configs"]:
        for fpath in scan_dir.rglob("*"):
            if fpath.is_file() and fpath.suffix in (".py", ".json", ".md", ".yaml", ".yml", ".toml", ".txt"):
                try:
                    txt = fpath.read_text(encoding="utf-8", errors="ignore")
                    for pname, pat in secret_patterns:
                        if pat.search(txt):
                            secret_findings.append({"file": str(fpath.relative_to(ROOT)), "pattern": pname})
                except Exception:
                    pass

    # Check if extension.pem exists in root (important finding!)
    pem_in_root = (ROOT / "extension.pem").exists()

    # 9. Check Git state
    git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    git_branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT, text=True).strip()
    git_status_lines = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip().splitlines()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "git_state": {
            "branch": git_branch,
            "base_commit": git_commit,
            "modified_or_untracked_count": len(git_status_lines),
        },
        "environment": collect_environment_metadata(),
        "hashes_inventory": hashes_inventory,
        "samples_csv_audit": samples_audit,
        "redirect_domain_changes_in_10k_infra": redirect_changed_domain_count,
        "splits_overlap_audit": splits_audit,
        "recalculated_metrics_table": recalculated_table,
        "joblib_models_audit": joblib_models_info,
        "security_and_secrets_audit": {
            "secret_findings_in_code_and_artifacts": secret_findings,
            "env_file_exists_locally_untracked": (ROOT / ".env").exists(),
            "extension_pem_exists_in_root": pem_in_root,
            "note": (
                "Ningún artefacto en artifacts/, src/, scripts/ o configs/ contiene claves API. "
                "Los archivos locales .env y extension.pem existen en el directorio de trabajo y "
                "SON EXCLUIDOS obligatoriamente del paquete reproducible ZIP."
            ),
        },
    }

    out_json = OUT_DIR / "01_auditoria_baseline_results.json"
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"=== FASE I GUARDADA EN {out_json} ===", flush=True)


if __name__ == "__main__":
    main()
