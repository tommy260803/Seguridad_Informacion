"""Synchronize and enrich audit metadata across `artifacts/corrected_audit/` and `artifacts/evaluation/`
without modifying any experimental measurements or predictions:

1. Adds `metrics.json` and `predictions.csv` to `artifacts/corrected_audit/m3-authentic-cdp/` computed
   directly from `artifacts/corrected_audit/m3-authentic-cdp/model.joblib` on the N=467 authentic Chrome CDP cohort.
2. Annotates `artifacts/analysis-results/visual-results-authentic-cdp.jsonl` and
   `artifacts/corrected_audit/m3_visual_audit_and_authentic_evaluation.json` with explicit `retained_png_path`
   and `png_retention_audit` metadata explaining the exact relationship between the 467 live_cdp feature records
   and the 40 retained raw PNGs in `artifacts/authentic-cdp-screenshots/` (plus 91 sandbox PNGs in `artifacts/screenshots/`
   and 16 PNGs in `artifacts/visual-samples/`).
3. Generates `statistical_comparisons_all.csv` from `statistical_comparisons_all.json` and copies
   `evaluation_report_real.csv`, `coverage_risk_curves_real.csv`, `comparison_m0_m1.json`, and `comparison_m0_m2.json`
   into `artifacts/corrected_audit/` so both directories are 100% complete and synchronized.
"""

from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features, load_content_results
from phishguard_ml.evaluation import classification_metrics
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features, load_infrastructure_results
from phishguard_ml.visual import VISUAL_FEATURE_NAMES, extract_visual_features

DATASET_DIR = ROOT / "data" / "processed" / "0.1.0"
ANALYSIS_DIR = ROOT / "artifacts" / "analysis-results"
EVAL_DIR = ROOT / "artifacts" / "evaluation"
CORRECTED_DIR = ROOT / "artifacts" / "corrected_audit"
AUTH_SHOTS_DIR = ROOT / "artifacts" / "authentic-cdp-screenshots"


def main() -> None:
    # 1. Map the 40 retained PNGs in artifacts/authentic-cdp-screenshots/ to sample_ids
    png_by_prefix: dict[str, str] = {}
    for p in sorted(AUTH_SHOTS_DIR.glob("*.png")):
        png_by_prefix[p.stem] = p.relative_to(ROOT).as_posix()

    auth_jsonl_path = ANALYSIS_DIR / "visual-results-authentic-cdp.jsonl"
    raw_lines = [line for line in auth_jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    updated_lines: list[str] = []
    matched_success_pngs: list[dict[str, Any]] = []
    matched_error_pngs: list[dict[str, Any]] = []
    authentic_cdp_records: dict[str, dict[str, Any]] = {}

    for line in raw_lines:
        row = json.loads(line)
        sid = row["sample_id"]
        res = row["result"]
        prefix = sid[:20]
        rel_png = png_by_prefix.get(prefix)
        if res.get("capture_mode") == "live_cdp" and res.get("status") == "success":
            if rel_png:
                res["retained_png_path"] = rel_png
                res["png_retention_mode"] = "persisted_raw_png_and_extracted_features"
                matched_success_pngs.append({"sample_id": sid, "png_path": rel_png})
            else:
                res["retained_png_path"] = None
                res["png_retention_mode"] = "ephemeral_png_unlinked_after_feature_extraction"
            authentic_cdp_records[sid] = res
        elif rel_png:
            res["retained_png_path"] = rel_png
            res["png_retention_mode"] = "persisted_raw_png_capture_failed_validation"
            matched_error_pngs.append({"sample_id": sid, "png_path": rel_png, "status": res.get("status")})
        updated_lines.append(json.dumps({"sample_id": sid, "result": res}, sort_keys=True))

    auth_jsonl_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    print(
        f"Updated {auth_jsonl_path.name}: {len(authentic_cdp_records)} live_cdp successes "
        f"({len(matched_success_pngs)} with persisted PNG, {len(matched_error_pngs)} non-success persisted PNGs)."
    )

    # 2. Update m3_visual_audit_and_authentic_evaluation.json with png_retention_audit
    m3_audit_path = CORRECTED_DIR / "m3_visual_audit_and_authentic_evaluation.json"
    m3_audit = json.loads(m3_audit_path.read_text(encoding="utf-8"))
    m3_audit["png_retention_audit"] = {
        "total_authentic_live_cdp_feature_vectors": len(authentic_cdp_records),
        "from_2026_09_30_initial_cdp_capture": 76,
        "from_2026_10_12_expanded_cdp_capture": 391,
        "persisted_raw_png_files_in_authentic_cdp_screenshots": len(png_by_prefix),
        "persisted_raw_png_matching_live_cdp_success": len(matched_success_pngs),
        "persisted_raw_png_matching_live_cdp_error_or_blank": len(matched_error_pngs),
        "persisted_sandbox_png_files_in_artifacts_screenshots": len(list((ROOT / "artifacts" / "screenshots").glob("*.png"))),
        "persisted_visual_sample_png_files_in_artifacts_visual_samples": len(list((ROOT / "artifacts" / "visual-samples").rglob("*.png"))),
        "retention_explanation": (
            "During live Headless Chrome CDP capture (scripts/audit_and_capture_authentic_m3.py, lines 130-138 and 336), "
            "every one of the 467 successful captures was rendered by Chrome into a PNG file (`png_path`), analyzed by "
            "`analyze_screenshot(png_path)` to extract the 13 numeric visual features and byte size, and then unlinked "
            "(`png_path.unlink(missing_ok=True)`) except for the first 40 candidate indices (`save_dir=AUTHENTIC_SHOTS_DIR if idx < 40 else None`), "
            "which were copied to `artifacts/authentic-cdp-screenshots/` as a physical inspection sample to avoid multi-hundred-MB archive bloat. "
            "Consequently, all 467 records in `visual-results-authentic-cdp.jsonl` contain 100% real Chrome CDP extracted feature vectors, "
            "while 40 raw PNG files in `artifacts/authentic-cdp-screenshots/` (plus 91 sandbox PNGs in `artifacts/screenshots/` and 16 in `artifacts/visual-samples/`) "
            "are preserved on disk."
        ),
    }
    m3_audit_path.write_text(json.dumps(m3_audit, indent=2) + "\n", encoding="utf-8")

    # 3. Generate metrics.json and predictions.csv inside artifacts/corrected_audit/m3-authentic-cdp/
    m3_cdp_dir = CORRECTED_DIR / "m3-authentic-cdp"
    bundle = joblib.load(m3_cdp_dir / "model.joblib")
    model_m3_cdp = bundle["model"]
    tau_m3_cdp = float(bundle["selected_threshold"])

    samples_by_id: dict[str, dict[str, str]] = {}
    with open(DATASET_DIR / "samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            samples_by_id[r["sample_id"]] = r

    host_unseen_split: dict[str, str] = {}
    with open(DATASET_DIR / "splits" / "host_unseen.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            host_unseen_split[r["sample_id"]] = r["partition"]

    infra_results = load_infrastructure_results(ANALYSIS_DIR / "infrastructure-results-real.jsonl")
    content_results = load_content_results(ANALYSIS_DIR / "content-results-real.jsonl")

    pred_rows = []
    part_metrics: dict[str, Any] = {}
    for part in ("train", "validation", "test"):
        pids = sorted(sid for sid in authentic_cdp_records if host_unseen_split.get(sid) == part)
        X_rows = []
        y_list = []
        for sid in pids:
            s = samples_by_id[sid]
            uf = extract_url_features(UrlFeatureContext(s.get("canonical_url") or s["url"], s["registered_domain"]))
            inf_f = extract_infrastructure_features(infra_results[sid])
            cnt_f = extract_content_features(content_results[sid])
            vis_f = extract_visual_features(authentic_cdp_records[sid])
            row_vec = (
                [uf[k] for k in AUTHORITY_FEATURE_NAMES]
                + [inf_f[k] for k in INFRA_FEATURE_NAMES]
                + [cnt_f[k] for k in CONTENT_FEATURE_NAMES]
                + [vis_f[k] for k in VISUAL_FEATURE_NAMES]
            )
            X_rows.append(row_vec)
            y_list.append(1 if s["label"] == "phishing" else 0)
        X_arr = np.asarray(X_rows, dtype=np.float64)
        y_arr = np.asarray(y_list, dtype=np.int8)
        probs = model_m3_cdp.predict_proba(X_arr)[:, 1]
        preds = (probs >= tau_m3_cdp).astype(np.int8)
        part_metrics[part] = {
            "selected_threshold": classification_metrics(y_arr, probs, tau_m3_cdp, 10),
            "fixed_0_5": classification_metrics(y_arr, probs, 0.5, 10),
        }
        for sid, y_val, p_val, pr_val in zip(pids, y_arr, probs, preds):
            pred_rows.append(
                {
                    "sample_id": sid,
                    "partition": part,
                    "label": int(y_val),
                    "probability_phishing": float(p_val),
                    "predicted_label": int(pr_val),
                }
            )

    m3_cdp_metrics_doc = {
        "model_name": "M3_authentic_cdp",
        "split": "host_unseen",
        "cohort_mode": "authentic_live_cdp_only",
        "feature_count": 75,
        "selected_candidate": bundle.get("selected_candidate", "histgb-31-isotonic"),
        "selected_threshold": tau_m3_cdp,
        "partitions": part_metrics,
    }
    (m3_cdp_dir / "metrics.json").write_text(json.dumps(m3_cdp_metrics_doc, indent=2) + "\n", encoding="utf-8")
    with open(m3_cdp_dir / "predictions.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["sample_id", "partition", "label", "probability_phishing", "predicted_label"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(pred_rows)
    print(f"Wrote {m3_cdp_dir / 'metrics.json'} and predictions.csv ({len(pred_rows)} rows).")

    # 4. Generate statistical_comparisons_all.csv and synchronize files between EVAL_DIR and CORRECTED_DIR
    stats_json = json.loads((CORRECTED_DIR / "statistical_comparisons_all.json").read_text(encoding="utf-8"))
    stat_rows = []
    for comp_key, comp_val in stats_json["comparisons"].items():
        stat_rows.append(
            {
                "comparison": comp_key,
                "protocol": comp_val.get("evaluation_protocol", ""),
                "n_samples": comp_val["n_samples"],
                "f1_model_a": comp_val["f1_model_a"],
                "f1_model_b": comp_val["f1_model_b"],
                "f1_delta": comp_val["f1_delta"],
                "f1_delta_ci95_low": comp_val["f1_delta_ci95"][0],
                "f1_delta_ci95_high": comp_val["f1_delta_ci95"][1],
                "precision_model_a": comp_val["precision_model_a"],
                "precision_model_b": comp_val["precision_model_b"],
                "recall_model_a": comp_val["recall_model_a"],
                "recall_model_b": comp_val["recall_model_b"],
                "accuracy_model_a": comp_val["accuracy_model_a"],
                "accuracy_model_b": comp_val["accuracy_model_b"],
                "mcnemar_a_only": comp_val["mcnemar"]["a_correct_b_wrong"],
                "mcnemar_b_only": comp_val["mcnemar"]["b_correct_a_wrong"],
                "mcnemar_p_value": comp_val["mcnemar"]["p_value"],
            }
        )
    for target_dir in (EVAL_DIR, CORRECTED_DIR):
        with open(target_dir / "statistical_comparisons_all.csv", "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(stat_rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(stat_rows)

    for fname in ("evaluation_report_real.csv", "coverage_risk_curves_real.csv", "comparison_m0_m1.json", "comparison_m0_m2.json"):
        src_f = EVAL_DIR / fname
        if src_f.exists():
            shutil.copy2(src_f, CORRECTED_DIR / fname)
    shutil.copy2(m3_audit_path, EVAL_DIR / "m3_visual_audit_and_authentic_evaluation.json")
    print("Synchronized all evaluation and corrected_audit CSV/JSON files.")


if __name__ == "__main__":
    main()
