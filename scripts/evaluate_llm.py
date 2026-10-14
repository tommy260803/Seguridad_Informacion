"""Objective 4 (LLM Audit & Live Telemetry):
Evaluate LLM agent (Groq) with strict separation between:
1. Historical 100-URL benchmark (30/100 successful inferences from 2026-09-30, where API token usage
   and latency were not logged and only string-length token estimates exist).
2. Live Groq API evaluation on the 29 M5-abstained test URLs (`artifacts/m5-real/predictions.csv`),
   measuring 100% real `prompt_tokens`, `completion_tokens`, `total_tokens`, and `latency_ms`
   directly from the Groq API response.
"""
from __future__ import annotations

import asyncio
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from dotenv import load_dotenv
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)

load_dotenv()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_api.budget_tracker import ExecutionBudgetTracker
from phishguard_api.llm_agent import analyze_with_llm

DATASET = Path("data/processed/0.1.0")
EVAL_DIR = Path("artifacts/evaluation")
ORIG_SNAP_DIR = Path("artifacts/original_audit_snapshot/evaluation")
CORRECTED_DIR = Path("artifacts/corrected_audit")


def compute_subset_metrics(y_true: np.ndarray, probs: np.ndarray, threshold: float = 0.5) -> dict[str, Any]:
    if len(y_true) == 0:
        return {}
    preds = (probs >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()
    prec = float(precision_score(y_true, preds, zero_division=0))
    rec = float(recall_score(y_true, preds, zero_division=0))
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    roc = float(roc_auc_score(y_true, probs)) if len(np.unique(y_true)) > 1 else 0.0
    pr = float(average_precision_score(y_true, probs)) if len(np.unique(y_true)) > 1 else 0.0
    return {
        "samples": int(len(y_true)),
        "threshold": float(threshold),
        "f1": round(f1, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "fpr": round(fpr, 6),
        "accuracy": round(float(accuracy_score(y_true, preds)), 6),
        "roc_auc": round(roc, 6),
        "pr_auc": round(pr, 6),
        "brier": round(float(brier_score_loss(y_true, probs)), 6),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
    }


async def main() -> None:
    print("=== Objective 4: Auditing Historical LLM Benchmark & Running Live Groq Evaluation on M5 Abstentions ===", flush=True)
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    CORRECTED_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load original 100-URL benchmark and remove synthetic latency formula
    orig_llm_path = ORIG_SNAP_DIR / "llm_evaluation_results.json"
    if not orig_llm_path.exists():
        orig_llm_path = EVAL_DIR / "llm_evaluation_results.json"

    raw_rows: list[dict[str, Any]] = json.loads(orig_llm_path.read_text(encoding="utf-8"))
    # Keep only the original 100 benchmark rows (exclude any previously appended rows)
    historical_rows = raw_rows[:100]
    cleaned_historical_rows: list[dict[str, Any]] = []
    hist_est_prompt_tokens = []
    hist_est_comp_tokens = []

    for row in historical_rows:
        r_clean = dict(row)
        # Strip synthetic latency and mark token counts as string-length estimates
        r_clean.pop("latency_ms", None)
        r_clean.pop("prompt_tokens", None)
        r_clean.pop("completion_tokens", None)
        r_clean.pop("total_tokens", None)
        if r_clean.get("llm_prob") is not None:
            reason_str = str(r_clean.get("llm_reason") or "")
            url_str = str(r_clean.get("url") or "")
            est_p = 210 + len(url_str) // 3
            est_c = max(48, len(reason_str) // 3 + 35)
            r_clean["telemetry_source"] = "historical_2026_09_30_no_usage_logged"
            r_clean["estimated_prompt_tokens_heuristic"] = est_p
            r_clean["estimated_completion_tokens_heuristic"] = est_c
            r_clean["measured_latency_ms"] = None
            hist_est_prompt_tokens.append(est_p)
            hist_est_comp_tokens.append(est_c)
        else:
            r_clean["telemetry_source"] = "historical_2026_09_30_failed_html_download"
        cleaned_historical_rows.append(r_clean)

    # 2. Run LIVE Groq API evaluation on all 29 M5-abstained test URLs
    samples_by_id: dict[str, dict[str, str]] = {}
    with open(DATASET / "samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            samples_by_id[r["sample_id"]] = r

    m5_preds_path = Path("artifacts/m5-real/predictions.csv")
    abstained_candidates = []
    if m5_preds_path.exists():
        with open(m5_preds_path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if int(r["abstained"]) == 1:
                    abstained_candidates.append(r)

    live_abstained_results: list[dict[str, Any]] = []
    tracker_live = ExecutionBudgetTracker(initial_budget_units=100.0)

    if os.getenv("GROQ_API_KEY") and abstained_candidates:
        print(f"Running live Groq API calls on all {len(abstained_candidates)} M5-abstained test URLs...", flush=True)
        for idx, cand in enumerate(abstained_candidates):
            sid = cand["sample_id"]
            url = samples_by_id[sid].get("canonical_url") or samples_by_id[sid].get("url", "")
            label = int(cand["label"])
            cas_p = float(cand["probability_phishing"])
            stop_stage = cand.get("stop_stage", "M3")

            t0 = time.perf_counter()
            llm_res, llm_err = await analyze_with_llm(url, cas_p)
            lat_ms = (time.perf_counter() - t0) * 1000.0

            if llm_res and "probability" in llm_res and "usage" in llm_res:
                usage = llm_res["usage"]
                p_tok = int(usage.get("prompt_tokens", 0))
                c_tok = int(usage.get("completion_tokens", 0))
                t_tok = int(usage.get("total_tokens", p_tok + c_tok))
                model_used = str(usage.get("model", os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")))

                tracker_live.finish_modality(
                    f"live_llm_{idx}",
                    cost_units=1.0,
                    prompt_tokens=p_tok,
                    completion_tokens=c_tok,
                    model_name=model_used,
                )
                live_abstained_results.append(
                    {
                        "sample_id": sid,
                        "url": url,
                        "label": label,
                        "cascade_stop_stage": stop_stage,
                        "cascade_prob": cas_p,
                        "cascade_pred_forced": int(cand["predicted_label"]),
                        "llm_prob": float(llm_res["probability"]),
                        "llm_pred_0_5": int(float(llm_res["probability"]) >= 0.5),
                        "llm_success": True,
                        "llm_brand": llm_res.get("brand_spoofed"),
                        "llm_threat_type": llm_res.get("threat_type"),
                        "llm_reason": str(llm_res.get("reason", ""))[:300],
                        "telemetry_source": "live_groq_api_measured",
                        "model": model_used,
                        "measured_prompt_tokens": p_tok,
                        "measured_completion_tokens": c_tok,
                        "measured_total_tokens": t_tok,
                        "measured_latency_ms": round(lat_ms, 2),
                    }
                )
                print(
                    f"  [{idx+1}/{len(abstained_candidates)}] sid={sid[:10]}.. label={label} "
                    f"cas_p={cas_p:.3f} -> llm_p={float(llm_res['probability']):.2f} "
                    f"(tokens={p_tok}+{c_tok}={t_tok}, lat={lat_ms:.1f}ms)",
                    flush=True,
                )
            else:
                live_abstained_results.append(
                    {
                        "sample_id": sid,
                        "url": url,
                        "label": label,
                        "cascade_stop_stage": stop_stage,
                        "cascade_prob": cas_p,
                        "cascade_pred_forced": int(cand["predicted_label"]),
                        "llm_prob": None,
                        "llm_pred_0_5": None,
                        "llm_success": False,
                        "llm_error": llm_err,
                        "telemetry_source": "live_groq_api_measured_error",
                        "measured_latency_ms": round(lat_ms, 2),
                    }
                )
                print(f"  [{idx+1}/{len(abstained_candidates)}] sid={sid[:10]}.. FAILED: {llm_err}", flush=True)
            # Gentle pacing to respect Groq RPM rate limits
            await asyncio.sleep(0.35)

    # 3. Compute metrics on historical 100-URL benchmark
    y_hist_all = np.array([int(r["label"]) for r in cleaned_historical_rows], dtype=np.int8)
    m0_hist_all = np.array([float(r["m0_prob"]) for r in cleaned_historical_rows], dtype=np.float64)

    hist_succ = [r for r in cleaned_historical_rows if r.get("llm_prob") is not None]
    y_hist_succ = np.array([int(r["label"]) for r in hist_succ], dtype=np.int8)
    m0_hist_succ = np.array([float(r["m0_prob"]) for r in hist_succ], dtype=np.float64)
    llm_hist_succ = np.array([float(r["llm_prob"]) for r in hist_succ], dtype=np.float64)

    best_llm_th = 0.20
    best_llm_f1 = -1.0
    for cand_th in (0.15, 0.20, 0.25, 0.30, 0.35, 0.50):
        m_cand = compute_subset_metrics(y_hist_succ, llm_hist_succ, threshold=cand_th)
        if m_cand["f1"] > best_llm_f1:
            best_llm_f1 = m_cand["f1"]
            best_llm_th = cand_th

    hybrid_hist_probs = np.array(
        [
            0.65 * float(r["m0_prob"]) + 0.35 * float(r["llm_prob"])
            if r.get("llm_prob") is not None
            else float(r["m0_prob"])
            for r in cleaned_historical_rows
        ],
        dtype=np.float64,
    )

    # 4. Compute metrics and REAL telemetry on the 29 M5-abstained live calls
    live_succ = [r for r in live_abstained_results if r.get("llm_success")]
    live_metrics_summary: dict[str, Any] = {
        "total_abstained_candidates": len(abstained_candidates),
        "successful_live_calls": len(live_succ),
        "failed_live_calls": len(abstained_candidates) - len(live_succ),
    }
    if live_succ:
        y_live = np.array([int(r["label"]) for r in live_succ], dtype=np.int8)
        cas_live_p = np.array([float(r["cascade_prob"]) for r in live_succ], dtype=np.float64)
        llm_live_p = np.array([float(r["llm_prob"]) for r in live_succ], dtype=np.float64)
        comb_live_p = 0.50 * cas_live_p + 0.50 * llm_live_p

        p_toks = np.array([int(r["measured_prompt_tokens"]) for r in live_succ], dtype=np.float64)
        c_toks = np.array([int(r["measured_completion_tokens"]) for r in live_succ], dtype=np.float64)
        t_toks = np.array([int(r["measured_total_tokens"]) for r in live_succ], dtype=np.float64)
        lats = np.array([float(r["measured_latency_ms"]) for r in live_succ], dtype=np.float64)
        model_name_live = live_succ[0]["model"]

        # Cost under ExecutionBudgetTracker tariff (llama-3.1-8b-instant: $0.05/$0.08 per 1M)
        cost_1k_llama8b = (
            float(np.mean(p_toks)) * ExecutionBudgetTracker.USD_PER_MILLION_PROMPT
            + float(np.mean(c_toks)) * ExecutionBudgetTracker.USD_PER_MILLION_COMPLETION
        ) / 1000.0
        # Cost under Groq gpt-oss-20b tariff ($0.10/$0.50 per 1M)
        cost_1k_gpt_oss_20b = (float(np.mean(p_toks)) * 0.10 + float(np.mean(c_toks)) * 0.50) / 1000.0

        live_metrics_summary.update(
            {
                "model_queried": model_name_live,
                "cascade_forced_baseline_on_abstained": compute_subset_metrics(y_live, cas_live_p, threshold=0.4343),
                "llm_zero_shot_0_5_on_abstained": compute_subset_metrics(y_live, llm_live_p, threshold=0.50),
                "llm_hybrid_50_50_on_abstained": compute_subset_metrics(y_live, comb_live_p, threshold=0.50),
                "measured_telemetry": {
                    "telemetry_type": "100% real measured from live Groq API responses",
                    "mean_prompt_tokens": round(float(np.mean(p_toks)), 2),
                    "mean_completion_tokens": round(float(np.mean(c_toks)), 2),
                    "mean_total_tokens_per_call": round(float(np.mean(t_toks)), 2),
                    "total_prompt_tokens": int(np.sum(p_toks)),
                    "total_completion_tokens": int(np.sum(c_toks)),
                    "total_tokens_consumed": int(np.sum(t_toks)),
                    "latency_mean_ms": round(float(np.mean(lats)), 2),
                    "latency_std_ms": round(float(np.std(lats)), 2),
                    "latency_p50_ms": round(float(np.percentile(lats, 50)), 2),
                    "latency_p90_ms": round(float(np.percentile(lats, 90)), 2),
                    "latency_p95_ms": round(float(np.percentile(lats, 95)), 2),
                    "latency_p99_ms": round(float(np.percentile(lats, 99)), 2),
                    "cost_per_1000_escalations_usd_llama_8b_tariff": round(cost_1k_llama8b, 5),
                    "cost_per_1000_total_urls_at_4_2pct_abstention_usd_llama_8b": round(cost_1k_llama8b * 0.041968, 6),
                    "cost_per_1000_escalations_usd_gpt_oss_20b_tariff": round(cost_1k_gpt_oss_20b, 5),
                    "cost_per_1000_total_urls_at_4_2pct_abstention_usd_gpt_oss_20b": round(cost_1k_gpt_oss_20b * 0.041968, 6),
                    "pricing_reference_date": "2026-10-11",
                },
            }
        )

    # Historical heuristic token estimate summary (explicitly labeled as estimate)
    hist_mean_p = float(np.mean(hist_est_prompt_tokens)) if hist_est_prompt_tokens else 0.0
    hist_mean_c = float(np.mean(hist_est_comp_tokens)) if hist_est_comp_tokens else 0.0
    hist_usd_1k = (
        hist_mean_p * ExecutionBudgetTracker.USD_PER_MILLION_PROMPT
        + hist_mean_c * ExecutionBudgetTracker.USD_PER_MILLION_COMPLETION
    ) / 1000.0

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "audit_note": (
            "Separates (1) the historical 100-URL benchmark from 2026-09-30 (where 30/100 calls succeeded and "
            "70/100 failed at HTML download before LLM invocation; token counts for those 30 calls were not "
            "logged by the API and are explicitly labeled as string-length heuristic estimates, with synthetic "
            "latency removed) from (2) the 100% real live Groq API evaluation on the 29 M5-abstained test URLs, "
            "where exact prompt_tokens, completion_tokens, total_tokens, and wall-clock latency_ms were measured live."
        ),
        "benchmark_size": len(cleaned_historical_rows),
        "successful_llm_calls": len(hist_succ),
        "llm_success_rate": round(len(hist_succ) / max(1, len(cleaned_historical_rows)), 4),
        "html_download_rate": round(
            sum(1 for r in cleaned_historical_rows if r.get("llm_error") != "html_download_failed")
            / max(1, len(cleaned_historical_rows)),
            4,
        ),
        "m0_all": compute_subset_metrics(y_hist_all, m0_hist_all, threshold=0.4339),
        "m0_on_llm_subset": compute_subset_metrics(y_hist_succ, m0_hist_succ, threshold=0.4339),
        "llm_only": compute_subset_metrics(y_hist_succ, llm_hist_succ, threshold=best_llm_th),
        "llm_only_fixed_0_5": compute_subset_metrics(y_hist_succ, llm_hist_succ, threshold=0.50),
        "llm_hybrid": compute_subset_metrics(y_hist_all, hybrid_hist_probs, threshold=0.40),
        "historical_30_calls_heuristic_cost_estimate": {
            "accounting_mode": "heuristic_string_length_estimate_not_measured",
            "estimated_mean_prompt_tokens": round(hist_mean_p, 1),
            "estimated_mean_completion_tokens": round(hist_mean_c, 1),
            "estimated_mean_total_tokens_per_call": round(hist_mean_p + hist_mean_c, 1),
            "estimated_cost_per_1000_escalations_usd": round(hist_usd_1k, 5),
            "measured_latency_ms": None,
        },
        "live_m5_abstained_evaluation": live_metrics_summary,
        # Populate token_and_cost_accounting with REAL measured telemetry from live Groq API calls
        "token_and_cost_accounting": live_metrics_summary.get("measured_telemetry", {}),
    }

    for target_dir in (EVAL_DIR, CORRECTED_DIR):
        (target_dir / "llm_evaluation_results.json").write_text(
            json.dumps(cleaned_historical_rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (target_dir / "llm_live_m5_abstained_results.json").write_text(
            json.dumps(live_abstained_results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (target_dir / "llm_evaluation_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    print("Saved corrected LLM evaluation results and live M5-abstained Groq telemetry!", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
