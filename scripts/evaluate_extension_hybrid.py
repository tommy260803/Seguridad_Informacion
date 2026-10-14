"""Objective 6: Evaluate the Browser Extension's Production Model (`HybridM0Model` on `/check`)
and compare it directly against Experimental Configurations M0-M5 on the N=691 Test Cohort.

Documents and benchmarks:
1. Live network latency of `predict_hybrid` (which invokes `_check_server_geolocation` and `_check_domain_age`
   via live external GeoIP/WHOIS network requests in `DetectionRules.analyze`) on N=20 test URLs.
2. Classification performance and local CPU latency on all N=691 Complete-Case test URLs under two modes:
   - `production_with_tranco_reputation_shield`: Exact logic of `/check` including Tranco top-1M lookup
     (quantifying the dataset source-overlap effect since legitimate URLs in dataset 0.1.0 come from Tranco).
   - `ablation_without_tranco_shield_m0_brand_rules_only`: Disables Tranco lookup (`trust_score=0.0`) to
     measure true unseen-domain generalization of M0 (11 features) + Brand similarity + Homoglyphs + Rules.
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

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_common import collect_environment_metadata
from phishguard_ml.content import load_content_results
from phishguard_ml.detection_rules import DetectionRules, RuleResult
from phishguard_ml.evaluation import classification_metrics
from phishguard_ml.hybrid_model import HybridM0Model
from phishguard_ml.infrastructure import load_infrastructure_results
from phishguard_ml.visual import load_visual_results

DATASET_DIR = Path("data/processed/0.1.0")
ANALYSIS_DIR = Path("artifacts/analysis-results")
EVAL_DIR = Path("artifacts/evaluation")
CORRECTED_DIR = Path("artifacts/corrected_audit")


def no_op_geo(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="server_geolocation", triggered=False, confidence=0.0, reason="Offline benchmark")


def no_op_age(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="domain_age", triggered=False, confidence=0.0, reason="Offline benchmark")


def main() -> None:
    print("=== Objective 6: Evaluating Browser Extension Architecture (HybridM0Model vs M0-M5) ===", flush=True)
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    CORRECTED_DIR.mkdir(parents=True, exist_ok=True)

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
    visual_results = load_visual_results(ANALYSIS_DIR / "visual-results-real.jsonl")

    cc_test_ids = sorted(
        sid
        for sid, res in infra_results.items()
        if host_unseen_split.get(sid) == "test"
        and res.get("status") == "success"
        and content_results.get(sid, {}).get("status") == "success"
        and visual_results.get(sid, {}).get("status") == "success"
    )
    y_test = np.array([1 if samples_by_id[sid]["label"] == "phishing" else 0 for sid in cc_test_ids], dtype=np.int8)

    hybrid = HybridM0Model()

    # 1. Measure REAL live network latency of `predict_hybrid` (with external GeoIP + WHOIS socket calls) on 16 test URLs
    print("Measuring live network latency of predict_hybrid (including external GeoIP & WHOIS) on 16 test URLs...", flush=True)
    live_sample_ids = [sid for sid in cc_test_ids if samples_by_id[sid]["label"] == "phishing"][:8] + [
        sid for sid in cc_test_ids if samples_by_id[sid]["label"] == "legitimate"
    ][:8]
    live_net_lats_ms = []
    for sid in live_sample_ids:
        url = samples_by_id[sid].get("canonical_url") or samples_by_id[sid]["url"]
        t0 = time.perf_counter()
        _ = hybrid.predict(url, user_country="PE")
        live_net_lats_ms.append((time.perf_counter() - t0) * 1000.0)

    # 2. Evaluate Mode A on all N=691 test URLs: Production `predict_hybrid` (with Tranco reputation shield, local CPU rules)
    print("Evaluating HybridM0Model on all N=691 test URLs (Mode A: With Tranco shield)...", flush=True)
    probs_with_tranco = []
    lats_with_tranco_ms = []
    with (
        patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
        patch.object(DetectionRules, "_check_domain_age", no_op_age),
    ):
        for sid in cc_test_ids:
            url = samples_by_id[sid].get("canonical_url") or samples_by_id[sid]["url"]
            t0 = time.perf_counter_ns()
            res = hybrid.predict(url, user_country="PE")
            lats_with_tranco_ms.append((time.perf_counter_ns() - t0) / 1e6)
            probs_with_tranco.append(float(res["probability"]))

    probs_with_tranco_arr = np.array(probs_with_tranco, dtype=np.float64)
    metrics_with_tranco = classification_metrics(y_test, probs_with_tranco_arr, 0.5, 15)

    # 3. Evaluate Mode B on all N=691 test URLs: Ablation without Tranco shield (M0 + Brand + Homoglyphs + Rules only)
    print("Evaluating HybridM0Model on all N=691 test URLs (Mode B: Without Tranco shield, unseen-domain generalization)...", flush=True)
    from phishguard_data import reputation as rep_mod

    orig_get_rep = rep_mod.get_reputation

    def neutral_reputation(url: str, psl: Any = None) -> dict[str, Any]:
        base = orig_get_rep(url, psl=psl)
        base["tranco_rank"] = None
        base["trust_score"] = 0.0
        return base

    probs_no_tranco = []
    lats_no_tranco_ms = []
    with (
        patch("phishguard_ml.hybrid_model.get_reputation", side_effect=neutral_reputation),
        patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
        patch.object(DetectionRules, "_check_domain_age", no_op_age),
    ):
        for sid in cc_test_ids:
            url = samples_by_id[sid].get("canonical_url") or samples_by_id[sid]["url"]
            t0 = time.perf_counter_ns()
            res = hybrid.predict(url, user_country="PE")
            lats_no_tranco_ms.append((time.perf_counter_ns() - t0) / 1e6)
            probs_no_tranco.append(float(res["probability"]))

    probs_no_tranco_arr = np.array(probs_no_tranco, dtype=np.float64)
    metrics_no_tranco = classification_metrics(y_test, probs_no_tranco_arr, 0.5, 15)
    metrics_no_tranco_cal = classification_metrics(y_test, probs_no_tranco_arr, 0.35, 15)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "environment": collect_environment_metadata(),
        "test_cohort": "host_unseen_complete_case_N691",
        "architectural_audit": {
            "extension_active_endpoint": "POST /check (extension/background.js line 6)",
            "extension_active_engine": "HybridM0Model (src/phishguard_ml/hybrid_model.py)",
            "async_cascade_endpoint": "POST /analyses (src/phishguard_api/server.py line 270 & worker.py)",
            "key_differences_documented": [
                "1. Endpoint Routing: extension/background.js exclusively calls synchronous POST /check (even rewriting /analyses to /check at lines 50-53). POST /analyses is only polled by legacy analyzing.js.",
                "2. Model Architecture on /check: Uses HybridM0Model (11-feature M0 + Tranco top-1M reputation + Levenshtein/Jaro brand similarity + IDN homoglyphs + 15 heuristic rules in detection_rules.py), NOT the M1-M5 network/DOM/visual cascade.",
                "3. Hidden External Network Calls in /check: DetectionRules.analyze() spawns 3 threads executing live external GeoIP (_check_server_geolocation) and WHOIS (_check_domain_age) lookups with an 8-second timeout on uncached domains.",
                "4. Cache & Bloom Filter Scope: DecisionCache and BloomFilter are invoked in src/phishguard_api/worker.py (POST /analyses), whereas POST /check relies on a client-side Map in extension/background.js (3-minute TTL) plus per-process _geo_cache/_whois_cache dicts.",
                "5. www. Normalization Difference: src/phishguard_api/inference.py (lines 56-60) decrements subdomain_count and host_label_count by 1.0 when the hostname starts with 'www.', whereas offline M0 training extracts raw canonical authority counts.",
                "6. Worker Model Paths Fixed: UnifiedModelManager in src/phishguard_api/inference.py previously looked only for m1-baseline/m2-baseline/m3-baseline and has now been updated to load m1-real, m2-real, and m3-authentic-cdp/m3-real.",
            ],
        },
        "live_network_latency_with_whois_and_geoip_n16_ms": {
            "samples": len(live_net_lats_ms),
            "mean": round(float(np.mean(live_net_lats_ms)), 2),
            "std": round(float(np.std(live_net_lats_ms)), 2),
            "p50": round(float(np.percentile(live_net_lats_ms, 50)), 2),
            "p90": round(float(np.percentile(live_net_lats_ms, 90)), 2),
            "p95": round(float(np.percentile(live_net_lats_ms, 95)), 2),
        },
        "evaluation_on_n691_test": {
            "production_with_tranco_reputation_shield": {
                "note": (
                    "Includes Tranco domain rank lookup. Because legitimate URLs in dataset 0.1.0 were sampled from "
                    "Tranco, this mode reflects upper-bound allowlist performance and must not be conflated with "
                    "unseen-domain ML generalization."
                ),
                "metrics_threshold_0_5": metrics_with_tranco,
                "local_cpu_latency_ms": {
                    "mean": round(float(np.mean(lats_with_tranco_ms)), 3),
                    "p50": round(float(np.percentile(lats_with_tranco_ms, 50)), 3),
                    "p95": round(float(np.percentile(lats_with_tranco_ms, 95)), 3),
                },
            },
            "ablation_without_tranco_shield_m0_brand_rules_only": {
                "note": (
                    "Tranco lookup disabled (trust_score=0.0). Evaluates pure generalization of M0 + Brand similarity "
                    "+ Homoglyphs + Heuristic rules on unseen domains."
                ),
                "metrics_threshold_0_5": metrics_no_tranco,
                "metrics_threshold_0_35": metrics_no_tranco_cal,
                "local_cpu_latency_ms": {
                    "mean": round(float(np.mean(lats_no_tranco_ms)), 3),
                    "p50": round(float(np.percentile(lats_no_tranco_ms, 50)), 3),
                    "p95": round(float(np.percentile(lats_no_tranco_ms, 95)), 3),
                },
            },
        },
    }

    for target_dir in (EVAL_DIR, CORRECTED_DIR):
        (target_dir / "extension_architecture_and_hybrid_evaluation.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )

    print(
        f"Extension HybridM0Model evaluated on N={len(cc_test_ids)} test URLs:\n"
        f"  Live network latency (with WHOIS/GeoIP, N=16): P50={report['live_network_latency_with_whois_and_geoip_n16_ms']['p50']:.1f}ms, "
        f"P95={report['live_network_latency_with_whois_and_geoip_n16_ms']['p95']:.1f}ms\n"
        f"  With Tranco shield (tau=0.50): F1={metrics_with_tranco['f1']:.4f}, Prec={metrics_with_tranco['precision']:.4f}, "
        f"Rec={metrics_with_tranco['recall']:.4f}, Local CPU P50={report['evaluation_on_n691_test']['production_with_tranco_reputation_shield']['local_cpu_latency_ms']['p50']:.3f}ms\n"
        f"  Without Tranco shield (tau=0.50): F1={metrics_no_tranco['f1']:.4f}, Prec={metrics_no_tranco['precision']:.4f}, "
        f"Rec={metrics_no_tranco['recall']:.4f}\n"
        f"  Without Tranco shield (tau=0.35): F1={metrics_no_tranco_cal['f1']:.4f}, Prec={metrics_no_tranco_cal['precision']:.4f}, "
        f"Rec={metrics_no_tranco_cal['recall']:.4f}",
        flush=True,
    )


if __name__ == "__main__":
    main()
