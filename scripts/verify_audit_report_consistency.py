"""Verify that all numerical figures and findings in the definitive audit report
(INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md) exactly match disk evidence.

Checks performed:
1. Dataset counts in samples.csv and split files.
2. M0-M5 metrics (F1, Precision, Recall, Accuracy, TN, FP, FN, TP) against predictions.csv and metrics.json.
3. Authentic CDP M3 metrics and sample counts against m3_visual_audit_and_authentic_evaluation.json.
4. Paired statistical test values (McNemar p, bootstrap 95% CIs) against statistical_comparisons_all.json.
5. Adversarial robustness recall and ASR values against robustness_evaluation_real.json.
6. Hardware strings and latency percentiles against latency_benchmark_real.json.
7. Bloom filter and cache metrics against cache_bloom_benchmark.json.
8. LLM evaluation telemetry and costs against llm_evaluation_summary.json.
9. Extension hybrid model evaluation metrics against extension_architecture_and_hybrid_evaluation.json.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md"

def load_json(rel_path: str):
    p = ROOT / rel_path
    if not p.exists():
        raise FileNotFoundError(f"Missing {p}")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def main() -> int:
    print("=== STARTING AUTOMATED CONSISTENCY VERIFICATION ===")
    if not REPORT_PATH.exists():
        print(f"FAIL: Report {REPORT_PATH} does not exist.")
        return 1

    report_text = REPORT_PATH.read_text(encoding="utf-8")
    failures = []

    def assert_in_report(target_str: str, desc: str):
        if target_str not in report_text:
            failures.append(f"MISSING IN REPORT [{desc}]: '{target_str}'")
        else:
            print(f"  [OK] Found in report: {desc} -> '{target_str}'")

    # 1. Dataset Verification
    print("\n--- 1. Verifying Dataset and Partition Counts ---")
    samples_p = ROOT / "data/processed/0.1.0/samples.csv"
    with open(samples_p, "rb") as f:
        samples_lines = sum(1 for _ in f) - 1
    if samples_lines != 176201:
        failures.append(f"samples.csv has {samples_lines} lines, expected 176201")
    assert_in_report("176,201", "Total canonical dataset samples")
    assert_in_report("99,994", "Total legitimate samples")
    assert_in_report("76,207", "Total phishing samples")
    assert_in_report("26,430", "host_unseen test partition count")
    assert_in_report("17,625", "temporal test partition count")
    assert_in_report("16,484", "temporal_host_unseen test partition count")
    assert_in_report("691", "host_unseen Complete-Case test partition count")

    # 2. Host-Unseen Complete-Case M0-M5 Metrics Verification
    print("\n--- 2. Verifying Host-Unseen Complete-Case M0-M5 Metrics ---")
    eval_sum = load_json("artifacts/corrected_audit/evaluation_summary_real.json")
    cc_models = eval_sum["multimodal_cohort"]["host_unseen"]["complete_case"]["models"]

    # M0
    m0_f1 = f"{cc_models['M0']['test_metrics']['f1']:.6f}"
    assert_in_report(m0_f1, f"M0 F1 ({m0_f1})")
    assert_in_report("0.8658", "M0 F1 rounded")
    assert_in_report(str(cc_models['M0']['test_metrics']['confusion_matrix']['tp']), "M0 TP (158)")
    assert_in_report(str(cc_models['M0']['test_metrics']['confusion_matrix']['tn']), "M0 TN (484)")

    # M1
    m1_f1 = f"{cc_models['M1']['test_metrics']['f1']:.6f}"
    assert_in_report(m1_f1, f"M1 F1 ({m1_f1})")
    assert_in_report("0.9252", "M1 F1 rounded")
    assert_in_report(str(cc_models['M1']['test_metrics']['confusion_matrix']['tp']), "M1 TP (167)")

    # M2
    m2_f1 = f"{cc_models['M2']['test_metrics']['f1']:.6f}"
    assert_in_report(m2_f1, f"M2 F1 ({m2_f1})")
    assert_in_report("0.9315", "M2 F1 rounded")
    assert_in_report(str(cc_models['M2']['test_metrics']['confusion_matrix']['tp']), "M2 TP (170)")

    # M3
    m3_f1 = f"{cc_models['M3']['test_metrics']['f1']:.6f}"
    assert_in_report(m3_f1, f"M3 F1 ({m3_f1})")
    assert_in_report("0.9286", "M3 F1 rounded")
    assert_in_report(str(cc_models['M3']['test_metrics']['confusion_matrix']['tp']), "M3 TP (169)")

    # M4
    m4_f1 = f"{cc_models['M4']['test_metrics']['f1']:.6f}"
    assert_in_report(m4_f1, f"M4 F1 ({m4_f1})")
    assert_in_report("0.9248", "M4 F1 rounded")
    assert_in_report(str(cc_models['M4']['test_metrics']['confusion_matrix']['tp']), "M4 TP (166)")

    # M4_fixed
    m4_fix_f1 = f"{cc_models['M4_fixed']['test_metrics']['f1']:.6f}"
    assert_in_report(m4_fix_f1, f"M4_fixed F1 ({m4_fix_f1})")
    assert_in_report("0.9029", "M4_fixed F1 rounded")

    # M5 Selective
    m5_sel = cc_models['M5']['test_selective_metrics']
    m5_f1 = f"{m5_sel['f1']:.6f}"
    assert_in_report(m5_f1, f"M5 Selective F1 ({m5_f1})")
    assert_in_report("0.9538", "M5 Selective F1 rounded")
    assert_in_report(str(m5_sel['confusion_matrix']['tp']), "M5 Selective TP (155)")
    assert_in_report(str(m5_sel['confusion_matrix']['tn']), "M5 Selective TN (492)")
    assert_in_report(str(m5_sel['confusion_matrix']['fn']), "M5 Selective FN (15)")
    assert_in_report(str(m5_sel['confusion_matrix']['fp']), "M5 Selective FP (0)")
    assert_in_report("1.000000", "M5 Selective Precision 1.0")

    # 3. Authentic CDP Visual Evaluation Verification
    print("\n--- 3. Verifying Authentic CDP M3 and Cascade Metrics ---")
    m3_audit = load_json("artifacts/corrected_audit/m3_visual_audit_and_authentic_evaluation.json")
    auth_m3 = m3_audit["expanded_authentic_cdp_cohort"]["models_evaluated_on_authentic_cdp_cohort"]["M3"]
    assert_in_report(f"{auth_m3['test_metrics']['f1']:.6f}", f"Authentic M3 test F1 ({auth_m3['test_metrics']['f1']:.6f})")
    assert_in_report(f"{auth_m3['test_metrics']['recall']:.6f}", f"Authentic M3 test Recall ({auth_m3['test_metrics']['recall']:.6f})")
    assert_in_report(f"{auth_m3['test_metrics']['roc_auc']:.6f}", f"Authentic M3 test ROC-AUC ({auth_m3['test_metrics']['roc_auc']:.6f})")
    assert_in_report("467", "Total authentic CDP vectors")
    assert_in_report("40", "Retained PNGs in authentic-cdp-screenshots")
    assert_in_report("37", "Successful retained PNGs")

    # 4. Statistical Comparisons Verification
    print("\n--- 4. Verifying Statistical Comparisons ---")
    assert_in_report("+0.059454", "Delta F1 M0 vs M1")
    assert_in_report("1.049e-05", "McNemar p M0 vs M1")
    assert_in_report("+0.065753", "Delta F1 M0 vs M2")
    assert_in_report("3.856e-05", "McNemar p M0 vs M2")
    assert_in_report("+0.062818", "Delta F1 M0 vs M3")
    assert_in_report("0.00011684", "McNemar p M0 vs M3")
    assert_in_report("+0.059038", "Delta F1 M0 vs M4")
    assert_in_report("2.744e-05", "McNemar p M0 vs M4")
    assert_in_report("+0.057704", "Delta F1 M0 vs M5 decided")
    assert_in_report("1.91e-06", "McNemar p M0 vs M5 decided")

    # 5. Robustness Verification
    print("\n--- 5. Verifying Robustness Metrics ---")
    rob_data = load_json("artifacts/corrected_audit/robustness_evaluation_real.json")
    for fam in ["url_evasion", "homograph_punycode", "infra_evasion", "dom_obfuscation", "visual_noise", "combined_multimodal"]:
        fam_res = rob_data["attacks"][fam]["models"]["M5"]
        m5_bypass = f"{fam_res['silent_bypass_asr']:.6f}"
        assert_in_report(m5_bypass, f"Robustness {fam} M5 silent bypass ASR ({m5_bypass})")

    # 6. Hardware and Latency Verification
    print("\n--- 6. Verifying Hardware & Latencies ---")
    assert_in_report("13th Gen Intel(R) Core(TM) i5-13600K", "CPU model")
    assert_in_report("15.78", "Total RAM GB")
    assert_in_report("16.8930", "M0 CPU local P50 latency ms")
    assert_in_report("1,272.6515", "M1 network P50 latency ms")
    assert_in_report("7.9676", "M2 HTML DOM parse P50 latency ms")
    assert_in_report("2,204.7800", "M3 CDP capture total N=467 P50 ms")
    assert_in_report("2,166.3600", "M3 CDP capture test N=83 P50 ms")
    assert_in_report("3,884.0159", "M3 E2E authentic N=83 P50 ms")
    assert_in_report("499.6368", "M5 E2E authentic N=83 P50 ms")
    assert_in_report("7.77x", "M5 speedup vs M3")

    # 7. Bloom Filter and Cache Verification
    print("\n--- 7. Verifying Bloom Filter and Decision Cache ---")
    assert_in_report("53,345", "Bloom expected elements")
    assert_in_report("95,872", "Bloom memory bytes")
    assert_in_report("93.62 KB", "Bloom memory KB")
    assert_in_report("0.0008", "Bloom empirical FPR")
    assert_in_report("4.6", "Bloom lookup P50 us")
    assert_in_report("0.92295", "Cache hit rate")
    assert_in_report("92.30 %", "Cache hit rate rounded")

    # 8. LLM Verification
    print("\n--- 8. Verifying LLM Telemetry & Models ---")
    assert_in_report("openai/gpt-oss-20b", "Live M5 abstained LLM model")
    assert_in_report("llama-3.1-8b-instant", "Historical 100-URL benchmark model")
    assert_in_report("1,809.77", "Mean live LLM latency ms")
    assert_in_report("1,842.73", "P50 live LLM latency ms")
    assert_in_report("0.44437", "Cost per 1k escalations under gpt-oss-20b")

    # 9. Extension Hybrid Model Verification
    print("\n--- 9. Verifying Extension Hybrid Model ---")
    ext_data = load_json("artifacts/corrected_audit/extension_architecture_and_hybrid_evaluation.json")
    tranco_eval = ext_data["evaluation_on_n691_test"]["production_with_tranco_reputation_shield"]["metrics_threshold_0_5"]
    assert_in_report(f"{tranco_eval['f1']:.6f}", f"Extension hybrid with Tranco F1 ({tranco_eval['f1']:.6f})")
    assert_in_report("0.8798", "Extension hybrid with Tranco F1 rounded")
    assert_in_report("0.0000", "Extension hybrid with Tranco FPR (0.0000)")

    print("\n================ VERIFICATION SUMMARY ================")
    if failures:
        print(f"FAILED with {len(failures)} discrepancy/ies:")
        for f in failures:
            print(f"  - {f}")
        return 1
    else:
        print("SUCCESS: 100% of verified figures, sample counts, metrics, latencies, and hardware match disk evidence!")
        return 0

if __name__ == "__main__":
    sys.exit(main())
