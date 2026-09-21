"""Evaluate LLM agent (Groq) on phishing detection benchmark."""
import asyncio
import csv
import json
import random
import sys
import time
import urllib.request
import ssl as _ssl
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.stdout.reconfigure(encoding="utf-8")

from phishguard_api.llm_agent import analyze_phishing_with_llm

DATASET = Path("data/processed/0.1.0")
OUTPUT = Path("artifacts/evaluation")
OUTPUT.mkdir(parents=True, exist_ok=True)


def load_test_samples(n=100, seed=42):
    rng = random.Random(seed)
    assignments = {}
    with open(DATASET / "splits" / "host_unseen.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["partition"] == "test":
                assignments[row["sample_id"]] = True
    samples = []
    with open(DATASET / "samples.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["sample_id"] in assignments:
                samples.append(row)
    phish = [s for s in samples if s["label"] == "phishing"]
    legit = [s for s in samples if s["label"] == "legitimate"]
    k = min(n // 2, len(phish), len(legit))
    selected = rng.sample(phish, k) + rng.sample(legit, k)
    rng.shuffle(selected)
    return selected[:n]


def download_html(url, timeout=10):
    try:
        ctx = _ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "research/0.1", "Accept": "text/html,*/*"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(2_000_000)
    except Exception:
        return None


def load_m0_predictions():
    preds = {}
    with open("artifacts/url-baseline-0.2.0/predictions.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["partition"] == "test":
                preds[row["sample_id"]] = float(row["probability_phishing"])
    return preds


async def evaluate_llm():
    print("=" * 70)
    print("LLM AGENT EVALUATION (Groq - openai/gpt-oss-20b)")
    print("=" * 70)

    samples = load_test_samples(n=100, seed=42)
    n_phish = sum(1 for s in samples if s["label"] == "phishing")
    print(f"\nBenchmark: {len(samples)} URLs ({n_phish} phishing, {len(samples) - n_phish} legitimate)")

    m0_preds = load_m0_predictions()
    results = []
    llm_ok = 0
    llm_fail = 0
    html_ok = 0
    start = time.time()

    for i, sample in enumerate(samples):
        url = sample["canonical_url"]
        label = 1 if sample["label"] == "phishing" else 0
        sid = sample["sample_id"]
        m0_prob = m0_preds.get(sid, 0.5)

        html_bytes = download_html(url)
        llm_prob = None
        llm_result = None
        llm_error = None

        if html_bytes is not None:
            html_ok += 1
            try:
                llm_result, llm_error = await analyze_phishing_with_llm(url, html_bytes)
                llm_prob = llm_result.get("probability") if llm_result else None
                if llm_prob is not None:
                    llm_ok += 1
                else:
                    llm_fail += 1
            except Exception as e:
                llm_error = {"kind": "exception", "message": str(e)[:200]}
                llm_fail += 1
        else:
            llm_error = {"kind": "html_download_failed"}

        results.append({
            "sample_id": sid, "url": url, "label": label,
            "m0_prob": m0_prob, "m0_pred": int(m0_prob >= 0.5),
            "llm_prob": llm_prob, "llm_pred": int(llm_prob >= 0.5) if llm_prob is not None else None,
            "llm_success": llm_result is not None,
            "llm_brand": llm_result.get("brand_spoofed") if llm_result else None,
            "llm_reason": (llm_result.get("reason", "")[:200] if llm_result else None),
            "llm_error": llm_error.get("kind") if llm_error else None,
        })

        if (i + 1) % 10 == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            print(f"  [{i+1}/{len(samples)}] {rate:.1f} u/s, ok={llm_ok}, fail={llm_fail}, html={html_ok}")

    elapsed = time.time() - start
    print(f"\nDone in {elapsed:.1f}s ({len(samples)/elapsed:.1f} u/s)")
    print(f"HTML: {html_ok}/{len(samples)}, LLM ok: {llm_ok}, fail: {llm_fail}")

    with open(OUTPUT / "llm_evaluation_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    return results


if __name__ == "__main__":
    results = asyncio.run(evaluate_llm())
