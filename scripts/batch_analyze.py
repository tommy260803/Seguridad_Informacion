"""Batch analysis of dataset URLs using real InfrastructureAnalyzer and ContentAnalyzer.

Produces:
  - artifacts/analysis-results/infrastructure-results-real.jsonl
  - artifacts/analysis-results/content-results-real.jsonl

Usage:
  python scripts/batch_analyze.py --sample-size 2000 --seed 42
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_data.psl import PublicSuffixList
from phishguard_infra.analyzer import InfrastructureAnalyzer
from phishguard_infra.config import load_infrastructure_config
from phishguard_infra.resolver import SocketResolver
from phishguard_infra.transport import PinnedHttpTransport
from phishguard_content.analyzer import analyze_html

import urllib.request
import urllib.error
import ssl as _ssl


DATASET_DIR = Path("data/processed/0.1.0")
OUTPUT_DIR = Path("artifacts/analysis-results")
PSL_PATH = Path("data/raw/public_suffix_list.dat")
CONFIG_PATH = Path("configs/infrastructure-analyzer.json")

# Limits
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 8
HTML_DOWNLOAD_TIMEOUT = 10
MAX_HTML_BYTES = 2_000_000
WORKERS_INFRA = 4
WORKERS_CONTENT = 8


def load_dataset(split_name: str) -> list[dict[str, str]]:
    """Load samples with partition assignments."""
    assignments: dict[str, str] = {}
    with open(DATASET_DIR / "splits" / f"{split_name}.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            assignments[row["sample_id"]] = row["partition"]

    samples = []
    with open(DATASET_DIR / "samples.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            partition = assignments.get(row["sample_id"])
            if partition:
                row["partition"] = partition
                samples.append(row)
    return samples


def stratified_sample(
    samples: list[dict], n: int, seed: int
) -> list[dict]:
    """Take a stratified sample by partition+label."""
    import random
    rng = random.Random(seed)
    strata: dict[tuple, list] = defaultdict(list)
    for s in samples:
        key = (s["partition"], s["label"])
        strata[key].append(s)

    selected = []
    for key, group in sorted(strata.items()):
        k = min(len(group), max(1, round(n * len(group) / len(samples))))
        selected.extend(rng.sample(group, k))

    # Trim or pad to exactly n
    if len(selected) > n:
        selected = rng.sample(selected, n)
    elif len(selected) < n:
        remaining = [s for s in samples if s not in selected]
        selected.extend(rng.sample(remaining, min(n - len(selected), len(remaining))))

    rng.shuffle(selected)
    return selected[:n]


def create_analyzer() -> InfrastructureAnalyzer:
    """Create a real InfrastructureAnalyzer."""
    config = load_infrastructure_config(CONFIG_PATH)
    psl = PublicSuffixList.from_file(PSL_PATH)
    resolver = SocketResolver()
    transport = PinnedHttpTransport(config)
    return InfrastructureAnalyzer(config, psl, resolver, transport)


def analyze_infrastructure(
    analyzer: InfrastructureAnalyzer, sample: dict
) -> dict[str, Any]:
    """Run infrastructure analysis on a single URL."""
    sample_id = sample["sample_id"]
    url = sample["canonical_url"]
    try:
        result = analyzer.analyze(url)
        return {
            "sample_id": sample_id,
            "result": result.to_dict(),
        }
    except Exception as exc:
        return {
            "sample_id": sample_id,
            "result": {
                "status": "error",
                "error_code": "batch_exception",
                "error_detail": str(exc)[:512],
                "features": {"infrastructure_available": 0.0},
                "observed_at": datetime.now(timezone.utc).isoformat(),
            },
        }


def download_html(url: str) -> bytes | None:
    """Download HTML content from a URL."""
    try:
        ctx = _ssl.create_default_context()
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "phishing-research-content/0.1",
                "Accept": "text/html,*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=HTML_DOWNLOAD_TIMEOUT, context=ctx) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type and "text" not in content_type:
                return None
            return resp.read(MAX_HTML_BYTES)
    except Exception:
        return None


def analyze_content(sample: dict) -> dict[str, Any]:
    """Download HTML and run content analysis."""
    sample_id = sample["sample_id"]
    url = sample["canonical_url"]
    try:
        body = download_html(url)
        if body is None:
            return {
                "sample_id": sample_id,
                "result": {
                    "status": "blocked",
                    "error_code": "not_html",
                    "features": {"content_available": 0.0},
                },
            }
        result = analyze_html(body, url)
        return {
            "sample_id": sample_id,
            "result": result.to_dict(),
        }
    except Exception as exc:
        return {
            "sample_id": sample_id,
            "result": {
                "status": "error",
                "error_code": "batch_exception",
                "error_detail": str(exc)[:512],
                "features": {"content_available": 0.0},
            },
        }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    """Write results as JSONL."""
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Batch analysis of dataset URLs")
    parser.add_argument("--sample-size", type=int, default=2000, help="Number of URLs to analyze")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for stratified sampling")
    parser.add_argument("--split", type=str, default="host_unseen", help="Dataset split to use")
    parser.add_argument("--infra-only", action="store_true", help="Only run infrastructure analysis")
    parser.add_argument("--content-only", action="store_true", help="Only run content analysis")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    infra_path = OUTPUT_DIR / "infrastructure-results-real.jsonl"
    content_path = OUTPUT_DIR / "content-results-real.jsonl"

    # Load existing results for resumability
    existing_infra: dict[str, dict] = {}
    existing_content: dict[str, dict] = {}
    if infra_path.exists():
        with open(infra_path, encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                existing_infra[row["sample_id"]] = row
        print(f"Loaded {len(existing_infra)} existing infrastructure results")
    if content_path.exists():
        with open(content_path, encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                existing_content[row["sample_id"]] = row
        print(f"Loaded {len(existing_content)} existing content results")

    # Load dataset
    print(f"Loading dataset from {DATASET_DIR}...")
    samples = load_dataset(args.split)
    print(f"Total samples: {len(samples)}")

    # Stratified sample
    selected = stratified_sample(samples, args.sample_size, args.seed)
    label_dist = Counter(s["label"] for s in selected)
    partition_dist = Counter(s["partition"] for s in selected)
    print(f"Selected {len(selected)} samples")
    print(f"  Labels: {dict(label_dist)}")
    print(f"  Partitions: {dict(partition_dist)}")

    # Infrastructure analysis
    if not args.content_only:
        pending_infra = [s for s in selected if s["sample_id"] not in existing_infra]
        print(f"\n=== Infrastructure Analysis ===")
        print(f"Pending: {len(pending_infra)} URLs (already done: {len(existing_infra)})")

        if pending_infra:
            analyzer = create_analyzer()
            infra_results = list(existing_infra.values())
            start = time.time()

            with ThreadPoolExecutor(max_workers=WORKERS_INFRA) as executor:
                futures = {
                    executor.submit(analyze_infrastructure, analyzer, sample): sample
                    for sample in pending_infra
                }
                for i, future in enumerate(as_completed(futures)):
                    result = future.result()
                    infra_results.append(result)
                    if (i + 1) % 100 == 0:
                        elapsed = time.time() - start
                        rate = (i + 1) / elapsed
                        eta = (len(pending_infra) - i - 1) / rate if rate > 0 else 0
                        statuses = Counter(r["result"]["status"] for r in infra_results)
                        print(f"  [{i+1}/{len(pending_infra)}] {rate:.1f} URLs/s, ETA {eta:.0f}s, statuses={dict(statuses)}")

            # Sort by sample_id for determinism
            infra_results.sort(key=lambda r: r["sample_id"])
            write_jsonl(infra_path, infra_results)
            elapsed = time.time() - start
            statuses = Counter(r["result"]["status"] for r in infra_results)
            successes = statuses.get("success", 0)
            print(f"Infrastructure done: {len(infra_results)} results in {elapsed:.1f}s")
            print(f"  Statuses: {dict(statuses)}")
            print(f"  Coverage: {successes}/{len(infra_results)} = {successes/len(infra_results)*100:.1f}%")
            print(f"  Saved to: {infra_path}")

    # Content analysis
    if not args.infra_only:
        pending_content = [s for s in selected if s["sample_id"] not in existing_content]
        print(f"\n=== Content Analysis ===")
        print(f"Pending: {len(pending_content)} URLs (already done: {len(existing_content)})")

        if pending_content:
            content_results = list(existing_content.values())
            start = time.time()

            with ThreadPoolExecutor(max_workers=WORKERS_CONTENT) as executor:
                futures = {
                    executor.submit(analyze_content, sample): sample
                    for sample in pending_content
                }
                for i, future in enumerate(as_completed(futures)):
                    result = future.result()
                    content_results.append(result)
                    if (i + 1) % 100 == 0:
                        elapsed = time.time() - start
                        rate = (i + 1) / elapsed
                        eta = (len(pending_content) - i - 1) / rate if rate > 0 else 0
                        statuses = Counter(r["result"]["status"] for r in content_results)
                        print(f"  [{i+1}/{len(pending_content)}] {rate:.1f} URLs/s, ETA {eta:.0f}s, statuses={dict(statuses)}")

            content_results.sort(key=lambda r: r["sample_id"])
            write_jsonl(content_path, content_results)
            elapsed = time.time() - start
            statuses = Counter(r["result"]["status"] for r in content_results)
            successes = statuses.get("success", 0)
            print(f"Content done: {len(content_results)} results in {elapsed:.1f}s")
            print(f"  Statuses: {dict(statuses)}")
            print(f"  Coverage: {successes}/{len(content_results)} = {successes/len(content_results)*100:.1f}%")
            print(f"  Saved to: {content_path}")

    print("\n=== Summary ===")
    if infra_path.exists():
        with open(infra_path, encoding="utf-8") as f:
            count = sum(1 for _ in f)
        print(f"  Infrastructure results: {count} ({infra_path})")
    if content_path.exists():
        with open(content_path, encoding="utf-8") as f:
            count = sum(1 for _ in f)
        print(f"  Content results: {count} ({content_path})")


if __name__ == "__main__":
    main()
