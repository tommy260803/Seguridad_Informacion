"""Create temporal and temporal_host_unseen splits and update dataset statistics.json & manifest.json.

Phishing URLs have source_timestamps from PhishTank (2011-2026).
Legitimate URLs from Tranco are distributed deterministically by registered_domain hash
so legitimate domains do not leak across partitions.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

DATASET = Path("data/processed/0.1.0")
TEMPORAL_CSV = DATASET / "splits" / "temporal.csv"
TEMPORAL_HU_CSV = DATASET / "splits" / "temporal_host_unseen.csv"
STATS_JSON = DATASET / "statistics.json"
MANIFEST_JSON = DATASET / "manifest.json"
RATIOS = {"train": 0.80, "validation": 0.10, "test": 0.10}


def stable_hash(value: str, seed: int = 20260916) -> float:
    """Deterministic hash in [0, 1] for consistent domain-level assignment."""
    h = hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def summarize_split(samples_by_id: dict[str, dict[str, str]], assignments: dict[str, str]) -> dict:
    partitions = {}
    domains_by_part: dict[str, set[str]] = {"train": set(), "validation": set(), "test": set()}
    ids_by_part: dict[str, set[str]] = {"train": set(), "validation": set(), "test": set()}

    for part in ("test", "train", "validation"):
        part_samples = [samples_by_id[sid] for sid, p in assignments.items() if p == part]
        labels_cnt = Counter(s["label"] for s in part_samples)
        hosts = {s["host"] for s in part_samples}
        domains = {s["registered_domain"] for s in part_samples}
        domains_by_part[part] = domains
        ids_by_part[part] = {s["sample_id"] for s in part_samples}

        obs_dates = [s["observed_at"] for s in part_samples if s.get("observed_at")]
        src_dates = [s["source_timestamp"] for s in part_samples if s.get("source_timestamp")]
        partitions[part] = {
            "labels": {
                "legitimate": labels_cnt.get("legitimate", 0),
                "phishing": labels_cnt.get("phishing", 0),
            },
            "observed_at_max": max(obs_dates) if obs_dates else None,
            "observed_at_min": min(obs_dates) if obs_dates else None,
            "source_timestamp_max": max(src_dates) if src_dates else None,
            "source_timestamp_min": min(src_dates) if src_dates else None,
            "samples": len(part_samples),
            "unique_hosts": len(hosts),
            "unique_registered_domains": len(domains),
        }

    leakage_audit = {
        "domains_train_test": len(domains_by_part["train"] & domains_by_part["test"]),
        "domains_train_validation": len(domains_by_part["train"] & domains_by_part["validation"]),
        "domains_validation_test": len(domains_by_part["validation"] & domains_by_part["test"]),
        "samples_train_test": len(ids_by_part["train"] & ids_by_part["test"]),
        "samples_train_validation": len(ids_by_part["train"] & ids_by_part["validation"]),
        "samples_validation_test": len(ids_by_part["validation"] & ids_by_part["test"]),
    }
    return {
        "leakage_audit": leakage_audit,
        "partitions": partitions,
        "reason": None,
        "status": "ready",
    }


def main() -> None:
    samples = []
    with open(DATASET / "samples.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            samples.append(row)
    samples_by_id = {s["sample_id"]: s for s in samples}
    print(f"Total samples: {len(samples)}")

    phish = [s for s in samples if s["label"] == "phishing"]
    legit = [s for s in samples if s["label"] == "legitimate"]

    # Phishing: chronological order by source_timestamp
    phish_with_dates = []
    for s in phish:
        ts = s.get("source_timestamp", "") or s.get("observed_at", "")
        phish_with_dates.append((ts, s["sample_id"], s))
    phish_with_dates.sort(key=lambda x: (x[0], x[1]))

    n_phish = len(phish_with_dates)
    train_end = int(n_phish * RATIOS["train"])
    val_end = int(n_phish * (RATIOS["train"] + RATIOS["validation"]))

    assignments: dict[str, str] = {}
    for _, _, s in phish_with_dates[:train_end]:
        assignments[s["sample_id"]] = "train"
    for _, _, s in phish_with_dates[train_end:val_end]:
        assignments[s["sample_id"]] = "validation"
    for _, _, s in phish_with_dates[val_end:]:
        assignments[s["sample_id"]] = "test"

    # Legitimate: deterministic assignment by registered_domain to prevent artificial domain overlap
    for s in legit:
        h = stable_hash(s["registered_domain"], seed=42)
        if h < RATIOS["train"]:
            assignments[s["sample_id"]] = "train"
        elif h < RATIOS["train"] + RATIOS["validation"]:
            assignments[s["sample_id"]] = "validation"
        else:
            assignments[s["sample_id"]] = "test"

    # Write temporal.csv
    with open(TEMPORAL_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "partition"], lineterminator="\n")
        writer.writeheader()
        for sample_id in sorted(assignments):
            writer.writerow({"sample_id": sample_id, "partition": assignments[sample_id]})

    # Build temporal_host_unseen: exclude validation samples whose domain is in train,
    # and exclude test samples whose domain is in train or validation.
    train_domains = {
        samples_by_id[sid]["registered_domain"]
        for sid, part in assignments.items()
        if part == "train"
    }
    hu_assignments: dict[str, str] = {}
    excluded_val = 0
    excluded_test = 0
    val_domains: set[str] = set()

    for sid, part in assignments.items():
        dom = samples_by_id[sid]["registered_domain"]
        if part == "train":
            hu_assignments[sid] = "train"
        elif part == "validation":
            if dom in train_domains:
                excluded_val += 1
            else:
                hu_assignments[sid] = "validation"
                val_domains.add(dom)

    for sid, part in assignments.items():
        if part == "test":
            dom = samples_by_id[sid]["registered_domain"]
            if dom in train_domains or dom in val_domains:
                excluded_test += 1
            else:
                hu_assignments[sid] = "test"

    with open(TEMPORAL_HU_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "partition"], lineterminator="\n")
        writer.writeheader()
        for sample_id in sorted(hu_assignments):
            writer.writerow({"sample_id": sample_id, "partition": hu_assignments[sample_id]})

    temporal_summary = summarize_split(samples_by_id, assignments)
    temporal_hu_summary = summarize_split(samples_by_id, hu_assignments)

    # Audit Multimodal Real Cohort (10,000 URLs in infrastructure-results-real.jsonl)
    infra_real_path = Path("artifacts/analysis-results/infrastructure-results-real.jsonl")
    cohort_ids: set[str] = set()
    infra_success_ids: set[str] = set()
    if infra_real_path.exists():
        for line in infra_real_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            sid = row["sample_id"]
            cohort_ids.add(sid)
            if row["result"].get("status") == "success":
                infra_success_ids.add(sid)

    content_real_path = Path("artifacts/analysis-results/content-results-real.jsonl")
    content_success_ids: set[str] = set()
    if content_real_path.exists():
        for line in content_real_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row["result"].get("status") == "success":
                content_success_ids.add(row["sample_id"])

    # Load conventional and host_unseen assignments to summarize cohort across splits
    split_files = {
        "conventional": DATASET / "splits" / "conventional.csv",
        "host_unseen": DATASET / "splits" / "host_unseen.csv",
        "temporal": TEMPORAL_CSV,
        "temporal_host_unseen": TEMPORAL_HU_CSV,
    }
    cohort_splits_summary = {}
    for split_name, sp_path in split_files.items():
        sp_map = {}
        with open(sp_path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["sample_id"] in cohort_ids:
                    sp_map[r["sample_id"]] = r["partition"]
        part_counts = {}
        for part in ("train", "validation", "test"):
            p_ids = [sid for sid, p in sp_map.items() if p == part]
            p_labels = Counter(samples_by_id[sid]["label"] for sid in p_ids)
            p_cc = [sid for sid in p_ids if sid in infra_success_ids and sid in content_success_ids]
            part_counts[part] = {
                "samples_ite": len(p_ids),
                "legitimate_ite": p_labels.get("legitimate", 0),
                "phishing_ite": p_labels.get("phishing", 0),
                "samples_complete_case": len(p_cc),
            }
        cohort_splits_summary[split_name] = part_counts

    # Update statistics.json
    stats = json.loads(STATS_JSON.read_text(encoding="utf-8"))
    stats["splits"]["temporal"] = temporal_summary
    stats["splits"]["temporal_host_unseen"] = temporal_hu_summary
    stats["temporal_host_unseen_excluded_validation_samples"] = excluded_val
    stats["temporal_host_unseen_excluded_test_samples"] = excluded_test
    stats["multimodal_cohort"] = {
        "total_analyzed_samples": len(cohort_ids),
        "infra_success_samples": len(infra_success_ids),
        "content_success_samples": len(content_success_ids),
        "both_infra_and_content_success_samples": len(infra_success_ids & content_success_ids),
        "splits": cohort_splits_summary,
    }
    STATS_JSON.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Update manifest.json hashes and byte sizes
    manifest = json.loads(MANIFEST_JSON.read_text(encoding="utf-8"))
    for out_entry in manifest.get("outputs", []):
        rel_path = DATASET / out_entry["path"]
        if rel_path.exists():
            out_entry["bytes"] = rel_path.stat().st_size
            out_entry["sha256"] = compute_file_sha256(rel_path)
    MANIFEST_JSON.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("Updated temporal.csv, temporal_host_unseen.csv, statistics.json, and manifest.json successfully.")
    print(f"Temporal test samples: {temporal_summary['partitions']['test']['samples']}")
    print(
        f"Temporal host-unseen test samples: {temporal_hu_summary['partitions']['test']['samples']} "
        f"(excluded test={excluded_test}, val={excluded_val})"
    )
    print(f"Multimodal cohort total: {len(cohort_ids)}, complete-case: {len(infra_success_ids & content_success_ids)}")


if __name__ == "__main__":
    main()
