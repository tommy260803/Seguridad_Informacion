"""Create a temporal split of the dataset using phishing report timestamps.

Phishing URLs have source_timestamps from PhishTank (2011-2026).
Legitimate URLs all share the same observed_at (snapshot date).

Strategy:
- Split phishing by source_timestamp (older=train, newer=test)
- Distribute legitimate proportionally using deterministic hashing
- Result: splits/temporal.csv
"""
import csv
import hashlib
from collections import Counter, defaultdict
from pathlib import Path

DATASET = Path("data/processed/0.1.0")
OUTPUT = DATASET / "splits" / "temporal.csv"
RATIOS = {"train": 0.80, "validation": 0.10, "test": 0.10}

def stable_hash(value: str, seed: int = 42) -> float:
    """Deterministic hash for consistent assignment."""
    h = hashlib.sha256(f"{seed}:{value}".encode()).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


# Load all samples
samples = []
with open(DATASET / "samples.csv", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        samples.append(row)

print(f"Total samples: {len(samples)}")

# Separate by label
phish = [s for s in samples if s["label"] == "phishing"]
legit = [s for s in samples if s["label"] == "legitimate"]
print(f"Phishing: {len(phish)}, Legitimate: {len(legit)}")

# === PHISHING: temporal split by source_timestamp ===
phish_with_dates = []
for s in phish:
    ts = s.get("source_timestamp", "") or s.get("observed_at", "")
    date_str = ts[:10] if ts else "0000-00-00"
    phish_with_dates.append((date_str, s))

phish_with_dates.sort(key=lambda x: x[0])

# Find cutoff for 80/20 split
n_phish = len(phish_with_dates)
train_end = int(n_phish * RATIOS["train"])
val_end = int(n_phish * (RATIOS["train"] + RATIOS["validation"]))

phish_train = [s for _, s in phish_with_dates[:train_end]]
phish_val = [s for _, s in phish_with_dates[train_end:val_end]]
phish_test = [s for _, s in phish_with_dates[val_end:]]

phish_dates = [d for d, _ in phish_with_dates]
print(f"\nPhishing temporal split:")
print(f"  Train: {len(phish_train)} (dates: {phish_dates[0]} to {phish_dates[train_end-1]})")
print(f"  Val:   {len(phish_val)} (dates: {phish_dates[train_end]} to {phish_dates[val_end-1]})")
print(f"  Test:  {len(phish_test)} (dates: {phish_dates[val_end]} to {phish_dates[-1]})")

# === LEGITIMATE: distribute proportionally with deterministic hashing ===
legit_assignments = []
for s in legit:
    h = stable_hash(s["sample_id"])
    if h < RATIOS["train"]:
        partition = "train"
    elif h < RATIOS["train"] + RATIOS["validation"]:
        partition = "validation"
    else:
        partition = "test"
    legit_assignments.append((partition, s))

legit_counts = Counter(p for p, _ in legit_assignments)
print(f"\nLegitimate deterministic split:")
for p in ["train", "validation", "test"]:
    print(f"  {p}: {legit_counts.get(p, 0)}")

# === COMBINE ===
assignments = {}
for s in phish_train:
    assignments[s["sample_id"]] = "train"
for s in phish_val:
    assignments[s["sample_id"]] = "validation"
for s in phish_test:
    assignments[s["sample_id"]] = "test"
for partition, s in legit_assignments:
    assignments[s["sample_id"]] = partition

# Write split file
with open(OUTPUT, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["sample_id", "partition"], lineterminator="\n")
    writer.writeheader()
    for sample_id in sorted(assignments):
        writer.writerow({"sample_id": sample_id, "partition": assignments[sample_id]})

# Verify
partition_counts = Counter(assignments.values())
print(f"\nFinal split ({OUTPUT.name}):")
for p in ["train", "validation", "test"]:
    total = partition_counts[p]
    p_phish = sum(1 for s in phish if assignments.get(s["sample_id"]) == p)
    p_legit = sum(1 for s in legit if assignments.get(s["sample_id"]) == p)
    print(f"  {p}: {total} (phish={p_phish}, legit={p_legit})")

# Audit: check domain leakage
train_domains = {s["registered_domain"] for s in samples if assignments.get(s["sample_id"]) == "train"}
test_domains = {s["registered_domain"] for s in samples if assignments.get(s["sample_id"]) == "test"}
leakage = train_domains & test_domains
print(f"\nDomain leakage check:")
print(f"  Train domains: {len(train_domains)}")
print(f"  Test domains: {len(test_domains)}")
print(f"  Overlapping: {len(leakage)} ({len(leakage)/len(test_domains)*100:.1f}% of test)")
