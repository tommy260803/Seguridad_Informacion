from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable

from phishguard_data.hashing import sha256_text
from phishguard_data.models import Sample


PARTITIONS = ("train", "validation", "test")


def _stable_order(value: str, seed: int) -> str:
    return sha256_text(f"{seed}:{value}")


def _counts(total: int, ratios: dict[str, float]) -> dict[str, int]:
    exact = {name: total * ratios[name] for name in PARTITIONS}
    result = {name: int(exact[name]) for name in PARTITIONS}
    remaining = total - sum(result.values())
    order = sorted(PARTITIONS, key=lambda name: (exact[name] - result[name], ratios[name]), reverse=True)
    for name in order[:remaining]:
        result[name] += 1
    return result


def conventional_split(samples: Iterable[Sample], ratios: dict[str, float], seed: int) -> dict[str, str]:
    by_label: dict[str, list[Sample]] = defaultdict(list)
    for sample in samples:
        by_label[sample.label].append(sample)
    assignments: dict[str, str] = {}
    for label_samples in by_label.values():
        ordered = sorted(label_samples, key=lambda sample: _stable_order(sample.sample_id, seed))
        target = _counts(len(ordered), ratios)
        offset = 0
        for partition in PARTITIONS:
            for sample in ordered[offset : offset + target[partition]]:
                assignments[sample.sample_id] = partition
            offset += target[partition]
    return assignments


def host_unseen_split(samples: Iterable[Sample], ratios: dict[str, float], seed: int) -> dict[str, str]:
    sample_list = list(samples)
    groups: dict[str, list[Sample]] = defaultdict(list)
    for sample in sample_list:
        groups[sample.registered_domain].append(sample)
    labels = sorted({sample.label for sample in sample_list})
    totals = Counter(sample.label for sample in sample_list)
    targets = {
        partition: {label: totals[label] * ratios[partition] for label in labels}
        for partition in PARTITIONS
    }
    current = {partition: Counter() for partition in PARTITIONS}
    group_order = sorted(
        groups.items(),
        key=lambda item: (-len(item[1]), _stable_order(item[0], seed)),
    )
    assignments: dict[str, str] = {}
    for domain, group in group_order:
        group_counts = Counter(sample.label for sample in group)

        def desirability(partition: str) -> tuple[float, float, str]:
            label_deficit = sum(
                (targets[partition][label] - current[partition][label]) * group_counts[label]
                for label in labels
            )
            total_target = sum(targets[partition].values())
            total_deficit = total_target - sum(current[partition].values())
            return label_deficit, total_deficit, _stable_order(f"{domain}:{partition}", seed)

        chosen = max(PARTITIONS, key=desirability)
        for sample in group:
            assignments[sample.sample_id] = chosen
            current[chosen][sample.label] += 1
    return assignments


def temporal_split(
    samples: Iterable[Sample],
    ratios: dict[str, float],
    minimum_span_days: int = 0,
) -> tuple[dict[str, str], str | None]:
    sample_list = list(samples)
    timestamps = sorted({sample.observed_at for sample in sample_list})
    if len(timestamps) < 3:
        return {}, "requires_at_least_three_snapshot_timestamps"

    groups: dict[str, list[Sample]] = defaultdict(list)
    for sample in sample_list:
        groups[sample.observed_at].append(sample)
    ordered_times = sorted(groups, key=lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")))
    first_time = datetime.fromisoformat(ordered_times[0].replace("Z", "+00:00"))
    last_time = datetime.fromisoformat(ordered_times[-1].replace("Z", "+00:00"))
    span_days = (last_time - first_time).total_seconds() / 86400
    if span_days < minimum_span_days:
        return {}, f"snapshot_span_days_{span_days:.3f}_below_minimum_{minimum_span_days}"
    cumulative: list[int] = []
    running = 0
    for timestamp in ordered_times:
        running += len(groups[timestamp])
        cumulative.append(running)
    train_target = len(sample_list) * ratios["train"]
    validation_target = len(sample_list) * (ratios["train"] + ratios["validation"])
    candidates = (
        (
            abs(cumulative[train_end - 1] - train_target)
            + abs(cumulative[validation_end - 1] - validation_target),
            train_end,
            validation_end,
        )
        for train_end in range(1, len(ordered_times) - 1)
        for validation_end in range(train_end + 1, len(ordered_times))
    )
    _, train_end, validation_end = min(candidates)
    assignments: dict[str, str] = {}
    for index, timestamp in enumerate(ordered_times):
        partition = "train" if index < train_end else "validation" if index < validation_end else "test"
        for sample in groups[timestamp]:
            assignments[sample.sample_id] = partition
    return assignments, None


def temporal_host_unseen(
    samples: Iterable[Sample], temporal_assignments: dict[str, str]
) -> tuple[dict[str, str], int]:
    sample_list = list(samples)
    past_domains = {
        sample.registered_domain
        for sample in sample_list
        if temporal_assignments.get(sample.sample_id) in {"train", "validation"}
    }
    result: dict[str, str] = {}
    excluded = 0
    for sample in sample_list:
        partition = temporal_assignments.get(sample.sample_id)
        if partition == "test" and sample.registered_domain in past_domains:
            excluded += 1
            continue
        if partition:
            result[sample.sample_id] = partition
    return result, excluded


def leakage_audit(samples: Iterable[Sample], assignments: dict[str, str]) -> dict[str, object]:
    domains: dict[str, set[str]] = {partition: set() for partition in PARTITIONS}
    sample_ids: dict[str, set[str]] = {partition: set() for partition in PARTITIONS}
    for sample in samples:
        partition = assignments.get(sample.sample_id)
        if partition in domains:
            domains[partition].add(sample.registered_domain)
            sample_ids[partition].add(sample.sample_id)
    intersections: dict[str, int] = {}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        intersections[f"domains_{left}_{right}"] = len(domains[left] & domains[right])
        intersections[f"samples_{left}_{right}"] = len(sample_ids[left] & sample_ids[right])
    return intersections
