from datetime import datetime, timedelta, timezone

from phishguard_data.hashing import sha256_text
from phishguard_data.models import Sample
from phishguard_data.splits import (
    conventional_split,
    host_unseen_split,
    temporal_split,
)


def make_sample(index: int, observed_at: str, domain: str | None = None) -> Sample:
    label = "phishing" if index % 2 else "legitimate"
    host = domain or f"domain-{index}.com"
    url = f"https://{host}/{index}"
    return Sample(
        sample_id=sha256_text(f"{label}\0{url}"),
        canonical_url=url,
        canonical_url_sha256=sha256_text(url),
        label=label,
        source="fixture",
        source_record_id=str(index),
        source_timestamp=None,
        observed_at=observed_at,
        first_observed_at=observed_at,
        scheme="https",
        host=host,
        registered_domain=host,
        has_userinfo=False,
        target=None,
        rank=None,
        url_origin="reported_url",
        snapshot_id=observed_at,
    )


def test_conventional_split_is_deterministic_and_stratified() -> None:
    timestamp = "2026-01-01T00:00:00Z"
    samples = [make_sample(index, timestamp) for index in range(40)]
    ratios = {"train": 0.7, "validation": 0.15, "test": 0.15}

    first = conventional_split(samples, ratios, seed=7)
    second = conventional_split(reversed(samples), ratios, seed=7)

    assert first == second
    for partition in ratios:
        labels = {sample.label for sample in samples if first[sample.sample_id] == partition}
        assert labels == {"legitimate", "phishing"}


def test_host_unseen_has_no_domain_overlap() -> None:
    timestamp = "2026-01-01T00:00:00Z"
    samples = [make_sample(index, timestamp, f"group-{index // 2}.com") for index in range(60)]
    assignments = host_unseen_split(
        samples,
        {"train": 0.7, "validation": 0.15, "test": 0.15},
        seed=9,
    )

    domain_partition: dict[str, str] = {}
    for sample in samples:
        partition = assignments[sample.sample_id]
        assert domain_partition.setdefault(sample.registered_domain, partition) == partition


def test_temporal_split_keeps_snapshot_boundaries_and_order() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    samples = []
    for day in range(4):
        observed_at = (start + timedelta(days=day)).isoformat().replace("+00:00", "Z")
        samples.extend(make_sample(day * 10 + item, observed_at) for item in range(10))

    assignments, reason = temporal_split(
        samples,
        {"train": 0.7, "validation": 0.15, "test": 0.15},
    )

    assert reason is None
    dates_by_partition = {
        partition: {sample.observed_at for sample in samples if assignments[sample.sample_id] == partition}
        for partition in ("train", "validation", "test")
    }
    assert max(dates_by_partition["train"]) < min(dates_by_partition["validation"])
    assert max(dates_by_partition["validation"]) < min(dates_by_partition["test"])


def test_temporal_split_is_unavailable_for_one_snapshot() -> None:
    samples = [make_sample(index, "2026-01-01T00:00:00Z") for index in range(10)]

    assignments, reason = temporal_split(
        samples,
        {"train": 0.7, "validation": 0.15, "test": 0.15},
    )

    assert assignments == {}
    assert reason == "requires_at_least_three_snapshot_timestamps"


def test_temporal_split_enforces_minimum_span() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    samples = [
        make_sample(
            day * 10 + item,
            (start + timedelta(days=day)).isoformat().replace("+00:00", "Z"),
        )
        for day in range(3)
        for item in range(4)
    ]

    assignments, reason = temporal_split(
        samples,
        {"train": 0.7, "validation": 0.15, "test": 0.15},
        minimum_span_days=30,
    )

    assert assignments == {}
    assert reason == "snapshot_span_days_2.000_below_minimum_30"
