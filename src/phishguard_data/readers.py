from __future__ import annotations

import bz2
import csv
import gzip
import io
import json
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, TextIO

from phishguard_data.models import SourceRecord


def normalize_timestamp(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def open_text_auto(path: Path) -> Iterator[TextIO]:
    suffix = path.suffix.lower()
    if suffix == ".bz2":
        with bz2.open(path, "rt", encoding="utf-8-sig", newline="") as stream:
            yield stream
        return
    if suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8-sig", newline="") as stream:
            yield stream
        return
    if suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            files = [item for item in archive.infolist() if not item.is_dir()]
            if len(files) != 1:
                raise ValueError(f"Expected one file inside {path}, found {len(files)}")
            with archive.open(files[0]) as binary:
                with io.TextIOWrapper(binary, encoding="utf-8-sig", newline="") as stream:
                    yield stream
        return
    with path.open("rt", encoding="utf-8-sig", newline="") as stream:
        yield stream


def read_phishtank(path: Path, observed_at: str) -> Iterator[SourceRecord]:
    with open_text_auto(path) as stream:
        first = stream.read(1)
        stream.seek(0)
        if first == "[":
            rows = json.load(stream)
            if not isinstance(rows, list):
                raise ValueError("PhishTank JSON root must be a list")
        else:
            rows = csv.DictReader(stream)
        for index, raw_row in enumerate(rows, start=1):
            row = {str(key).strip().lower(): value for key, value in raw_row.items()}
            url = str(row.get("url") or "").strip()
            source_id = str(row.get("phish_id") or index)
            verified = str(row.get("verified") or "yes").strip().lower()
            if verified not in {"yes", "true", "1"}:
                continue
            timestamp = normalize_timestamp(
                str(row.get("verification_time") or row.get("submission_time") or "")
            )
            yield SourceRecord(
                source="phishtank",
                source_record_id=source_id,
                raw_url=url,
                label="phishing",
                source_timestamp=timestamp,
                observed_at=observed_at,
                target=str(row.get("target") or "").strip() or None,
            )


def read_tranco(path: Path, observed_at: str, limit: int) -> Iterator[SourceRecord]:
    with open_text_auto(path) as stream:
        rows = csv.reader(stream)
        for index, row in enumerate(rows, start=1):
            if not row:
                continue
            if len(row) >= 2:
                raw_rank, domain = row[0].strip(), row[1].strip()
            else:
                raw_rank, domain = str(index), row[0].strip()
            try:
                rank = int(raw_rank)
            except ValueError:
                if index == 1:
                    continue
                raise ValueError(f"Invalid Tranco rank at row {index}: {raw_rank!r}")
            if rank > limit:
                break
            yield SourceRecord(
                source="tranco",
                source_record_id=str(rank),
                raw_url=f"https://{domain}/",
                label="legitimate",
                source_timestamp=None,
                observed_at=observed_at,
                rank=rank,
                url_origin="constructed_from_domain",
            )
