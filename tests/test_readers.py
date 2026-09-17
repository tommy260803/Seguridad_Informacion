import bz2
import zipfile
from pathlib import Path

from phishguard_data.readers import read_phishtank, read_tranco


def test_read_phishtank_bzip2_filters_unverified(tmp_path: Path) -> None:
    path = tmp_path / "phishtank.csv.bz2"
    content = (
        "phish_id,url,submission_time,verified,verification_time,online,target\n"
        "1,https://bad.example/a,2026-01-01T00:00:00Z,yes,2026-01-01T01:00:00Z,yes,Bank\n"
        "2,https://unknown.example/,2026-01-01T00:00:00Z,no,,yes,\n"
    )
    path.write_bytes(bz2.compress(content.encode("utf-8")))

    rows = list(read_phishtank(path, "2026-02-01T00:00:00Z"))

    assert len(rows) == 1
    assert rows[0].source_record_id == "1"
    assert rows[0].source_timestamp == "2026-01-01T01:00:00Z"


def test_read_tranco_zip_honors_rank_limit(tmp_path: Path) -> None:
    path = tmp_path / "tranco.csv.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("top.csv", "1,one.example\n2,two.example\n3,three.example\n")

    rows = list(read_tranco(path, "2026-02-01T00:00:00Z", limit=2))

    assert [row.rank for row in rows] == [1, 2]
    assert rows[0].raw_url == "https://one.example/"
    assert rows[0].url_origin == "constructed_from_domain"
