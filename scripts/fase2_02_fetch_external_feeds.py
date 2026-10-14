"""Test and fetch external independent phishing and legitimate URL sources for Phase II."""
from __future__ import annotations

import csv
import io
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from phishguard_data.psl import PublicSuffixList

OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase2_externa" / "raw_feeds"


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    client = httpx.Client(timeout=25.0, follow_redirects=True, headers={"User-Agent": "PhishPe-Scientific-Validator/2.0"})

    sources = {
        "openphish_feed": "https://openphish.com/feed.txt",
        "openphish_github": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        "phishing_db_new_today": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
        "phishing_db_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt",
        "phishstats_api": "https://phishstats.info:2096/api/phishing?_where=(score,gt,5)&_size=400&_sort=-id",
        "hipo_universities": "https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json",
        "cisa_dotgov": "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv",
        "majestic_million": "https://downloads.majestic.com/majestic_million.csv",
    }

    manifest = {}
    for name, url in sources.items():
        print(f"Fetching {name} -> {url} ...", flush=True)
        try:
            if name == "majestic_million":
                # Stream only first 2500 lines of majestic_million.csv to save bandwidth and disk
                lines = []
                with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    for line in resp.iter_lines():
                        lines.append(line)
                        if len(lines) >= 2500:
                            break
                content = "\n".join(lines)
                out_file = OUT_DIR / f"{name}_head2500.csv"
                out_file.write_text(content, encoding="utf-8")
                manifest[name] = {
                    "url": url,
                    "status": "success",
                    "fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "lines_or_records": len(lines) - 1,
                    "saved_to": str(out_file.relative_to(ROOT)),
                }
                print(f"  [OK] {name}: {len(lines)-1} rows saved.", flush=True)
            else:
                resp = client.get(url)
                resp.raise_for_status()
                ext = ".json" if url.endswith(".json") or "api/phishing" in url else (".csv" if url.endswith(".csv") else ".txt")
                out_file = OUT_DIR / f"{name}{ext}"
                out_file.write_bytes(resp.content)
                count = len(json.loads(resp.text)) if ext == ".json" else len(resp.text.splitlines())
                manifest[name] = {
                    "url": url,
                    "status": "success",
                    "http_status": resp.status_code,
                    "fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "bytes": len(resp.content),
                    "lines_or_records": count,
                    "saved_to": str(out_file.relative_to(ROOT)),
                }
                print(f"  [OK] {name}: {count} records ({len(resp.content)} bytes).", flush=True)
        except Exception as e:
            manifest[name] = {
                "url": url,
                "status": "error",
                "error": str(e),
                "fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            print(f"  [ERR] {name}: {e}", flush=True)

    (OUT_DIR / "feeds_fetch_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
