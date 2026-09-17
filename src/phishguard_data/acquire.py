from __future__ import annotations

import json
import hashlib
import os
import platform
import ssl
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from phishguard_data import __version__
from phishguard_data.config import PipelineConfig, SourceConfig
from phishguard_data.hashing import sha256_file


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _url_identity(value: str) -> dict[str, str | None]:
    parsed = urlsplit(value)
    return {
        "origin": f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else None,
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def _resolve_version(source: SourceConfig, config: PipelineConfig) -> str | None:
    if not source.version_url:
        return None
    parsed = urlsplit(source.version_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Version endpoint must be an HTTPS URL: {source.version_url}")
    request = urllib.request.Request(source.version_url, headers={"User-Agent": config.acquisition.user_agent})
    with urllib.request.urlopen(
        request,
        timeout=config.acquisition.timeout_seconds,
        context=ssl.create_default_context(),
    ) as response:
        if urlsplit(response.geturl()).scheme != "https":
            raise ValueError(f"Version endpoint redirected outside HTTPS: {response.geturl()}")
        value = response.read(257)
    if len(value) > 256:
        raise ValueError(f"Version endpoint response is too large: {source.name}")
    resolved = value.decode("utf-8").strip()
    if not resolved or any(ord(character) < 32 for character in resolved):
        raise ValueError(f"Version endpoint returned an invalid value: {source.name}")
    return resolved


def _download(source: SourceConfig, destination: Path, config: PipelineConfig) -> dict[str, object]:
    parsed = urlsplit(source.url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Acquisition source must be an HTTPS URL: {source.url}")
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": config.acquisition.user_agent, "Accept-Encoding": "identity"},
    )
    temporary = destination.with_suffix(destination.suffix + ".part")
    total = 0
    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(
            request,
            timeout=config.acquisition.timeout_seconds,
            context=context,
        ) as response:
            final_url = response.geturl()
            if urlsplit(final_url).scheme != "https":
                raise ValueError(f"Acquisition redirected outside HTTPS: {final_url}")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > config.acquisition.max_download_bytes:
                raise ValueError(f"Source exceeds configured size limit: {source.name}")
            with temporary.open("xb") as output:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > config.acquisition.max_download_bytes:
                        raise ValueError(f"Source exceeded configured size limit: {source.name}")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(destination)
            return {
                "name": source.name,
                "requested_url": _url_identity(source.url),
                "final_url": _url_identity(final_url),
                "filename": source.filename,
                "terms_url": source.terms_url,
                "version_hint": source.version_hint,
                "resolved_version": _resolve_version(source, config),
                "bytes": total,
                "sha256": sha256_file(destination),
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
            }
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def fetch_snapshot(config: PipelineConfig) -> Path:
    started = utc_now()
    snapshot_id = started.strftime("%Y%m%dT%H%M%S.%fZ")
    snapshot_dir = config.raw_dir / snapshot_id
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    records: list[dict[str, object]] = []
    try:
        for source in config.acquisition.sources:
            records.append(_download(source, snapshot_dir / source.filename, config))
        manifest = {
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "observed_at": format_utc(started),
            "completed_at": format_utc(utc_now()),
            "pipeline_version": __version__,
            "python_version": platform.python_version(),
            "user_agent": config.acquisition.user_agent,
            "sources": records,
        }
        (snapshot_dir / "acquisition-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except Exception:
        failure = {
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "observed_at": format_utc(started),
            "failed_at": format_utc(utc_now()),
            "completed_sources": records,
        }
        (snapshot_dir / "acquisition-failed.json").write_text(
            json.dumps(failure, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        raise
    return snapshot_dir
