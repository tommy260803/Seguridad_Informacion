"""Objective 3: Audit M3, separate synthetic PIL images from authentic Chrome CDP screenshots,
expand authentic live CDP capture, and run an independent 100% authentic visual evaluation.
"""
from __future__ import annotations

import asyncio
import base64
import collections
import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import joblib
import numpy as np
import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_common import collect_environment_metadata
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features, load_content_results
from phishguard_ml.evaluation import classification_metrics, select_f1_threshold, select_fpr_threshold
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features, load_infrastructure_results
from phishguard_ml.visual import VISUAL_FEATURE_NAMES, extract_visual_features
from phishguard_visual.analyzer import analyze_screenshot

DATASET_DIR = Path("data/processed/0.1.0")
ANALYSIS_DIR = Path("artifacts/analysis-results")
ORIG_SNAP_DIR = Path("artifacts/original_audit_snapshot")
CORRECTED_DIR = Path("artifacts/corrected_audit")
AUTHENTIC_SHOTS_DIR = Path("artifacts/authentic-cdp-screenshots")

CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def find_browser_executable() -> str:
    for p in CHROME_PATHS:
        if Path(p).exists():
            return p
    raise RuntimeError("No local Chrome or Edge executable found.")


async def capture_live_cdp_one(
    http_client: httpx.AsyncClient,
    debug_port: int,
    sample_id: str,
    url: str,
    tmp_dir: Path,
    save_dir: Path | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    target_id: str | None = None
    try:
        resp = await http_client.put(f"http://127.0.0.1:{debug_port}/json/new", timeout=2.5)
        resp.raise_for_status()
        target_info = resp.json()
        target_id = target_info["id"]
        ws_url = target_info["webSocketDebuggerUrl"]

        async with websockets.connect(ws_url, max_size=16_000_000, open_timeout=1.8, close_timeout=0.8) as ws:
            await ws.send(json.dumps({"id": 1, "method": "Page.enable"}))
            await asyncio.wait_for(ws.recv(), timeout=1.2)

            await ws.send(json.dumps({"id": 3, "method": "Page.navigate", "params": {"url": url}}))
            nav_deadline = time.perf_counter() + 2.5
            nav_error = None
            while time.perf_counter() < nav_deadline:
                try:
                    raw_msg = await asyncio.wait_for(ws.recv(), timeout=0.5)
                except asyncio.TimeoutError:
                    break
                msg = json.loads(raw_msg)
                if msg.get("id") == 3 and msg.get("result", {}).get("errorText"):
                    nav_error = msg["result"]["errorText"]
                    break
                if msg.get("method") in ("Page.loadEventFired", "Page.domContentEventFired"):
                    await asyncio.sleep(0.05)
                    break

            if nav_error:
                return {
                    "status": "error",
                    "capture_mode": "live_cdp_failed",
                    "observed_at": observed_at,
                    "total_elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
                    "error_code": "nav_error",
                    "error_detail": str(nav_error)[:120],
                    "features": {"visual_observation_available": 0.0},
                }

            await ws.send(
                json.dumps({"id": 4, "method": "Page.captureScreenshot", "params": {"format": "png", "fromSurface": True}})
            )
            b64_data = None
            cap_deadline = time.perf_counter() + 2.0
            while time.perf_counter() < cap_deadline:
                raw_msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                msg = json.loads(raw_msg)
                if msg.get("id") == 4:
                    b64_data = msg.get("result", {}).get("data")
                    break

            if not b64_data:
                return {
                    "status": "error",
                    "capture_mode": "live_cdp_failed",
                    "observed_at": observed_at,
                    "total_elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
                    "error_code": "empty_shot",
                    "features": {"visual_observation_available": 0.0},
                }

            png_bytes = base64.b64decode(b64_data)
            png_path = tmp_dir / f"{sample_id}.png"
            png_path.write_bytes(png_bytes)
            if save_dir is not None:
                save_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(png_path, save_dir / f"{sample_id[:20]}.png")

            vis_res = analyze_screenshot(png_path)
            png_path.unlink(missing_ok=True)
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return {
                "status": vis_res.status if vis_res.status in {"success", "blocked", "error"} else "error",
                "capture_mode": "live_cdp",
                "is_synthetic": False,
                "bytes_received": vis_res.bytes_received,
                "observed_at": observed_at,
                "total_elapsed_ms": elapsed_ms,
                "error_code": vis_res.error_code,
                "error_detail": vis_res.error_detail,
                "features": vis_res.features,
            }
    except Exception as exc:
        return {
            "status": "error",
            "capture_mode": "live_cdp_failed",
            "observed_at": observed_at,
            "total_elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            "error_code": "live_timeout",
            "error_detail": str(exc)[:120],
            "features": {"visual_observation_available": 0.0},
        }
    finally:
        if target_id:
            try:
                await http_client.get(f"http://127.0.0.1:{debug_port}/json/close/{target_id}", timeout=1.0)
            except Exception:
                pass


def audit_sandbox_screenshots() -> dict[str, Any]:
    """Audit the 91 real sandbox screenshots in artifacts/screenshots and 97 HTML previews."""
    preview_map: dict[str, str] = {}
    for p_file in sorted(glob.glob("artifacts/previews/*.html")):
        uid = os.path.splitext(os.path.basename(p_file))[0]
        head_txt = Path(p_file).read_text(encoding="utf-8", errors="ignore")[:1200]
        m = re.search(r'<base href="([^"]+)"', head_txt)
        if m:
            preview_map[uid] = m.group(1)

    records = []
    for s_file in sorted(glob.glob("artifacts/screenshots/*.png")):
        uid = os.path.splitext(os.path.basename(s_file))[0]
        url = preview_map.get(uid, "unknown")
        vis = analyze_screenshot(Path(s_file))
        records.append(
            {
                "job_id": uid,
                "url": url,
                "bytes": vis.bytes_received,
                "status": vis.status,
                "features": vis.features,
            }
        )
    unique_urls = sorted({r["url"] for r in records if r["url"] != "unknown"})
    return {
        "total_screenshot_pngs": len(records),
        "total_preview_htmls": len(preview_map),
        "matched_png_to_url_count": sum(1 for r in records if r["url"] != "unknown"),
        "unique_captured_urls": len(unique_urls),
        "unique_urls_list": unique_urls,
        "records_sample": records[:15],
    }


async def main() -> None:
    print("=== Objective 3: Auditing M3 & Expanding Authentic Chrome CDP Captures ===", flush=True)
    CORRECTED_DIR.mkdir(parents=True, exist_ok=True)
    AUTHENTIC_SHOTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Audit original visual-results-real.jsonl
    orig_vis_path = ORIG_SNAP_DIR / "analysis-results" / "visual-results-real.jsonl"
    if not orig_vis_path.exists():
        orig_vis_path = ANALYSIS_DIR / "visual-results-real.jsonl"

    samples_by_id: dict[str, dict[str, str]] = {}
    with open(DATASET_DIR / "samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            samples_by_id[r["sample_id"]] = r

    host_unseen_split: dict[str, str] = {}
    with open(DATASET_DIR / "splits" / "host_unseen.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            host_unseen_split[r["sample_id"]] = r["partition"]

    orig_records: dict[str, dict[str, Any]] = {}
    mode_counter: collections.Counter[tuple[str, str]] = collections.Counter()
    partition_mode_counter: collections.Counter[tuple[str, str, str]] = collections.Counter()

    for line in orig_vis_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        sid = row["sample_id"]
        res = row["result"]
        orig_records[sid] = res
        cm = str(res.get("capture_mode", "unknown"))
        st = str(res.get("status", "unknown"))
        mode_counter[(cm, st)] += 1
        if st == "success":
            partition_mode_counter[(cm, host_unseen_split.get(sid, "none"), samples_by_id[sid]["label"])] += 1

    print("Original visual-results-real.jsonl breakdown:", dict(mode_counter), flush=True)

    # 2. Separate existing authentic live_cdp from synthetic recorded_dom_viewport
    authentic_cdp_records: dict[str, dict[str, Any]] = {}
    synthetic_dom_records: dict[str, dict[str, Any]] = {}

    for sid, res in orig_records.items():
        if res.get("capture_mode") == "live_cdp" and res.get("status") == "success":
            r_copy = dict(res)
            r_copy["is_synthetic"] = False
            authentic_cdp_records[sid] = r_copy
        elif res.get("capture_mode") == "recorded_dom_viewport":
            r_copy = dict(res)
            r_copy["capture_mode"] = "synthetic_dom_viewport_pil"
            r_copy["is_synthetic"] = True
            synthetic_dom_records[sid] = r_copy

    # 3. Expand authentic live_cdp captures using Google Chrome Headless on Complete-Case URLs
    infra_results = load_infrastructure_results(ANALYSIS_DIR / "infrastructure-results-real.jsonl")
    content_results = load_content_results(ANALYSIS_DIR / "content-results-real.jsonl")

    cc_ids = [
        sid
        for sid in sorted(infra_results.keys())
        if infra_results[sid].get("status") == "success"
        and content_results.get(sid, {}).get("status") == "success"
        and sid not in authentic_cdp_records
    ]

    # Select balanced candidates across train (280), validation (100), test (160) -> 540 new candidates
    candidates: list[str] = []
    targets_per_part = {"train": 140, "validation": 50, "test": 80}  # per class (phishing & legitimate)
    for part, per_cls in targets_per_part.items():
        for lbl in ("phishing", "legitimate"):
             matching = [
                 sid
                 for sid in cc_ids
                 if host_unseen_split.get(sid) == part and samples_by_id[sid]["label"] == lbl
             ]
             candidates.extend(matching[:per_cls])

    print(f"Launching Headless Chrome CDP to capture {len(candidates)} additional live candidates...", flush=True)
    browser_exe = find_browser_executable()
    debug_port = 9241
    user_data_dir = Path(tempfile.mkdtemp(prefix="phishguard_cdp_audit_"))
    tmp_shot_dir = Path(tempfile.mkdtemp(prefix="phishguard_shots_audit_"))

    chrome_proc = subprocess.Popen(
        [
            browser_exe,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--ignore-certificate-errors",
            "--mute-audio",
            "--window-size=1280,720",
            f"--remote-debugging-port={debug_port}",
            f"--user-data-dir={user_data_dir}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    newly_captured = 0
    newly_failed = 0
    failed_cdp_records: dict[str, dict[str, Any]] = {}
    t_start_cdp = time.perf_counter()
    try:
        async with httpx.AsyncClient() as client:
            for _ in range(25):
                try:
                    r = await client.get(f"http://127.0.0.1:{debug_port}/json/version", timeout=1.0)
                    if r.status_code == 200:
                        break
                except Exception:
                    await asyncio.sleep(0.2)

            sem = asyncio.Semaphore(24)

            async def worker(idx: int, sid: str) -> None:
                nonlocal newly_captured, newly_failed
                url = infra_results[sid].get("final_url") or samples_by_id[sid].get("canonical_url") or samples_by_id[sid]["url"]
                async with sem:
                    try:
                        res = await asyncio.wait_for(
                            capture_live_cdp_one(
                                client,
                                debug_port,
                                sid,
                                url,
                                tmp_shot_dir,
                                save_dir=AUTHENTIC_SHOTS_DIR if idx < 40 else None,
                            ),
                            timeout=4.2,
                        )
                        if res.get("status") == "success":
                            authentic_cdp_records[sid] = res
                            newly_captured += 1
                        else:
                            failed_cdp_records[sid] = res
                            newly_failed += 1
                    except Exception as exc:
                        failed_cdp_records[sid] = {
                            "status": "error",
                            "capture_mode": "live_cdp_failed",
                            "error_code": "timeout",
                            "error_detail": str(exc)[:80],
                            "features": {"visual_observation_available": 0.0},
                        }
                        newly_failed += 1

            # Run in batches of 120 to keep Chrome responsive
            batch_size = 120
            for b_start in range(0, len(candidates), batch_size):
                batch = candidates[b_start : b_start + batch_size]
                await asyncio.gather(*(worker(b_start + i, sid) for i, sid in enumerate(batch)))
                print(
                    f"  CDP progress: {min(b_start + batch_size, len(candidates))}/{len(candidates)} "
                    f"(total authentic successes={len(authentic_cdp_records)}, new={newly_captured}, failed={newly_failed}, "
                    f"elapsed={time.perf_counter() - t_start_cdp:.1f}s)",
                    flush=True,
                )
    finally:
        chrome_proc.terminate()
        try:
            chrome_proc.wait(timeout=3)
        except Exception:
            chrome_proc.kill()
        shutil.rmtree(user_data_dir, ignore_errors=True)
        shutil.rmtree(tmp_shot_dir, ignore_errors=True)

    # 4. Write strictly separated JSONL files
    auth_jsonl_path = ANALYSIS_DIR / "visual-results-authentic-cdp.jsonl"
    synth_jsonl_path = ANALYSIS_DIR / "visual-results-synthetic-dom-proxy.jsonl"

    auth_lines = []
    synth_lines = []
    for sid in sorted(infra_results.keys()):
        if sid in authentic_cdp_records:
            auth_lines.append(json.dumps({"sample_id": sid, "result": authentic_cdp_records[sid]}, sort_keys=True))
        elif sid in failed_cdp_records:
            auth_lines.append(json.dumps({"sample_id": sid, "result": failed_cdp_records[sid]}, sort_keys=True))
        else:
            auth_lines.append(
                json.dumps(
                    {
                        "sample_id": sid,
                        "result": {
                            "status": "not_captured",
                            "capture_mode": "none",
                            "is_synthetic": False,
                            "total_elapsed_ms": 0.0,
                            "features": {"visual_observation_available": 0.0},
                        },
                    },
                    sort_keys=True,
                )
            )
        if sid in synthetic_dom_records:
            synth_lines.append(json.dumps({"sample_id": sid, "result": synthetic_dom_records[sid]}, sort_keys=True))

    auth_jsonl_path.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    synth_jsonl_path.write_text("\n".join(synth_lines) + "\n", encoding="utf-8")
    print(f"Saved {len(authentic_cdp_records)} authentic CDP records to {auth_jsonl_path}", flush=True)
    print(f"Saved {len(synthetic_dom_records)} tagged synthetic DOM-proxy records to {synth_jsonl_path}", flush=True)

    # 5. Train & Evaluate M0, M1, M2, and M3 strictly on the 100% Authentic CDP Cohort (host_unseen)
    from train_and_evaluate_all_real import train_and_select_stage_model

    auth_ids = sorted(authentic_cdp_records.keys())
    train_auth = [sid for sid in auth_ids if host_unseen_split.get(sid) == "train"]
    val_auth = [sid for sid in auth_ids if host_unseen_split.get(sid) == "validation"]
    test_auth = [sid for sid in auth_ids if host_unseen_split.get(sid) == "test"]

    def build_auth_xy(id_list: list[str], stage_idx: int) -> tuple[np.ndarray, np.ndarray]:
        y_arr = np.array([1 if samples_by_id[sid]["label"] == "phishing" else 0 for sid in id_list], dtype=np.int8)
        rows = []
        for sid in id_list:
            s = samples_by_id[sid]
            uf = extract_url_features(UrlFeatureContext(s.get("canonical_url") or s["url"], s["registered_domain"]))
            parts = [np.array([uf[k] for k in AUTHORITY_FEATURE_NAMES], dtype=np.float64)]
            if stage_idx >= 1:
                inf_f = extract_infrastructure_features(infra_results[sid])
                parts.append(np.array([inf_f[k] for k in INFRA_FEATURE_NAMES], dtype=np.float64))
            if stage_idx >= 2:
                cnt_f = extract_content_features(content_results[sid])
                parts.append(np.array([cnt_f[k] for k in CONTENT_FEATURE_NAMES], dtype=np.float64))
            if stage_idx >= 3:
                vis_f = extract_visual_features(authentic_cdp_records[sid])
                parts.append(np.array([vis_f[k] for k in VISUAL_FEATURE_NAMES], dtype=np.float64))
            rows.append(np.concatenate(parts))
        return np.asarray(rows, dtype=np.float64), y_arr

    val_domains_auth = [samples_by_id[sid]["registered_domain"] for sid in val_auth]
    auth_stage_eval: dict[str, Any] = {}
    for s_idx, s_name in enumerate(("M0", "M1", "M2", "M3")):
        X_tr, y_tr = build_auth_xy(train_auth, s_idx)
        X_va, y_va = build_auth_xy(val_auth, s_idx)
        X_te, y_te = build_auth_xy(test_auth, s_idx)
        res = train_and_select_stage_model(X_tr, y_tr, X_va, y_va, val_domains_auth, X_te, y_te)
        auth_stage_eval[s_name] = {
            "selected_candidate": res["selected_candidate"],
            "selected_threshold": res["selected_threshold"],
            "test_metrics": res["partitions_metrics"]["test"]["selected_threshold"],
            "validation_metrics": res["partitions_metrics"]["validation"]["selected_threshold"],
        }
        if s_name == "M3":
            m3_auth_dir = CORRECTED_DIR / "m3-authentic-cdp"
            m3_auth_dir.mkdir(parents=True, exist_ok=True)
            joblib.dump(
                {
                    "model": res["model"],
                    "feature_names": list(AUTHORITY_FEATURE_NAMES)
                    + list(INFRA_FEATURE_NAMES)
                    + list(CONTENT_FEATURE_NAMES)
                    + list(VISUAL_FEATURE_NAMES),
                    "selected_threshold": res["selected_threshold"],
                    "selected_candidate": res["selected_candidate"],
                },
                m3_auth_dir / "model.joblib",
            )

    # Also measure authentic live_cdp latency distribution
    cdp_lats = np.array([float(r["total_elapsed_ms"]) for r in authentic_cdp_records.values()], dtype=np.float64)

    sandbox_audit = audit_sandbox_screenshots()

    m3_audit_report = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "environment": collect_environment_metadata(),
        "original_visual_jsonl_audit": {
            "total_records": len(orig_records),
            "authentic_live_cdp_count": sum(1 for r in orig_records.values() if r.get("capture_mode") == "live_cdp" and r.get("status") == "success"),
            "synthetic_recorded_dom_viewport_count": sum(1 for r in orig_records.values() if r.get("capture_mode") == "recorded_dom_viewport"),
            "blocked_or_unavailable_count": sum(1 for r in orig_records.values() if r.get("status") != "success"),
            "finding": (
                "In original visual-results-real.jsonl, only 76/5,612 (1.35%) visual records were authentic browser screenshots "
                "(capture_mode='live_cdp'). The remaining 5,536 records (capture_mode='recorded_dom_viewport') were synthetically "
                "drawn 640x360 PNG diagrams generated with PIL.ImageDraw from DOM/URL features."
            ),
        },
        "sandbox_screenshots_audit": sandbox_audit,
        "expanded_authentic_cdp_cohort": {
            "total_authentic_live_cdp_success": len(authentic_cdp_records),
            "newly_captured_in_audit": newly_captured,
            "newly_failed_offline_or_timeout": newly_failed,
            "authentic_cdp_latency_ms": {
                "mean": round(float(np.mean(cdp_lats)), 2),
                "std": round(float(np.std(cdp_lats)), 2),
                "p50": round(float(np.percentile(cdp_lats, 50)), 2),
                "p90": round(float(np.percentile(cdp_lats, 90)), 2),
                "p95": round(float(np.percentile(cdp_lats, 95)), 2),
                "p99": round(float(np.percentile(cdp_lats, 99)), 2),
            },
            "partitions_host_unseen": {
                "train": {
                    "total": len(train_auth),
                    "phishing": sum(1 for s in train_auth if samples_by_id[s]["label"] == "phishing"),
                    "legitimate": sum(1 for s in train_auth if samples_by_id[s]["label"] == "legitimate"),
                },
                "validation": {
                    "total": len(val_auth),
                    "phishing": sum(1 for s in val_auth if samples_by_id[s]["label"] == "phishing"),
                    "legitimate": sum(1 for s in val_auth if samples_by_id[s]["label"] == "legitimate"),
                },
                "test": {
                    "total": len(test_auth),
                    "phishing": sum(1 for s in test_auth if samples_by_id[s]["label"] == "phishing"),
                    "legitimate": sum(1 for s in test_auth if samples_by_id[s]["label"] == "legitimate"),
                },
            },
            "models_evaluated_on_authentic_cdp_cohort": auth_stage_eval,
        },
    }

    (CORRECTED_DIR / "m3_visual_audit_and_authentic_evaluation.json").write_text(
        json.dumps(m3_audit_report, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Saved M3 audit & authentic evaluation to {CORRECTED_DIR / 'm3_visual_audit_and_authentic_evaluation.json'}!\n"
        f"Authentic test cohort N={len(test_auth)}: "
        f"M2 F1={auth_stage_eval['M2']['test_metrics']['f1']:.4f} vs "
        f"M3 (Authentic CDP) F1={auth_stage_eval['M3']['test_metrics']['f1']:.4f}",
        flush=True,
    )


if __name__ == "__main__":
    asyncio.run(main())
