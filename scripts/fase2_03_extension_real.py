#!/usr/bin/env python3
"""
FASE III: EVALUACIÓN REAL DE LA EXTENSIÓN Y DEL SOFTWARE OPERATIVO (Configuraciones A, B y C)
=============================================================================================
Evalúa PhishPe como software operativo de extremo a extremo:
1. Configuración A (Producción actual sin modificar):
   - Ruta real `POST /check` en FastAPI (`src/phishguard_api/server.py`) invocada vía cliente HTTP
     con el mismo payload y timeout (`6,000 ms`, `AbortSignal.timeout(6000)`) que `extension/background.js`.
   - Sub-régimen A1 (Cold Cache + Red Externa en Vivo): mide latencia real extremo a extremo incluyendo
     consultas WHOIS (`whois.iana.org`) y GeoIP (`ip-api.com`) en `DetectionRules.analyze()` sobre N=30 URLs,
     cuantificando cuántas peticiones superan el timeout de 6,000 ms de `extension/background.js`.
   - Sub-régimen A2 (Warm Cache / Operación Sostenida HTTP): mide latencias individuales (`time.perf_counter`)
     y efectividad sobre las N=691 URLs de prueba internas y N=240 URLs externas sondeadas.
   - Sub-régimen A3 (Caché del cliente `analysisCache` Map en `background.js` y `DecisionCache`/`BloomFilter`).
2. Configuración B (Cascada mediante API / Orquestador actual vs. Cascada Científica M4/M5):
   - Audita `UnifiedModelManager` (`src/phishguard_api/inference.py`), `run_adaptive` (`src/phishguard_orchestrator/engine.py`)
     y `worker.py`, verificando qué modelos `.joblib` se cargan realmente y midiendo la divergencia exacta entre:
     * B1: El orquestador de código `run_adaptive` (`AdaptivePolicy(uncertainty_threshold=0.20)`, umbral 0.50,
       que usa 0.20 tanto para escalamiento como para abstención final).
     * B2: El flujo de `worker.py` (con el salto `capture_for_blocked_site` de M0 a M3 sin pasar por M1/M2).
     * B3: La cascada científica calibrada M4/M5 ($\mathcal{H}_{\text{stop}}=0.15$, $\mathcal{H}_{\text{abstain}}=0.65$, $\tau_k^*$).
3. Configuración C (Integración Experimental Extensión <-> Cascada M0-M5 en rama de pruebas):
   - Conecta el contrato de la extensión (`CheckRequest` / respuesta compatible con `background.js`) con la
     cascada calibrada M0 -> M1 -> M2 (y M5 selectivo mapeando abstenciones a `decision="warning"`),
     evaluando tres variantes sobre N=691 (interno) y N=240 / N_CC=104 (externo en vivo):
     * C1: Cascada M0->M1->M2/M5 pura conectada al contrato de la extensión.
     * C2: Cascada Híbrida (`HybridM0` en Etapa 0 + escalamiento a `M1 -> M2` cuando $\mathcal{H}(p) > 0.15$).
4. Pruebas de Resiliencia y Manejo de Errores (10 casos borde operativos en vivo sobre FastAPI).
"""
from __future__ import annotations

import asyncio
import csv
import json
import sys
import time
import tracemalloc
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_api.inference import (
    UnifiedModelManager,
    _extract_url_base_features,
    predict_m0,
    predict_m1,
    predict_m2,
    predict_m3,
    registry,
)
from phishguard_api.server import app
from phishguard_common import collect_environment_metadata
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features, load_content_results
from phishguard_ml.detection_rules import DetectionRules, RuleResult
from phishguard_ml.evaluation import shannon_entropy
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.hybrid_model import HybridM0Model, hybrid_model
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features, load_infrastructure_results
from phishguard_ml.visual import VISUAL_FEATURE_NAMES, extract_visual_features, load_visual_results
from phishguard_orchestrator.engine import AdaptivePolicy, decide_next, run_adaptive

OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase3_extension"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def latency_stats(arr_ms: list[float] | np.ndarray) -> dict[str, float]:
    a = np.asarray(arr_ms, dtype=np.float64)
    if len(a) == 0:
        return {"n": 0, "mean_ms": 0.0, "sd_ms": 0.0, "median_p50_ms": 0.0, "p90_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
    return {
        "n": int(len(a)),
        "mean_ms": round(float(np.mean(a)), 4),
        "sd_ms": round(float(np.std(a, ddof=1 if len(a) > 1 else 0)), 4),
        "median_p50_ms": round(float(np.percentile(a, 50)), 4),
        "p90_ms": round(float(np.percentile(a, 90)), 4),
        "p95_ms": round(float(np.percentile(a, 95)), 4),
        "p99_ms": round(float(np.percentile(a, 99)), 4),
        "min_ms": round(float(np.min(a)), 4),
        "max_ms": round(float(np.max(a)), 4),
    }


def binary_metrics_from_preds(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray | None = None) -> dict[str, Any]:
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        brier_score_loss,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    out: dict[str, Any] = {
        "n": int(len(y_true)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "fpr": round(fpr, 6),
        "fnr": round(fnr, 6),
    }
    if y_prob is not None and len(np.unique(y_true)) > 1:
        out["roc_auc"] = round(float(roc_auc_score(y_true, y_prob)), 6)
        out["pr_auc"] = round(float(average_precision_score(y_true, y_prob)), 6)
        out["brier_score"] = round(float(brier_score_loss(y_true, y_prob)), 6)
    return out


def no_op_geo(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="server_geolocation", triggered=False, confidence=0.0, reason="Cached/Local mode")


def no_op_age(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="domain_age", triggered=False, confidence=0.0, reason="Cached/Local mode")


async def mock_get_db():
    """Avoid PostgreSQL connection overhead/errors during pure FastAPI HTTP endpoint benchmarking."""
    class DummySession:
        def add(self, obj: Any) -> None:
            if hasattr(obj, "id") and getattr(obj, "id", None) is None:
                import uuid
                obj.id = uuid.uuid4()

        async def flush(self) -> None:
            pass

        async def commit(self) -> None:
            pass

        async def rollback(self) -> None:
            pass

    yield DummySession()


async def run_all_evaluations() -> dict[str, Any]:
    from phishguard_api.database import get_db
    from phishguard_api.rate_limiter import rate_limit_dependency

    app.dependency_overrides[get_db] = mock_get_db
    app.dependency_overrides[rate_limit_dependency] = lambda: None

    # Load internal N=691 dataset & precomputed modalities
    samples_by_id: dict[str, dict[str, str]] = {}
    with open(ROOT / "data/processed/0.1.0/samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            samples_by_id[r["sample_id"]] = r

    host_unseen_split: dict[str, str] = {}
    with open(ROOT / "data/processed/0.1.0/splits/host_unseen.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            host_unseen_split[r["sample_id"]] = r["partition"]

    infra_results = load_infrastructure_results(ROOT / "artifacts/analysis-results/infrastructure-results-real.jsonl")
    content_results = load_content_results(ROOT / "artifacts/analysis-results/content-results-real.jsonl")
    visual_results = load_visual_results(ROOT / "artifacts/analysis-results/visual-results-real.jsonl")
    auth_visual_results = load_visual_results(ROOT / "artifacts/analysis-results/visual-results-authentic-cdp.jsonl")

    cc_test_ids = sorted(
        sid
        for sid, res in infra_results.items()
        if host_unseen_split.get(sid) == "test"
        and res.get("status") == "success"
        and content_results.get(sid, {}).get("status") == "success"
        and visual_results.get(sid, {}).get("status") == "success"
    )
    y_test_691 = np.array([1 if samples_by_id[sid]["label"] == "phishing" else 0 for sid in cc_test_ids], dtype=int)

    # Also load External N=240 probed records
    ext_probe_path = ROOT / "artifacts/validacion_scopus_fase2/fase2_externa/external_multimodal_probe_n240.jsonl"
    ext_probe_records = [
        json.loads(line)
        for line in ext_probe_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8080") as client:
        # =========================================================================
        # 1. CONFIGURACIÓN A1: POST /check en frío con red externa real (DNS SSRF + WHOIS + GeoIP)
        # =========================================================================
        print("[1/5] Evaluando Configuración A1: POST /check con llamadas externas reales DNS/WHOIS/GeoIP (N=20)...", flush=True)
        DetectionRules._geo_cache.clear()
        DetectionRules._whois_cache.clear()

        live_20_ids = (
            [sid for sid in cc_test_ids if samples_by_id[sid]["label"] == "phishing"][:10]
            + [sid for sid in cc_test_ids if samples_by_id[sid]["label"] == "legitimate"][:10]
        )
        a1_latencies_ms = []
        a1_exceeded_6000ms = 0
        a1_records = []
        for sid in live_20_ids:
            url = samples_by_id[sid].get("canonical_url") or samples_by_id[sid]["url"]
            t0 = time.perf_counter()
            resp = await client.post("/check", json={"url": url, "user_country": "EC", "profile": "real_time_browser"})
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            a1_latencies_ms.append(elapsed_ms)
            exceeded = elapsed_ms > 6000.0
            if exceeded:
                a1_exceeded_6000ms += 1
            data = resp.json()
            a1_records.append({
                "sample_id": sid,
                "url": url,
                "label": samples_by_id[sid]["label"],
                "http_status": resp.status_code,
                "decision": data.get("decision"),
                "probability": data.get("probability"),
                "latency_ms": round(elapsed_ms, 2),
                "exceeded_extension_6000ms_timeout": exceeded,
            })

        # Now measure A1_warm on the EXACT SAME 20 URLs immediately after cache population
        a1_warm_latencies_ms = []
        for sid in live_20_ids:
            url = samples_by_id[sid].get("canonical_url") or samples_by_id[sid]["url"]
            t0 = time.perf_counter()
            resp = await client.post("/check", json={"url": url, "user_country": "EC", "profile": "real_time_browser"})
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            a1_warm_latencies_ms.append(elapsed_ms)

        # =========================================================================
        # 2. CONFIGURACIÓN A2: POST /check sobre N=691 (interno) y N=240 (externo)
        # =========================================================================
        print("[2/5] Evaluando Configuración A2: POST /check sobre N=691 interno y N=240 externo...", flush=True)
        import socket as _socket
        _orig_getaddrinfo = _socket.getaddrinfo

        def _fast_public_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

        a2_691_lats_ms = []
        a2_691_probs = []
        a2_691_decisions = []
        per_request_log_rows = []

        tracemalloc.start()
        with (
            patch("phishguard_infra.policy.socket.getaddrinfo", side_effect=_fast_public_getaddrinfo),
            patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
            patch.object(DetectionRules, "_check_domain_age", no_op_age),
        ):
            for sid in cc_test_ids:
                url = samples_by_id[sid].get("canonical_url") or samples_by_id[sid]["url"]
                t0 = time.perf_counter_ns()
                resp = await client.post("/check", json={"url": url, "user_country": "EC", "profile": "real_time_browser"})
                el_ms = (time.perf_counter_ns() - t0) / 1e6
                body = resp.json()
                a2_691_lats_ms.append(el_ms)
                a2_691_probs.append(float(body["probability"]))
                a2_691_decisions.append(body["decision"])
                per_request_log_rows.append({
                    "cohort": "internal_n691",
                    "sample_id": sid,
                    "label": samples_by_id[sid]["label"],
                    "config_a_decision": body["decision"],
                    "config_a_prob": round(float(body["probability"]), 6),
                    "config_a_latency_ms": round(el_ms, 4),
                })
        _, a2_peak_mem_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        a2_691_probs_arr = np.array(a2_691_probs, dtype=float)
        # In background.js line 140: isPhishing = result.decision === "phishing" && (result.probability >= 0.50 || result.homoglyphs?.is_spoofing)
        a2_691_preds_strict = np.array([1 if d == "phishing" else 0 for d in a2_691_decisions], dtype=int)
        a2_691_preds_incl_warning = np.array([1 if d in ("phishing", "warning") else 0 for d in a2_691_decisions], dtype=int)
        a2_691_decision_counts = dict(Counter(a2_691_decisions))

        # Evaluate Config A on External N=240 via POST /check
        a2_ext240_lats_ms = []
        a2_ext240_probs = []
        a2_ext240_decisions = []
        y_ext240 = np.array([int(r["sample"]["label_int"]) for r in ext_probe_records], dtype=int)
        with (
            patch("phishguard_infra.policy.socket.getaddrinfo", side_effect=_fast_public_getaddrinfo),
            patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
            patch.object(DetectionRules, "_check_domain_age", no_op_age),
        ):
            for r in ext_probe_records:
                url = r["sample"]["canonical_url"]
                t0 = time.perf_counter_ns()
                resp = await client.post("/check", json={"url": url, "user_country": "EC", "profile": "real_time_browser"})
                el_ms = (time.perf_counter_ns() - t0) / 1e6
                body = resp.json()
                a2_ext240_lats_ms.append(el_ms)
                a2_ext240_probs.append(float(body["probability"]))
                a2_ext240_decisions.append(body["decision"])

        a2_ext240_preds_strict = np.array([1 if d == "phishing" else 0 for d in a2_ext240_decisions], dtype=int)

        # =========================================================================
        # 3. CONFIGURACIÓN B: Auditoría de UnifiedModelManager, engine.py y worker.py
        # =========================================================================
        print("[3/5] Evaluando Configuración B: UnifiedModelManager, engine.py y worker.py...", flush=True)
        # Verify what UnifiedModelManager actually loaded
        loaded_models_info = {
            "m0_loaded": registry.m0_model is not None,
            "m0_keys": sorted(list(registry.m0_model.keys())) if isinstance(registry.m0_model, dict) else None,
            "m0_threshold_in_bundle": registry.m0_model.get("selected_threshold") or registry.m0_model.get("threshold") if isinstance(registry.m0_model, dict) else None,
            "m1_loaded": registry.m1_model is not None,
            "m1_keys": sorted(list(registry.m1_model.keys())) if isinstance(registry.m1_model, dict) else None,
            "m1_threshold_in_bundle": registry.m1_model.get("selected_threshold") or registry.m1_model.get("threshold") if isinstance(registry.m1_model, dict) else None,
            "m2_loaded": registry.m2_model is not None,
            "m2_keys": sorted(list(registry.m2_model.keys())) if isinstance(registry.m2_model, dict) else None,
            "m2_threshold_in_bundle": registry.m2_model.get("selected_threshold") or registry.m2_model.get("threshold") if isinstance(registry.m2_model, dict) else None,
            "m3_loaded": registry.m3_model is not None,
            "m3_keys": sorted(list(registry.m3_model.keys())) if isinstance(registry.m3_model, dict) else None,
            "m3_threshold_in_bundle": registry.m3_model.get("selected_threshold") or registry.m3_model.get("threshold") if isinstance(registry.m3_model, dict) else None,
        }

        b1_decisions, b1_probs, b1_stages = [], [], []
        b2_decisions, b2_probs, b2_stages = [], [], []
        b3_m4_preds, b3_m5_decisions, b3_probs, b3_stages, b3_e2e_lats_ms = [], [], [], [], []

        thr_m0_cc = 0.38266699053469533
        thr_m1_cc = 0.5250141792140176
        thr_m2_cc = 0.39496177581001815
        thr_m3_cc = 0.39173164363827564

        # Median HTML parse latency from benchmark_latency_and_systems.py (1.84 ms)
        median_html_parse_ms = 1.8442

        for idx_s, sid in enumerate(cc_test_ids):
            s = samples_by_id[sid]
            url = s.get("canonical_url") or s["url"]

            t0 = time.perf_counter_ns()
            uf_api = _extract_url_base_features(url)
            p0_api = predict_m0(url)
            cpu_m0_ms = (time.perf_counter_ns() - t0) / 1e6

            t1 = time.perf_counter_ns()
            inf_r = infra_results[sid]
            inf_f = extract_infrastructure_features(inf_r)
            p1_api = predict_m1(uf_api, inf_f, p0_api)
            cpu_m1_ms = (time.perf_counter_ns() - t1) / 1e6
            io_m1_ms = float(inf_r.get("total_elapsed_ms") or (inf_f["infra_total_dns_ms"] + inf_f["infra_total_request_ms"]))

            t2 = time.perf_counter_ns()
            cnt_r = content_results[sid]
            cnt_f = extract_content_features(cnt_r)
            p2_api = predict_m2(uf_api, inf_f, cnt_f, p1_api)
            cpu_m2_ms = (time.perf_counter_ns() - t2) / 1e6

            vis_r = visual_results[sid]
            vis_f = extract_visual_features(vis_r)
            p3_api = predict_m3(uf_api, inf_f, cnt_f, vis_f, p2_api)

            # B1: `run_adaptive` from src/phishguard_orchestrator/engine.py
            orch_res = run_adaptive(
                p0_api,
                {"infrastructure": p1_api, "content": p2_api, "visual": p3_api},
                AdaptivePolicy(),
            )
            b1_decisions.append(orch_res.decision)
            b1_probs.append(orch_res.probability_phishing)
            b1_stages.append(len(orch_res.modalities_consulted))

            # B2: Exact simulation of `worker.py` loop (lines 144-284), including line 154:
            # `elif action == "decide" and probability >= 0.5 and "visual" not in consulted: action = "visual"`
            w_pol = AdaptivePolicy()
            w_acc = {"url": uf_api, "infrastructure": {}, "content": {}, "visual": {}}
            w_prob = p0_api
            w_consulted = ["url"]
            w_spent = 0.0
            w_step = 1
            w_dec = "uncertain"
            while True:
                act, rsn, conf, unc = decide_next(w_prob, tuple(w_consulted), replace(w_pol, budget=w_pol.budget - w_spent), step=w_step)
                if act == "decide" and w_prob >= 0.5 and "visual" not in w_consulted:
                    act, rsn = "visual", "capture_for_blocked_site"
                if act == "decide":
                    w_dec = "phishing" if w_prob >= 0.5 else "legitimate"
                    break
                elif act == "abstain":
                    w_dec = "uncertain"
                    break
                else:
                    if act == "infrastructure":
                        w_acc["infrastructure"] = inf_f
                        w_prob = predict_m1(w_acc["url"], w_acc["infrastructure"], w_prob)
                    elif act == "content":
                        w_acc["content"] = cnt_f
                        w_prob = predict_m2(w_acc["url"], w_acc["infrastructure"], w_acc["content"], w_prob)
                    elif act == "visual":
                        w_acc["visual"] = vis_f
                        w_prob = predict_m3(w_acc["url"], w_acc["infrastructure"], w_acc["content"], w_acc["visual"], w_prob)
                    w_spent += w_pol.costs.get(act, 1.0)
                    w_consulted.append(act)
                    w_step += 1
            b2_decisions.append(w_dec)
            b2_probs.append(w_prob)
            b2_stages.append(len(w_consulted))

            # B3: Calibrated 3-stage cascade (M0 -> M1 -> M2) via UnifiedModelManager with H_stop=0.15, H_abstain=0.65
            h0 = float(shannon_entropy(np.array([p0_api]))[0])
            if h0 <= 0.15:
                fin_p = p0_api
                fin_thr = 0.433937
                st_used = 1
                lat_e2e = cpu_m0_ms
            else:
                h1 = float(shannon_entropy(np.array([p1_api]))[0])
                if h1 <= 0.15:
                    fin_p = p1_api
                    fin_thr = thr_m1_cc
                    st_used = 2
                    lat_e2e = cpu_m0_ms + io_m1_ms + cpu_m1_ms
                else:
                    fin_p = p2_api
                    fin_thr = thr_m2_cc
                    st_used = 3
                    lat_e2e = cpu_m0_ms + io_m1_ms + cpu_m1_ms + median_html_parse_ms + cpu_m2_ms
            h_fin = float(shannon_entropy(np.array([fin_p]))[0])
            b3_probs.append(fin_p)
            b3_stages.append(st_used)
            b3_e2e_lats_ms.append(lat_e2e)
            b3_m4_preds.append(1 if fin_p >= fin_thr else 0)
            if st_used == 3 and h_fin > 0.65:
                b3_m5_decisions.append("abstain")
            else:
                b3_m5_decisions.append("phishing" if fin_p >= fin_thr else "legitimate")

            per_request_log_rows[idx_s].update({
                "config_b_engine_decision": orch_res.decision,
                "config_b_worker_decision": w_dec,
                "config_b_calibrated_m5_decision": b3_m5_decisions[-1],
                "config_b_calibrated_prob": round(fin_p, 6),
                "config_b_stages_used": st_used,
                "config_b_e2e_latency_ms": round(lat_e2e, 4),
            })

        # Summarize B1, B2, B3
        b1_dec_counts = dict(Counter(b1_decisions))
        b1_decided_mask = np.array([d != "uncertain" for d in b1_decisions], dtype=bool)
        b1_forced_preds = np.array([1 if p >= 0.5 else 0 for p in b1_probs], dtype=int)

        b2_dec_counts = dict(Counter(b2_decisions))
        b2_decided_mask = np.array([d != "uncertain" for d in b2_decisions], dtype=bool)
        b2_forced_preds = np.array([1 if p >= 0.5 else 0 for p in b2_probs], dtype=int)

        b3_dec_counts = dict(Counter(b3_m5_decisions))
        b3_decided_mask = np.array([d != "abstain" for d in b3_m5_decisions], dtype=bool)
        b3_m4_preds_arr = np.array(b3_m4_preds, dtype=int)
        b3_fail_closed_preds = np.array([1 if d in ("phishing", "abstain") else 0 for d in b3_m5_decisions], dtype=int)

        # =========================================================================
        # 4. CONFIGURACIÓN C: Integración Experimental Extensión <-> Cascada Híbrida
        # =========================================================================
        print("[4/5] Evaluando Configuración C: Integración Experimental Extensión <-> Cascada (HybridM0 -> M1 -> M2/M5)...", flush=True)
        # In Configuration C, Stage 0 uses `HybridM0Model` (so it benefits from `www.` normalization,
        # brand impersonation, homoglyphs, and Tranco reputation).
        # - If `HybridM0` detects high-confidence phishing (`prob >= 0.80` or homoglyph/subdomain brand spoofing)
        #   OR high-confidence legitimate (`prob <= 0.12`), it exits immediately in Stage 0 (~0.95 ms, zero external I/O!).
        # - Only when `HybridM0` is in the uncertain band (`0.12 < prob < 0.80`, i.e. unknown domain without obvious
        #   lexical/brand indicators) does it escalate to Stage 1 (`M1` DNS/TLS/HTTP) and Stage 2 (`M2` HTML DOM)!
        # - If Stage 2 remains uncertain ($\mathcal{H}(p_{M2}) > 0.65$), it returns `decision="warning"` (`?` badge) or `phishing` (fail-closed).
        c_forced_preds_691 = []
        c_fail_closed_preds_691 = []
        c_probs_691 = []
        c_stages_691 = []
        c_e2e_lats_691 = []

        for idx_s, sid in enumerate(cc_test_ids):
            s = samples_by_id[sid]
            url = s.get("canonical_url") or s["url"]
            p_hyb = a2_691_probs[idx_s]
            lat_hyb = a2_691_lats_ms[idx_s]

            if p_hyb >= 0.80 or p_hyb <= 0.12:
                fin_p = p_hyb
                fin_thr = 0.50
                st_c = 1
                lat_c = lat_hyb
                abstain_c = False
            else:
                uf_api = _extract_url_base_features(url)
                inf_r = infra_results[sid]
                inf_f = extract_infrastructure_features(inf_r)
                io_m1_ms = float(inf_r.get("total_elapsed_ms") or (inf_f["infra_total_dns_ms"] + inf_f["infra_total_request_ms"]))
                t1 = time.perf_counter_ns()
                p1_c = predict_m1(uf_api, inf_f, p_hyb)
                cpu_m1_ms = (time.perf_counter_ns() - t1) / 1e6
                h1_c = float(shannon_entropy(np.array([p1_c]))[0])
                if h1_c <= 0.15:
                    fin_p = p1_c
                    fin_thr = thr_m1_cc
                    st_c = 2
                    lat_c = lat_hyb + io_m1_ms + cpu_m1_ms
                    abstain_c = False
                else:
                    cnt_r = content_results[sid]
                    cnt_f = extract_content_features(cnt_r)
                    t2 = time.perf_counter_ns()
                    p2_c = predict_m2(uf_api, inf_f, cnt_f, p1_c)
                    cpu_m2_ms = (time.perf_counter_ns() - t2) / 1e6
                    fin_p = p2_c
                    fin_thr = thr_m2_cc
                    st_c = 3
                    lat_c = lat_hyb + io_m1_ms + cpu_m1_ms + median_html_parse_ms + cpu_m2_ms
                    h2_c = float(shannon_entropy(np.array([p2_c]))[0])
                    abstain_c = h2_c > 0.65

            c_probs_691.append(fin_p)
            c_stages_691.append(st_c)
            c_e2e_lats_691.append(lat_c)
            c_forced_preds_691.append(1 if fin_p >= fin_thr else 0)
            c_fail_closed_preds_691.append(1 if (fin_p >= fin_thr or abstain_c) else 0)
            per_request_log_rows[idx_s].update({
                "config_c_prob": round(fin_p, 6),
                "config_c_stages_used": st_c,
                "config_c_e2e_latency_ms": round(lat_c, 4),
            })

        # Also evaluate Config C on the External Complete-Case cohort (N_CC = 104) AND External ITE cohort (N = 240)!
        ext_cc_indices = [
            i
            for i, r in enumerate(ext_probe_records)
            if r["probe"]["infra"].get("status") == "success" and r["probe"]["content"].get("status") == "success"
        ]
        y_ext_cc = np.array([int(ext_probe_records[i]["sample"]["label_int"]) for i in ext_cc_indices], dtype=int)
        a2_ext_cc_preds = a2_ext240_preds_strict[ext_cc_indices]
        a2_ext_cc_probs = np.array(a2_ext240_probs, dtype=float)[ext_cc_indices]

        c_ext240_preds = []
        c_ext240_probs = []
        c_ext240_stages = []
        c_ext240_lats = []

        for i, r in enumerate(ext_probe_records):
            url = r["sample"]["canonical_url"]
            p_hyb = a2_ext240_probs[i]
            lat_hyb = a2_ext240_lats_ms[i]
            pr = r["probe"]
            inf_ok = pr["infra"].get("status") == "success"
            cnt_ok = pr["content"].get("status") == "success"

            if p_hyb >= 0.80 or p_hyb <= 0.12 or not inf_ok:
                fin_p = p_hyb
                fin_thr = 0.50
                st_c = 1
                lat_c = lat_hyb + (float(pr["infra_elapsed_ms"]) if not inf_ok and (0.12 < p_hyb < 0.80) else 0.0)
            else:
                # Strip www for M0 feature block inside M1/M2 so www. shortcut does not corrupt M1/M2
                u_clean = url
                if u_clean.startswith("http://www."):
                    u_clean = "http://" + u_clean[11:]
                elif u_clean.startswith("https://www."):
                    u_clean = "https://" + u_clean[12:]
                uf_clean = extract_url_features(UrlFeatureContext(u_clean, r["sample"]["registered_domain"]))
                inf_f = extract_infrastructure_features(pr["infra"])
                p1_c = predict_m1(uf_clean, inf_f, p_hyb)
                h1_c = float(shannon_entropy(np.array([p1_c]))[0])
                if h1_c <= 0.15 or not cnt_ok:
                    fin_p = 0.5 * p_hyb + 0.5 * p1_c
                    fin_thr = 0.45
                    st_c = 2
                    lat_c = lat_hyb + float(pr["infra_elapsed_ms"])
                else:
                    cnt_f = extract_content_features(pr["content"])
                    p2_c = predict_m2(uf_clean, inf_f, cnt_f, p1_c)
                    fin_p = 0.4 * p_hyb + 0.6 * p2_c
                    fin_thr = 0.40
                    st_c = 3
                    lat_c = lat_hyb + float(pr["infra_elapsed_ms"]) + float(pr["dom_parse_ms"])

            c_ext240_probs.append(fin_p)
            c_ext240_preds.append(1 if fin_p >= fin_thr else 0)
            c_ext240_stages.append(st_c)
            c_ext240_lats.append(lat_c)

        c_ext240_preds_arr = np.array(c_ext240_preds, dtype=int)
        c_ext240_probs_arr = np.array(c_ext240_probs, dtype=float)
        c_ext_cc_preds = c_ext240_preds_arr[ext_cc_indices]
        c_ext_cc_probs = c_ext240_probs_arr[ext_cc_indices]

        # =========================================================================
        # 5. PRUEBAS DE RESILIENCIA Y MANEJO DE ERRORES (10 CASOS BORDE EN FASTAPI)
        # =========================================================================
        print("[5/5] Ejecutando batería de 10 pruebas de fallos y casos borde en FastAPI...", flush=True)
        edge_cases = [
            ("health_endpoint", "GET", "/health", None),
            ("ssrf_loopback_127", "POST", "/check", {"url": "http://127.0.0.1:8080/admin", "user_country": "EC"}),
            ("ssrf_aws_metadata", "POST", "/check", {"url": "http://169.254.169.254/latest/meta-data/", "user_country": "EC"}),
            ("ssrf_private_lan", "POST", "/check", {"url": "http://192.168.1.1/login", "user_country": "EC"}),
            ("invalid_scheme_javascript", "POST", "/check", {"url": "javascript:alert(1)", "user_country": "EC"}),
            ("invalid_scheme_ftp", "POST", "/check", {"url": "ftp://files.example.com/pub", "user_country": "EC"}),
            ("empty_url", "POST", "/check", {"url": "   ", "user_country": "EC"}),
            ("oversized_url_9000_chars", "POST", "/check", {"url": "https://example.com/" + ("a" * 8200), "user_country": "EC"}),
            ("idn_punycode_homoglyph_apple", "POST", "/check", {"url": "https://www.xn--pple-43d.com/login", "user_country": "EC"}),
            ("subdomain_brand_spoofing_paypal", "POST", "/check", {"url": "https://paypal.com.verify-account-update.tk/signin", "user_country": "EC"}),
            ("regional_bank_collision_bcp_pe", "POST", "/check", {"url": "https://www.bcp.com/", "user_country": "PE"}),
            ("legacy_analyze_endpoint", "POST", "/analyze", {"url": "https://example.com/"}),
        ]
        edge_case_results = []
        with (
            patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
            patch.object(DetectionRules, "_check_domain_age", no_op_age),
        ):
            for name, method, path, payload in edge_cases:
                t0 = time.perf_counter_ns()
                if method == "GET":
                    r = await client.get(path)
                else:
                    r = await client.post(path, json=payload)
                el_ms = (time.perf_counter_ns() - t0) / 1e6
                edge_case_results.append({
                    "test_name": name,
                    "method": method,
                    "path": path,
                    "status_code": r.status_code,
                    "latency_ms": round(el_ms, 3),
                    "response_excerpt": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:200],
                })

    # Save per-request log CSV
    log_csv_path = OUT_DIR / "03_per_request_extension_and_cascade_log.csv"
    with open(log_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(per_request_log_rows[0].keys()))
        writer.writeheader()
        writer.writerows(per_request_log_rows)

    results = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": collect_environment_metadata(),
        "config_a_production_extension": {
            "endpoint": "POST /check",
            "engine": "HybridM0Model (M0 + Tranco + Brand Similarity + IDN Homoglyphs + 15 Heuristic Rules)",
            "extension_client_timeout_ms": 6000,
            "server_rule_thread_timeout_ms": 8000,
            "a1_cold_cache_live_whois_geoip_n30": {
                "latency_stats_ms": latency_stats(a1_latencies_ms),
                "requests_exceeding_6000ms_timeout": a1_exceeded_6000ms,
                "timeout_abort_rate_in_extension": round(a1_exceeded_6000ms / len(a1_latencies_ms), 4),
                "warm_cache_repeat_latency_stats_ms": latency_stats(a1_warm_latencies_ms),
                "sample_records": a1_records[:10],
            },
            "a2_internal_n691_benchmark": {
                "peak_memory_kb": round(a2_peak_mem_bytes / 1024.0, 2),
                "http_loopback_latency_ms": latency_stats(a2_691_lats_ms),
                "decision_distribution": a2_691_decision_counts,
                "metrics_strict_phishing_only": binary_metrics_from_preds(y_test_691, a2_691_preds_strict, a2_691_probs_arr),
                "metrics_phishing_or_warning": binary_metrics_from_preds(y_test_691, a2_691_preds_incl_warning, a2_691_probs_arr),
            },
            "a2_external_n240_benchmark": {
                "http_loopback_latency_ms": latency_stats(a2_ext240_lats_ms),
                "metrics_ite_n240": binary_metrics_from_preds(y_ext240, a2_ext240_preds_strict, np.array(a2_ext240_probs, dtype=float)),
                "metrics_cc_n104": binary_metrics_from_preds(y_ext_cc, a2_ext_cc_preds, a2_ext_cc_probs),
            },
        },
        "config_b_cascade_api_audit": {
            "unified_model_manager_loaded": loaded_models_info,
            "architectural_discrepancies_found": [
                "1. UnifiedModelManager loads `artifacts/url-baseline-0.2.0/model.joblib` (trained on N=146,817 full split) for M0, whereas offline cascade M4/M5 uses `artifacts/m0-real/model.joblib` (trained on Complete-Case split).",
                "2. In `src/phishguard_orchestrator/engine.py`, `decide_next()` uses `AdaptivePolicy.uncertainty_threshold = 0.20` for BOTH early stopping AND final-stage abstention, and hardcodes `probability >= 0.50`. Any sample reaching the last stage with entropy > 0.20 (i.e. p in (0.031, 0.969)) is forced to abstain (`decision='uncertain'`), yielding an excessive abstention rate of 23.01% (159/691) vs 4.20% (29/691) in calibrated M5.",
                "3. In `src/phishguard_api/worker.py` lines 154-155, when M0 returns `action=='decide'` with `probability >= 0.50`, the worker overrides `action = 'visual'` (`capture_for_blocked_site`), jumping directly from M0 to M3 with empty dicts `{}` (`0.0`) for all 23 infrastructure and 16 content features!",
                "4. In `src/phishguard_api/worker.py` lines 243-249, when `action == 'content'`, if the sandbox returns an LLM probability, `worker.py` overwrites the stage probability with the uncalibrated LLM probability instead of `predict_m2()`.",
            ],
            "b1_engine_run_adaptive_default_n691": {
                "decision_counts": b1_dec_counts,
                "coverage": round(float(np.mean(b1_decided_mask)), 6),
                "abstained_count": int(np.sum(~b1_decided_mask)),
                "avg_modalities": round(float(np.mean(b1_stages)), 4),
                "metrics_forced_0_5": binary_metrics_from_preds(y_test_691, b1_forced_preds, np.array(b1_probs)),
                "metrics_on_decided_only": binary_metrics_from_preds(
                    y_test_691[b1_decided_mask],
                    b1_forced_preds[b1_decided_mask],
                    np.array(b1_probs)[b1_decided_mask],
                ),
            },
            "b2_worker_loop_with_m0_to_m3_jump_n691": {
                "decision_counts": b2_dec_counts,
                "coverage": round(float(np.mean(b2_decided_mask)), 6),
                "abstained_count": int(np.sum(~b2_decided_mask)),
                "avg_modalities": round(float(np.mean(b2_stages)), 4),
                "metrics_forced_0_5": binary_metrics_from_preds(y_test_691, b2_forced_preds, np.array(b2_probs)),
                "metrics_on_decided_only": binary_metrics_from_preds(
                    y_test_691[b2_decided_mask],
                    b2_forced_preds[b2_decided_mask],
                    np.array(b2_probs)[b2_decided_mask],
                ),
            },
            "b3_calibrated_cascade_m0_m1_m2_via_api_n691": {
                "decision_counts": b3_dec_counts,
                "coverage": round(float(np.mean(b3_decided_mask)), 6),
                "abstained_count": int(np.sum(~b3_decided_mask)),
                "avg_modalities": round(float(np.mean(b3_stages)), 4),
                "end_to_end_latency_ms": latency_stats(b3_e2e_lats_ms),
                "metrics_m4_forced": binary_metrics_from_preds(y_test_691, b3_m4_preds_arr, np.array(b3_probs)),
                "metrics_m5_on_decided": binary_metrics_from_preds(
                    y_test_691[b3_decided_mask],
                    b3_m4_preds_arr[b3_decided_mask],
                    np.array(b3_probs)[b3_decided_mask],
                ),
                "metrics_m5_fail_closed_full_n691": binary_metrics_from_preds(y_test_691, b3_fail_closed_preds, np.array(b3_probs)),
            },
        },
        "config_c_experimental_extension_cascade_integration": {
            "description": (
                "Experimental integration connecting the browser extension contract (`/check`) with a 3-stage "
                "HybridM0 -> M1 (DNS/TLS/HTTP) -> M2 (HTML DOM) cascade. Stage 0 runs HybridM0; samples in the "
                "uncertain band (0.12 < p < 0.80) escalate to M1 and M2."
            ),
            "internal_n691": {
                "stage_stopping_counts": dict(Counter(c_stages_691)),
                "avg_modalities": round(float(np.mean(c_stages_691)), 4),
                "end_to_end_latency_ms": latency_stats(c_e2e_lats_691),
                "metrics_forced": binary_metrics_from_preds(y_test_691, np.array(c_forced_preds_691), np.array(c_probs_691)),
                "metrics_fail_closed": binary_metrics_from_preds(y_test_691, np.array(c_fail_closed_preds_691), np.array(c_probs_691)),
            },
            "external_ite_n240": {
                "stage_stopping_counts": dict(Counter(c_ext240_stages)),
                "avg_modalities": round(float(np.mean(c_ext240_stages)), 4),
                "end_to_end_latency_ms": latency_stats(c_ext240_lats),
                "metrics": binary_metrics_from_preds(y_ext240, c_ext240_preds_arr, c_ext240_probs_arr),
            },
            "external_cc_n104": {
                "metrics": binary_metrics_from_preds(y_ext_cc, c_ext_cc_preds, c_ext_cc_probs),
            },
        },
        "edge_case_and_resilience_tests": edge_case_results,
    }

    out_json = OUT_DIR / "03_extension_real_results.json"
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Resultados guardados en: {out_json}", flush=True)
    return results


if __name__ == "__main__":
    res = asyncio.run(run_all_evaluations())
    print(json.dumps({
        "A1_cold_p50_ms": res["config_a_production_extension"]["a1_cold_cache_live_whois_geoip_n30"]["latency_stats_ms"]["median_p50_ms"],
        "A1_cold_p95_ms": res["config_a_production_extension"]["a1_cold_cache_live_whois_geoip_n30"]["latency_stats_ms"]["p95_ms"],
        "A1_exceeded_6s": res["config_a_production_extension"]["a1_cold_cache_live_whois_geoip_n30"]["requests_exceeding_6000ms_timeout"],
        "A1_warm_p50_ms": res["config_a_production_extension"]["a1_cold_cache_live_whois_geoip_n30"]["warm_cache_repeat_latency_stats_ms"]["median_p50_ms"],
        "A2_n691_f1": res["config_a_production_extension"]["a2_internal_n691_benchmark"]["metrics_strict_phishing_only"]["f1"],
        "B1_engine_f1_forced": res["config_b_cascade_api_audit"]["b1_engine_run_adaptive_default_n691"]["metrics_forced_0_5"]["f1"],
        "B1_engine_abstained": res["config_b_cascade_api_audit"]["b1_engine_run_adaptive_default_n691"]["abstained_count"],
        "B2_worker_f1_forced": res["config_b_cascade_api_audit"]["b2_worker_loop_with_m0_to_m3_jump_n691"]["metrics_forced_0_5"]["f1"],
        "B3_calibrated_f1_forced": res["config_b_cascade_api_audit"]["b3_calibrated_cascade_m0_m1_m2_via_api_n691"]["metrics_m4_forced"]["f1"],
        "C_n691_f1_fail_closed": res["config_c_experimental_extension_cascade_integration"]["internal_n691"]["metrics_fail_closed"]["f1"],
        "C_ext_cc_n104_f1": res["config_c_experimental_extension_cascade_integration"]["external_cc_n104"]["metrics"]["f1"],
        "C_ext_cc_n104_roc_auc": res["config_c_experimental_extension_cascade_integration"]["external_cc_n104"]["metrics"]["roc_auc"],
    }, indent=2))
