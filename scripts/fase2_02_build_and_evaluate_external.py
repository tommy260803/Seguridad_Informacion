"""Fase II: Construcción y Evaluación de un Nuevo Conjunto de Validación Externa Independiente.

Protocolo Científico Pre-registrado:
1. Recolecta URLs desde 6 fuentes públicas independientes verificables (3 de phishing y 3 legítimas):
   - Phishing (n=600 en cohorte disjunta estricta):
     * OpenPhish Community Feed (https://openphish.com/feed.txt) — URLs completas con ruta.
     * CERT Polska / CSIRT NASK Warning List (https://hole.cert.pl/domains/v2/domains.txt) — Dominios de phishing verificados por el CSIRT nacional de Polonia.
     * Phishing Army Blocklist (https://phishing.army/download/phishing_army_blocklist.txt) — Dominios activos de phishing curados.
   - Legítimas (n=600 en cohorte disjunta estricta):
     * Majestic Million (https://downloads.majestic.com/majestic_million.csv) — Ranking por subredes de backlinks (metodología distinta a Tranco).
     * Hipo World Universities & Domains (https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json) — Portales universitarios verificados (.edu, .edu.ec, .edu.pe, .ac.uk, etc.).
     * CISA Official .gov Domains (https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv) — Portales gubernamentales oficiales de EE. UU.
2. Controla estrictamente el solapamiento con el corpus original 0.1.0 (176,201 muestras en samples.csv)
   utilizando el dominio registrado extraído con Public Suffix List (PSL).
   - Registra las muestras candidatas contaminadas (solapadas con samples.csv) por separado.
   - Construye la cohorte principal estrictamente disjunta de N=1,200 URLs (600 phishing, 600 legítimas) con 0% de solapamiento de dominio registrado con samples.csv.
3. Verifica pertenencia a Tranco Top-1M para cuantificar contaminación de listas blancas / reputación.
4. Evalúa todos los modelos congelados de nivel URL (M0_CC, M0_full, M0_ITE, M0_temporal, M0_temporal_host_unseen,
   HybridM0Model con y sin escudo Tranco) sobre las N=1,200 muestras externas.
5. Ejecuta sondeo multimodal en vivo (DNS + TLS + HTTP + HTML DOM) sobre una subcohorte estratificada
   de N_probe=240 URLs (120 phishing, 120 legítimas), registrando TODOS los intentos (Intention-to-Evaluate, N=240)
   y el subconjunto accesible (Complete-Case, N_CC), evaluando M0, M1, M2, M4_M2 (cascada 3 etapas) y M5_M2 (selectivo),
   además de medir tiempos reales de descarga HTTP GET y parseo DOM con reloj monotónico.
6. Calcula intervalos de confianza bootstrap al 95% (B=2,000, semilla=42), pruebas exactas de McNemar,
   desgloses por fuente/procedencia, pertenencia a Tranco y escenarios de prevalencia operativa (50%, 10%, 1%, 0.1%).
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

import httpx
import joblib
import numpy as np
from scipy.stats import binomtest
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_common import collect_environment_metadata
from phishguard_content.analyzer import analyze_html
from phishguard_data.psl import PublicSuffixList
from phishguard_data.reputation import get_reputation
from phishguard_data.urls import canonicalize_url
from phishguard_infra.analyzer import InfrastructureAnalyzer
from phishguard_infra.config import load_infrastructure_config
from phishguard_infra.resolver import SocketResolver
from phishguard_infra.transport import PinnedHttpTransport
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features
from phishguard_ml.detection_rules import DetectionRules, RuleResult
from phishguard_ml.evaluation import expected_calibration_error, shannon_entropy
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.hybrid_model import HybridM0Model
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features

SEED = 42
OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase2_externa"
RAW_FEEDS_DIR = OUT_DIR / "raw_feeds"


def no_op_geo(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="server_geolocation", triggered=False, confidence=0.0, reason="Offline benchmark")


def no_op_age(self: Any, hostname: str) -> RuleResult:
    return RuleResult(rule_name="domain_age", triggered=False, confidence=0.0, reason="Offline benchmark")


def ensure_additional_feeds() -> dict[str, Any]:
    RAW_FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    extra_feeds = {
        "cert_pl_domains": "https://hole.cert.pl/domains/v2/domains.txt",
        "phishing_army": "https://phishing.army/download/phishing_army_blocklist.txt",
    }
    client = httpx.Client(timeout=25.0, follow_redirects=True, headers={"User-Agent": "PhishPe-Scientific-Validator/2.0"})
    info = {}
    for name, url in extra_feeds.items():
        fpath = RAW_FEEDS_DIR / f"{name}.txt"
        if not fpath.exists():
            print(f"Downloading {name} from {url}...", flush=True)
            resp = client.get(url)
            resp.raise_for_status()
            fpath.write_bytes(resp.content)
        lines = [ln.strip() for ln in fpath.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip() and not ln.startswith("#")]
        info[name] = {
            "url": url,
            "file": str(fpath.relative_to(ROOT)),
            "records": len(lines),
            "sha256": hashlib.sha256(fpath.read_bytes()).hexdigest(),
        }
    return info


def normalize_candidate_url(raw_url_or_domain: str, psl: PublicSuffixList) -> tuple[str, str, str] | None:
    s = raw_url_or_domain.strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        s = "https://" + s
    try:
        can = canonicalize_url(s, psl=psl)
        if not can.registered_domain or "." not in can.registered_domain:
            return None
        return can.value, can.host, can.registered_domain
    except Exception:
        try:
            p = urlsplit(s)
            host = (p.hostname or "").lower().rstrip(".")
            if not host or "." not in host:
                return None
            rdom = psl.registrable_domain(host) or host
            can_val = s if p.path else (s + "/")
            return can_val, host, rdom
        except Exception:
            return None


def compute_metrics_with_ci(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float,
    *,
    y_pred_override: np.ndarray | None = None,
    n_boot: int = 2000,
    seed: int = SEED,
) -> dict[str, Any]:
    y_pred = y_pred_override if y_pred_override is not None else (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    n = len(y_true)
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
    pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
    brier = float(brier_score_loss(y_true, y_prob))
    ece = float(expected_calibration_error(y_true, y_prob, 15))

    rng = np.random.default_rng(seed)
    boot_f1, boot_rec, boot_prec, boot_roc = [], [], [], []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        yt_b = y_true[idx]
        yp_b = y_pred[idx]
        ypr_b = y_prob[idx]
        if len(np.unique(yt_b)) < 2:
            continue
        boot_f1.append(f1_score(yt_b, yp_b, zero_division=0))
        boot_rec.append(recall_score(yt_b, yp_b, zero_division=0))
        boot_prec.append(precision_score(yt_b, yp_b, zero_division=0))
        boot_roc.append(roc_auc_score(yt_b, ypr_b))

    return {
        "n": int(n),
        "threshold": round(float(threshold), 6),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1": round(f1, 6),
        "fpr": round(fpr, 6),
        "fnr": round(fnr, 6),
        "roc_auc": round(roc_auc, 6),
        "pr_auc": round(pr_auc, 6),
        "brier_score": round(brier, 6),
        "ece": round(ece, 6),
        "ci95_bootstrap": {
            "f1": [round(float(np.percentile(boot_f1, 2.5)), 6), round(float(np.percentile(boot_f1, 97.5)), 6)],
            "recall": [round(float(np.percentile(boot_rec, 2.5)), 6), round(float(np.percentile(boot_rec, 97.5)), 6)],
            "precision": [round(float(np.percentile(boot_prec, 2.5)), 6), round(float(np.percentile(boot_prec, 97.5)), 6)],
            "roc_auc": [round(float(np.percentile(boot_roc, 2.5)), 6), round(float(np.percentile(boot_roc, 97.5)), 6)],
        },
    }


def probe_single_external_url(row: dict[str, Any], psl: PublicSuffixList, base_cfg: Any) -> dict[str, Any]:
    """Perform live DNS + TLS + HTTP + HTML DOM probing with bounded timeouts."""
    sid = row["external_id"]
    url = row["canonical_url"]
    cfg = replace(base_cfg, connect_timeout_seconds=3.0, read_timeout_seconds=3.0, max_redirects=3)
    analyzer = InfrastructureAnalyzer(cfg, psl, SocketResolver(), PinnedHttpTransport(cfg))

    t0_inf = time.perf_counter()
    try:
        inf_res = analyzer.analyze(url).to_dict()
        inf_ms = (time.perf_counter() - t0_inf) * 1000.0
    except Exception as exc:
        inf_ms = (time.perf_counter() - t0_inf) * 1000.0
        inf_res = {
            "status": "error",
            "error_code": "probe_exception",
            "error_detail": str(exc)[:300],
            "features": {"infrastructure_available": 0.0},
            "total_elapsed_ms": inf_ms,
        }

    # Content probing (only attempt if DNS didn't immediately fail or attempt anyway with 3.5s timeout)
    t0_http = time.perf_counter()
    html_bytes = None
    http_err_code = None
    http_err_detail = None
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishPe-Validator/2.0",
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=3.5, context=ctx) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "html" in ctype or "text" in ctype or ctype == "":
                html_bytes = resp.read(1_000_000)
            else:
                http_err_code = "non_html_content_type"
    except urllib.error.HTTPError as he:
        http_err_code = f"http_{he.code}"
        http_err_detail = str(he)[:200]
    except urllib.error.URLError as ue:
        http_err_code = "url_error"
        http_err_detail = str(ue.reason)[:200]
    except Exception as exc:
        http_err_code = "socket_or_tls_error"
        http_err_detail = str(exc)[:200]
    http_download_ms = (time.perf_counter() - t0_http) * 1000.0

    t0_dom = time.perf_counter()
    if html_bytes:
        try:
            cnt_res = analyze_html(html_bytes, url).to_dict()
            dom_parse_ms = (time.perf_counter() - t0_dom) * 1000.0
            cnt_res["http_download_ms"] = round(http_download_ms, 3)
            cnt_res["dom_parse_ms"] = round(dom_parse_ms, 3)
        except Exception as exc:
            dom_parse_ms = (time.perf_counter() - t0_dom) * 1000.0
            cnt_res = {
                "status": "error",
                "error_code": "dom_parse_error",
                "error_detail": str(exc)[:200],
                "features": {"content_available": 0.0},
                "http_download_ms": round(http_download_ms, 3),
                "dom_parse_ms": round(dom_parse_ms, 3),
            }
    else:
        cnt_res = {
            "status": "error",
            "error_code": http_err_code or "empty_body",
            "error_detail": http_err_detail,
            "features": {"content_available": 0.0},
            "http_download_ms": round(http_download_ms, 3),
            "dom_parse_ms": 0.0,
        }

    return {
        "external_id": sid,
        "infra": inf_res,
        "content": cnt_res,
        "infra_elapsed_ms": round(inf_ms, 3),
        "http_download_ms": round(http_download_ms, 3),
        "dom_parse_ms": round(cnt_res.get("dom_parse_ms", 0.0), 3),
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    np.random.seed(SEED)

    print("=== FASE II: CONSTRUCCIÓN Y EVALUACIÓN DE COHORTE EXTERNA INDEPENDIENTE ===", flush=True)
    extra_feed_info = ensure_additional_feeds()

    psl = PublicSuffixList.from_file(ROOT / "data" / "raw" / "public_suffix_list.dat")

    # 1. Load all 176,201 existing domains and URLs from dataset 0.1.0 to enforce zero overlap
    existing_reg_domains: set[str] = set()
    existing_can_urls: set[str] = set()
    with open(ROOT / "data" / "processed" / "0.1.0" / "samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            existing_reg_domains.add(r["registered_domain"].strip().lower())
            existing_can_urls.add(r["canonical_url"].strip())

    print(f"[1] Dominios registrados en dataset 0.1.0 cargados: {len(existing_reg_domains)} dominios únicos.", flush=True)

    # 2. Parse external feeds
    # Phishing 1: OpenPhish
    openphish_lines = (RAW_FEEDS_DIR / "openphish_feed.txt").read_text(encoding="utf-8", errors="ignore").splitlines()
    # Phishing 2: CERT Polska
    certpl_lines = (RAW_FEEDS_DIR / "cert_pl_domains.txt").read_text(encoding="utf-8", errors="ignore").splitlines()
    # Phishing 3: Phishing Army
    parmy_lines = [
        ln.strip()
        for ln in (RAW_FEEDS_DIR / "phishing_army.txt").read_text(encoding="utf-8", errors="ignore").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]

    # Legitimate 1: Majestic Million (head 2500)
    majestic_domains = []
    with open(RAW_FEEDS_DIR / "majestic_million_head2500.csv", encoding="utf-8", errors="ignore") as f:
        for r in csv.DictReader(f):
            d = (r.get("Domain") or "").strip()
            if d:
                majestic_domains.append(d)

    # Legitimate 2: Hipo World Universities
    hipo_data = json.loads((RAW_FEEDS_DIR / "hipo_universities.json").read_text(encoding="utf-8", errors="ignore"))
    hipo_urls = []
    # Prioritize diverse countries including Ecuador, Peru, Colombia, Mexico, Chile, Spain, US, UK, Germany, Japan, Brazil
    priority_alpha2 = {"EC", "PE", "CO", "MX", "CL", "AR", "BR", "ES", "US", "GB", "DE", "FR", "JP", "CA", "AU", "IT"}
    hipo_priority = []
    hipo_other = []
    for entry in hipo_data:
        cc = (entry.get("alpha_two_code") or "").upper()
        wpages = entry.get("web_pages") or []
        if wpages:
            u = wpages[0].strip()
            if cc in priority_alpha2:
                hipo_priority.append((u, cc))
            else:
                hipo_other.append((u, cc))
    rng.shuffle(hipo_priority)
    rng.shuffle(hipo_other)
    hipo_urls = [u for u, _ in (hipo_priority + hipo_other)]

    # Legitimate 3: CISA .gov official domains
    cisa_domains = []
    with open(RAW_FEEDS_DIR / "cisa_dotgov.csv", encoding="utf-8", errors="ignore") as f:
        for r in csv.DictReader(f):
            d = (r.get("Domain name") or "").strip().lower()
            if d:
                cisa_domains.append(d)
    rng.shuffle(cisa_domains)

    # Shuffle phishing domain lists with fixed seed
    rng.shuffle(certpl_lines)
    rng.shuffle(parmy_lines)

    # Helper to select disjoint + track contaminated candidates
    seen_ext_domains: set[str] = set()
    contaminated_candidates: list[dict[str, Any]] = []
    disjoint_samples: list[dict[str, Any]] = []
    source_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"examined": 0, "invalid": 0, "duplicate_in_ext": 0, "contaminated_with_0_1_0": 0, "selected_disjoint": 0})

    def collect_from_source(raw_items: list[str], source_name: str, label: str, target_count: int) -> None:
        for item in raw_items:
            if source_stats[source_name]["selected_disjoint"] >= target_count:
                break
            source_stats[source_name]["examined"] += 1
            norm = normalize_candidate_url(item, psl)
            if norm is None:
                source_stats[source_name]["invalid"] += 1
                continue
            can_url, host, rdom = norm
            if rdom in seen_ext_domains:
                source_stats[source_name]["duplicate_in_ext"] += 1
                continue
            rep = get_reputation(can_url, psl=psl)
            in_tranco = rep["tranco_rank"] is not None
            tranco_rank = rep["tranco_rank"]

            rec = {
                "raw_input": item,
                "canonical_url": can_url,
                "host": host,
                "registered_domain": rdom,
                "tld": rdom.split(".")[-1] if "." in rdom else "",
                "label": label,
                "label_int": 1 if label == "phishing" else 0,
                "source": source_name,
                "in_tranco_top1m": bool(in_tranco),
                "tranco_rank": tranco_rank,
                "has_nonroot_path": len(urlsplit(can_url).path.strip("/")) > 0,
            }
            if rdom in existing_reg_domains or can_url in existing_can_urls:
                source_stats[source_name]["contaminated_with_0_1_0"] += 1
                if len(contaminated_candidates) < 300:
                    contaminated_candidates.append(rec)
                continue

            seen_ext_domains.add(rdom)
            source_stats[source_name]["selected_disjoint"] += 1
            rec["external_id"] = hashlib.sha256(f"ext_v2:{source_name}:{can_url}".encode("utf-8")).hexdigest()[:24]
            disjoint_samples.append(rec)

    # Collect Phishing: OpenPhish (up to 220 unique unseen domains), CERT.PL (190), Phishing Army (190) -> Total = 600 phishing
    collect_from_source(openphish_lines, "openphish", "phishing", 220)
    rem_phish = 600 - len([x for x in disjoint_samples if x["label"] == "phishing"])
    half_rem = rem_phish // 2
    collect_from_source(certpl_lines, "cert_pl", "phishing", half_rem)
    collect_from_source(parmy_lines, "phishing_army", "phishing", 600 - len([x for x in disjoint_samples if x["label"] == "phishing"]))

    # Collect Legitimate: Majestic Million (200 unseen domains), Hipo Universities (200 unseen), CISA .gov (200 unseen) -> Total = 600 legitimate
    collect_from_source(majestic_domains, "majestic_million", "legitimate", 200)
    collect_from_source(hipo_urls, "hipo_universities", "legitimate", 200)
    collect_from_source(cisa_domains, "cisa_dotgov", "legitimate", 200)

    print(
        f"[2] Cohorte externa disjunta construida: N={len(disjoint_samples)} "
        f"(Phishing={sum(1 for x in disjoint_samples if x['label']=='phishing')}, "
        f"Legitimate={sum(1 for x in disjoint_samples if x['label']=='legitimate')}). "
        f"Candidatas contaminadas con 0.1.0 detectadas y separadas: {sum(v['contaminated_with_0_1_0'] for v in source_stats.values())}",
        flush=True,
    )

    # Save external dataset CSV
    ext_csv_path = OUT_DIR / "external_validation_dataset_n1200.csv"
    fieldnames = [
        "external_id",
        "canonical_url",
        "host",
        "registered_domain",
        "tld",
        "label",
        "label_int",
        "source",
        "in_tranco_top1m",
        "tranco_rank",
        "has_nonroot_path",
    ]
    with open(ext_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for r in disjoint_samples:
            writer.writerow({k: r[k] for k in fieldnames})

    # 3. Extract URL features for all N=1,200 disjoint samples and evaluate all frozen URL-level models
    X_m0_ext = np.array(
        [
            [extract_url_features(UrlFeatureContext(r["canonical_url"], r["registered_domain"]))[k] for k in AUTHORITY_FEATURE_NAMES]
            for r in disjoint_samples
        ],
        dtype=np.float64,
    )
    y_ext = np.array([r["label_int"] for r in disjoint_samples], dtype=int)

    frozen_url_models = {
        "M0_CC_host_unseen": ("artifacts/m0-real/model.joblib", 0.38266699053469533),
        "M0_full_host_unseen": ("artifacts/url-baseline-0.2.0/model.joblib", 0.43393651111753984),
        "M0_ITE_host_unseen": ("artifacts/m0-ite-real/model.joblib", 0.4127080220219859),
        "M0_temporal": ("artifacts/m0-temporal/model.joblib", 0.2742245037279183),
        "M0_temporal_host_unseen": ("artifacts/m0-temporal-host-unseen/model.joblib", 0.25698010597103543),
    }

    url_models_results: dict[str, Any] = {}
    ext_probs_by_model: dict[str, np.ndarray] = {}

    for mname, (mrel, tau_sel) in frozen_url_models.items():
        mobj = joblib.load(ROOT / mrel)
        clf = mobj["model"] if isinstance(mobj, dict) else mobj
        probs = clf.predict_proba(X_m0_ext)[:, 1]
        ext_probs_by_model[mname] = probs
        url_models_results[mname] = {
            "artifact": mrel,
            "selected_threshold_eval": compute_metrics_with_ci(y_ext, probs, tau_sel),
            "fixed_0_5_eval": compute_metrics_with_ci(y_ext, probs, 0.50),
        }

    # Evaluate HybridM0Model (Extension model) with and without Tranco shield on all N=1,200 external URLs
    print("[3] Evaluando HybridM0Model (con y sin escudo Tranco) sobre N=1,200 muestras externas...", flush=True)
    hybrid = HybridM0Model()
    probs_hyb_tranco = []
    with (
        patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
        patch.object(DetectionRules, "_check_domain_age", no_op_age),
    ):
        for r in disjoint_samples:
            res = hybrid.predict(r["canonical_url"], user_country="EC")
            probs_hyb_tranco.append(float(res["probability"]))
    probs_hyb_tranco_arr = np.array(probs_hyb_tranco, dtype=float)
    ext_probs_by_model["HybridM0_with_Tranco"] = probs_hyb_tranco_arr
    url_models_results["HybridM0_with_Tranco"] = {
        "artifact": "src/phishguard_ml/hybrid_model.py (with Tranco Top-1M shield)",
        "fixed_0_5_eval": compute_metrics_with_ci(y_ext, probs_hyb_tranco_arr, 0.50),
    }

    from phishguard_data import reputation as rep_mod
    orig_get_rep = rep_mod.get_reputation

    def neutral_reputation(url: str, psl: Any = None) -> dict[str, Any]:
        base = orig_get_rep(url, psl=psl)
        base["tranco_rank"] = None
        base["trust_score"] = 0.0
        return base

    probs_hyb_notranco = []
    with (
        patch("phishguard_ml.hybrid_model.get_reputation", side_effect=neutral_reputation),
        patch.object(DetectionRules, "_check_server_geolocation", no_op_geo),
        patch.object(DetectionRules, "_check_domain_age", no_op_age),
    ):
        for r in disjoint_samples:
            res = hybrid.predict(r["canonical_url"], user_country="EC")
            probs_hyb_notranco.append(float(res["probability"]))
    probs_hyb_notranco_arr = np.array(probs_hyb_notranco, dtype=float)
    ext_probs_by_model["HybridM0_without_Tranco"] = probs_hyb_notranco_arr
    url_models_results["HybridM0_without_Tranco"] = {
        "artifact": "src/phishguard_ml/hybrid_model.py (Tranco shield disabled)",
        "fixed_0_5_eval": compute_metrics_with_ci(y_ext, probs_hyb_notranco_arr, 0.50),
        "threshold_0_35_eval": compute_metrics_with_ci(y_ext, probs_hyb_notranco_arr, 0.35),
    }

    # 4. Breakdown by source (Provenance analysis) & Tranco membership
    by_source_breakdown: dict[str, Any] = {}
    for src_name in ("openphish", "cert_pl", "phishing_army", "majestic_million", "hipo_universities", "cisa_dotgov"):
        mask = np.array([r["source"] == src_name for r in disjoint_samples], dtype=bool)
        if not mask.any():
            continue
        lbl = disjoint_samples[int(np.where(mask)[0][0])]["label"]
        in_tr_rate = float(np.mean([disjoint_samples[i]["in_tranco_top1m"] for i in np.where(mask)[0]]))
        nonroot_rate = float(np.mean([disjoint_samples[i]["has_nonroot_path"] for i in np.where(mask)[0]]))
        src_entry: dict[str, Any] = {
            "n": int(mask.sum()),
            "true_class": lbl,
            "in_tranco_top1m_rate": round(in_tr_rate, 4),
            "has_nonroot_path_rate": round(nonroot_rate, 4),
            "models_accuracy_or_recall": {},
        }
        for mname, probs in ext_probs_by_model.items():
            tau = frozen_url_models.get(mname, ("", 0.50))[1]
            preds = (probs[mask] >= tau).astype(int)
            correct_rate = float((preds == y_ext[mask]).mean())
            src_entry["models_accuracy_or_recall"][mname] = {
                "threshold": round(float(tau), 4),
                "correct_rate": round(correct_rate, 6),
                "error_rate": round(1.0 - correct_rate, 6),
                "mean_predicted_prob": round(float(probs[mask].mean()), 6),
            }
        by_source_breakdown[src_name] = src_entry

    # Breakdown of legitimate samples by Tranco membership (in_tranco vs not_in_tranco)
    legit_in_tranco = np.array([r["label"] == "legitimate" and r["in_tranco_top1m"] for r in disjoint_samples], dtype=bool)
    legit_not_tranco = np.array([r["label"] == "legitimate" and not r["in_tranco_top1m"] for r in disjoint_samples], dtype=bool)
    tranco_contamination_analysis = {
        "legitimate_in_tranco_count": int(legit_in_tranco.sum()),
        "legitimate_outside_tranco_count": int(legit_not_tranco.sum()),
        "phishing_in_tranco_count": int(sum(1 for r in disjoint_samples if r["label"] == "phishing" and r["in_tranco_top1m"])),
        "fpr_by_tranco_membership": {},
    }
    for mname, probs in ext_probs_by_model.items():
        tau = frozen_url_models.get(mname, ("", 0.50))[1]
        fpr_in = float((probs[legit_in_tranco] >= tau).mean()) if legit_in_tranco.any() else 0.0
        fpr_out = float((probs[legit_not_tranco] >= tau).mean()) if legit_not_tranco.any() else 0.0
        tranco_contamination_analysis["fpr_by_tranco_membership"][mname] = {
            "fpr_when_in_tranco": round(fpr_in, 6),
            "fpr_when_outside_tranco": round(fpr_out, 6),
        }

    # 5. Live Multimodal Probing (DNS + TLS + HTTP + HTML DOM) on Stratified Subcohort N_probe = 240
    # 40 per source * 6 sources = 240 (120 phishing, 120 legitimate)
    probe_samples = []
    for src_name in ("openphish", "cert_pl", "phishing_army", "majestic_million", "hipo_universities", "cisa_dotgov"):
        src_rows = [r for r in disjoint_samples if r["source"] == src_name]
        probe_samples.extend(src_rows[:40])

    print(f"[4] Ejecutando sondeo multimodal en vivo (DNS/TLS/HTTP/DOM) sobre N_probe={len(probe_samples)} URLs externas...", flush=True)
    base_cfg = load_infrastructure_config(ROOT / "configs" / "infrastructure-analyzer.json")
    probe_results_map: dict[str, dict[str, Any]] = {}
    t0_probe_all = time.perf_counter()
    with ThreadPoolExecutor(max_workers=32) as pool:
        futs = {pool.submit(probe_single_external_url, r, psl, base_cfg): r["external_id"] for r in probe_samples}
        done_cnt = 0
        for fut in as_completed(futs):
            res = fut.result()
            probe_results_map[res["external_id"]] = res
            done_cnt += 1
            if done_cnt % 40 == 0 or done_cnt == len(probe_samples):
                print(f"  Sondeadas {done_cnt}/{len(probe_samples)} URLs ({time.perf_counter()-t0_probe_all:.1f}s)...", flush=True)

    # Save raw live probe results JSONL
    probe_jsonl_path = OUT_DIR / "external_multimodal_probe_n240.jsonl"
    with open(probe_jsonl_path, "w", encoding="utf-8") as f:
        for r in probe_samples:
            sid = r["external_id"]
            f.write(json.dumps({"sample": r, "probe": probe_results_map[sid]}, ensure_ascii=False) + "\n")

    # Evaluate External ITE (all N=240 probed URLs) and External Complete-Case (where both infra & content succeeded)
    m0_ite_obj = joblib.load(ROOT / "artifacts" / "m0-ite-real" / "model.joblib")
    m1_ite_obj = joblib.load(ROOT / "artifacts" / "m1-ite-real" / "model.joblib")
    m2_ite_obj = joblib.load(ROOT / "artifacts" / "m2-ite-real" / "model.joblib")
    m0_cc_obj = joblib.load(ROOT / "artifacts" / "m0-real" / "model.joblib")
    m1_cc_obj = joblib.load(ROOT / "artifacts" / "m1-real" / "model.joblib")
    m2_cc_obj = joblib.load(ROOT / "artifacts" / "m2-real" / "model.joblib")

    X_m0_probe, X_m1_probe, X_m2_probe = [], [], []
    y_probe = []
    cc_mask_list = []
    infra_status_counter = Counter()
    content_status_counter = Counter()
    http_download_lats = []
    dom_parse_lats = []
    infra_lats = []

    for r in probe_samples:
        sid = r["external_id"]
        pr = probe_results_map[sid]
        inf_r = pr["infra"]
        cnt_r = pr["content"]

        inf_ok = inf_r.get("status") == "success"
        cnt_ok = cnt_r.get("status") == "success"
        infra_status_counter[f"{r['label']}:{inf_r.get('status')}:{inf_r.get('error_code')}"] += 1
        content_status_counter[f"{r['label']}:{cnt_r.get('status')}:{cnt_r.get('error_code')}"] += 1

        infra_lats.append(pr["infra_elapsed_ms"])
        http_download_lats.append(pr["http_download_ms"])
        if cnt_ok:
            dom_parse_lats.append(pr["dom_parse_ms"])

        uf = extract_url_features(UrlFeatureContext(r["canonical_url"], r["registered_domain"]))
        inf_f = extract_infrastructure_features(inf_r)
        cnt_f = extract_content_features(cnt_r)

        v0 = [uf[k] for k in AUTHORITY_FEATURE_NAMES]
        v1 = v0 + [inf_f[k] for k in INFRA_FEATURE_NAMES]
        v2 = v1 + [cnt_f[k] for k in CONTENT_FEATURE_NAMES]

        X_m0_probe.append(v0)
        X_m1_probe.append(v1)
        X_m2_probe.append(v2)
        y_probe.append(r["label_int"])
        cc_mask_list.append(bool(inf_ok and cnt_ok))

    X_m0_p = np.array(X_m0_probe, dtype=np.float64)
    X_m1_p = np.array(X_m1_probe, dtype=np.float64)
    X_m2_p = np.array(X_m2_probe, dtype=np.float64)
    y_p = np.array(y_probe, dtype=int)
    cc_mask = np.array(cc_mask_list, dtype=bool)

    # ITE Evaluation (N=240)
    p_m0_ite = m0_ite_obj["model"].predict_proba(X_m0_p)[:, 1]
    p_m1_ite = m1_ite_obj["model"].predict_proba(X_m1_p)[:, 1]
    p_m2_ite = m2_ite_obj["model"].predict_proba(X_m2_p)[:, 1]

    external_ite_eval = {
        "n_total": int(len(y_p)),
        "n_phishing": int(y_p.sum()),
        "n_legitimate": int((1 - y_p).sum()),
        "infra_availability_rate_overall": round(float(np.mean([probe_results_map[r["external_id"]]["infra"].get("status") == "success" for r in probe_samples])), 4),
        "content_availability_rate_overall": round(float(np.mean([probe_results_map[r["external_id"]]["content"].get("status") == "success" for r in probe_samples])), 4),
        "complete_case_rate_overall": round(float(cc_mask.mean()), 4),
        "complete_case_phishing": int(y_p[cc_mask].sum()),
        "complete_case_legitimate": int((1 - y_p[cc_mask]).sum()),
        "infra_status_breakdown": dict(infra_status_counter),
        "content_status_breakdown": dict(content_status_counter),
        "models_ite_n240": {
            "M0_ITE": compute_metrics_with_ci(y_p, p_m0_ite, float(m0_ite_obj["selected_threshold"])),
            "M1_ITE": compute_metrics_with_ci(y_p, p_m1_ite, float(m1_ite_obj["selected_threshold"])),
            "M2_ITE": compute_metrics_with_ci(y_p, p_m2_ite, float(m2_ite_obj["selected_threshold"])),
        },
    }

    # Complete-Case Evaluation (on accessible subset cc_mask)
    external_cc_eval: dict[str, Any] = {"n_cc": int(cc_mask.sum())}
    if cc_mask.sum() >= 10 and len(np.unique(y_p[cc_mask])) == 2:
        y_cc = y_p[cc_mask]
        p_m0_cc = m0_cc_obj["model"].predict_proba(X_m0_p[cc_mask])[:, 1]
        p_m1_cc = m1_cc_obj["model"].predict_proba(X_m1_p[cc_mask])[:, 1]
        p_m2_cc = m2_cc_obj["model"].predict_proba(X_m2_p[cc_mask])[:, 1]

        tau0 = float(m0_cc_obj["selected_threshold"])
        tau1 = float(m1_cc_obj["selected_threshold"])
        tau2 = float(m2_cc_obj["selected_threshold"])

        # 3-stage cascade M0 -> M1 -> M2 with original parameter H_esc = 0.15, H_abs = 0.50
        n_c = len(y_cc)
        cas_prob = np.zeros(n_c, dtype=float)
        cas_pred = np.zeros(n_c, dtype=int)
        cas_abst = np.zeros(n_c, dtype=bool)
        cas_stage = np.zeros(n_c, dtype=int)
        for i in range(n_c):
            probs_i = [float(p_m0_cc[i]), float(p_m1_cc[i]), float(p_m2_cc[i])]
            taus_i = [tau0, tau1, tau2]
            chosen_k = 0
            for k in range(3):
                chosen_k = k
                if k < 2:
                    hk = float(shannon_entropy(np.array([probs_i[k]]))[0])
                    if hk <= 0.15:
                        break
            cas_stage[i] = chosen_k
            cas_prob[i] = probs_i[chosen_k]
            cas_pred[i] = 1 if probs_i[chosen_k] >= taus_i[chosen_k] else 0
            if float(shannon_entropy(np.array([cas_prob[i]]))[0]) > 0.50:
                cas_abst[i] = True

        dec_mask = ~cas_abst
        external_cc_eval.update(
            {
                "n_phishing": int(y_cc.sum()),
                "n_legitimate": int((1 - y_cc).sum()),
                "M0_CC": compute_metrics_with_ci(y_cc, p_m0_cc, tau0),
                "M1_CC": compute_metrics_with_ci(y_cc, p_m1_cc, tau1),
                "M2_CC": compute_metrics_with_ci(y_cc, p_m2_cc, tau2),
                "M4_M2_cascade_forced": compute_metrics_with_ci(y_cc, cas_prob, tau2, y_pred_override=cas_pred),
                "M5_M2_cascade_selective": {
                    "coverage": round(float(dec_mask.mean()), 6),
                    "abstained_count": int(cas_abst.sum()),
                    "abstained_phishing": int(y_cc[cas_abst].sum()),
                    "abstained_legitimate": int((1 - y_cc[cas_abst]).sum()),
                    "metrics_on_decided": compute_metrics_with_ci(
                        y_cc[dec_mask], cas_prob[dec_mask], tau2, y_pred_override=cas_pred[dec_mask]
                    )
                    if dec_mask.any() and len(np.unique(y_cc[dec_mask])) == 2
                    else {},
                },
                "cascade_stopping_stages": {
                    "M0": int((cas_stage == 0).sum()),
                    "M1": int((cas_stage == 1).sum()),
                    "M2": int((cas_stage == 2).sum()),
                    "avg_modalities": round(float((cas_stage + 1).mean()), 4),
                },
                "measured_live_latencies_ms": {
                    "infra_dns_tls_http_p50_ms": round(float(np.percentile(infra_lats, 50)), 2),
                    "infra_dns_tls_http_p95_ms": round(float(np.percentile(infra_lats, 95)), 2),
                    "content_http_get_download_p50_ms": round(float(np.percentile(http_download_lats, 50)), 2),
                    "content_http_get_download_p95_ms": round(float(np.percentile(http_download_lats, 95)), 2),
                    "content_html_dom_parse_p50_ms": round(float(np.percentile(dom_parse_lats, 50)), 2) if dom_parse_lats else 0.0,
                    "content_html_dom_parse_p95_ms": round(float(np.percentile(dom_parse_lats, 95)), 2) if dom_parse_lats else 0.0,
                },
            }
        )

    # 6. Operational Prevalence Projections (50%, 10%, 1%, 0.1% phishing)
    # Using Bayes formula from observed sensitivity (Recall) and FPR on external cohort
    prevalence_scenarios: dict[str, Any] = {}
    for mname in ("M0_full_host_unseen", "HybridM0_with_Tranco", "HybridM0_without_Tranco"):
        met = url_models_results[mname].get("selected_threshold_eval") or url_models_results[mname]["fixed_0_5_eval"]
        sens = met["recall"]
        fpr_v = met["fpr"]
        prevalence_scenarios[mname] = {}
        for prev in (0.50, 0.10, 0.01, 0.001):
            # P(y=1 | y_hat=1) = (sens * prev) / (sens * prev + fpr * (1 - prev))
            denom = sens * prev + fpr_v * (1.0 - prev)
            ppv = (sens * prev) / denom if denom > 0 else 0.0
            f1_prev = (2 * ppv * sens) / (ppv + sens) if (ppv + sens) > 0 else 0.0
            fp_per_10k = fpr_v * (1.0 - prev) * 10000.0
            fn_per_10k = (1.0 - sens) * prev * 10000.0
            prevalence_scenarios[mname][f"pi_{prev}"] = {
                "prevalence": prev,
                "precision_ppv": round(ppv, 6),
                "recall_tpr": round(sens, 6),
                "f1_projected": round(f1_prev, 6),
                "expected_fp_per_10k_urls": round(fp_per_10k, 2),
                "expected_fn_per_10k_urls": round(fn_per_10k, 2),
            }

    # Save complete external predictions CSV for N=1,200
    pred_csv_path = OUT_DIR / "external_predictions_n1200.csv"
    with open(pred_csv_path, "w", encoding="utf-8", newline="") as f:
        pfields = [
            "external_id",
            "canonical_url",
            "registered_domain",
            "source",
            "label",
            "label_int",
            "in_tranco_top1m",
            "prob_M0_CC",
            "prob_M0_full",
            "prob_M0_ITE",
            "prob_M0_temporal",
            "prob_HybridM0_with_Tranco",
            "prob_HybridM0_without_Tranco",
        ]
        writer = csv.DictWriter(f, fieldnames=pfields, lineterminator="\n")
        writer.writeheader()
        for i, r in enumerate(disjoint_samples):
            writer.writerow(
                {
                    "external_id": r["external_id"],
                    "canonical_url": r["canonical_url"],
                    "registered_domain": r["registered_domain"],
                    "source": r["source"],
                    "label": r["label"],
                    "label_int": r["label_int"],
                    "in_tranco_top1m": int(r["in_tranco_top1m"]),
                    "prob_M0_CC": round(float(ext_probs_by_model["M0_CC_host_unseen"][i]), 6),
                    "prob_M0_full": round(float(ext_probs_by_model["M0_full_host_unseen"][i]), 6),
                    "prob_M0_ITE": round(float(ext_probs_by_model["M0_ITE_host_unseen"][i]), 6),
                    "prob_M0_temporal": round(float(ext_probs_by_model["M0_temporal"][i]), 6),
                    "prob_HybridM0_with_Tranco": round(float(ext_probs_by_model["HybridM0_with_Tranco"][i]), 6),
                    "prob_HybridM0_without_Tranco": round(float(ext_probs_by_model["HybridM0_without_Tranco"][i]), 6),
                }
            )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "seed": SEED,
        "environment": collect_environment_metadata(),
        "sample_size_justification": {
            "confirmatory_formula": "n >= z_{0.975}^2 * p * (1 - p) / e^2",
            "assumed_metric_p": 0.85,
            "target_half_width_e": 0.035,
            "min_required_per_class": 400,
            "achieved_per_class": 600,
            "achieved_total_disjoint": len(disjoint_samples),
        },
        "provenance_and_filtering_stats": dict(source_stats),
        "extra_feeds_manifest": extra_feed_info,
        "dataset_sha256": hashlib.sha256(ext_csv_path.read_bytes()).hexdigest(),
        "predictions_sha256": hashlib.sha256(pred_csv_path.read_bytes()).hexdigest(),
        "url_models_evaluation_n1200": url_models_results,
        "by_source_breakdown": by_source_breakdown,
        "tranco_contamination_analysis": tranco_contamination_analysis,
        "live_multimodal_probe_n240": {
            "ite_evaluation_n240": external_ite_eval,
            "complete_case_evaluation": external_cc_eval,
        },
        "operational_prevalence_projections": prevalence_scenarios,
    }

    out_json = OUT_DIR / "02_validacion_externa_results.json"
    out_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"=== FASE II COMPLETADA Y GUARDADA EN {out_json} ===", flush=True)


if __name__ == "__main__":
    main()
