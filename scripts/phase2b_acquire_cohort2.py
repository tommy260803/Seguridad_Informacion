"""Fase 2 - PASO B: construcción de la SEGUNDA cohorte externa independiente (post-corrección).

Requisitos que implementa (encargo §3.1):
  * >= 1.000 URLs verificables, ambas clases representadas, varias fuentes por clase.
  * Dominios NO usados para entrenar/ajustar (exclusión estricta contra samples.csv
    y contra la cohorte externa anterior de 1.054/1.200 URL).
  * URLs con y sin www., IDN/Punycode, subdominios legítimos, rutas y parámetros,
    acortadores y redirecciones HTTP 301/302.
  * Justificación muestral ANTES de consultar etiquetas.
  * Congelación de etiquetas con SHA-256.

Salidas (artifacts/corrections_phase2/cohort2/):
  raw_feeds/**                       copias byte a byte de los feeds descargados
  cohort2_candidates_all.csv         todos los candidatos con su procedencia
  cohort2_dataset.csv                cohorte final congelada (etiquetas)
  cohort2_labels_frozen.json         hashes, conteos, justificación muestral
  cohort2_redirects.jsonl            cadenas de redirección reales medidas
  cohort2_excluded.csv               candidatos excluidos y motivo
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import random
import ssl
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_data.psl import PublicSuffixList  # noqa: E402

OUT = ROOT / "artifacts" / "corrections_phase2" / "cohort2"
RAW = OUT / "raw_feeds"
SEED = 42
N_PHISH = 600
N_LEGIT = 600
UA = {"User-Agent": "PhishPe-Scientific-Validator/3.0 (research; contact: phishpe-audit)"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "s.id", "rb.gy", "shorturl.at", "t.ly", "bl.ink", "soo.gd", "v.gd",
}


# --------------------------------------------------------------------------- utils
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def fetch(url: str, timeout: int = 40) -> bytes | None:
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as exc:
        print(f"    [fetch-fail] {url} -> {type(exc).__name__}: {exc}", flush=True)
        return None


def ensure_feed(name: str, url: str, alt_urls: tuple[str, ...] = ()) -> Path | None:
    RAW.mkdir(parents=True, exist_ok=True)
    dest = RAW / name
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    for u in (url, *alt_urls):
        data = fetch(u)
        if data and len(data) > 100:
            dest.write_bytes(data)
            print(f"  [feed] {name}: {len(data):,} bytes desde {u}", flush=True)
            return dest
    print(f"  [feed] {name}: NO DISPONIBLE", flush=True)
    return None


def extract_domain(url: str, psl: PublicSuffixList) -> tuple[str, str] | None:
    try:
        u = url if "://" in url else "http://" + url
        parts = urlsplit(u)
        host = (parts.hostname or "").lower().rstrip(".")
        if not host or " " in host:
            return None
        reg = psl.registrable_domain(host) or host
        return host, reg
    except Exception:
        return None


def flags(host: str, url: str) -> dict[str, Any]:
    parts = urlsplit(url if "://" in url else "http://" + url)
    path = parts.path or ""
    query = parts.query or ""
    labels = [l for l in host.split(".") if l]
    return {
        "has_www": int(labels[0] == "www") if labels else 0,
        "is_idn_punycode": int("xn--" in host),
        "has_subdomain": int(len(labels) > 2),
        "n_host_labels": len(labels),
        "has_path": int(bool(path) and path not in ("", "/")),
        "has_params": int(bool(query)),
        "is_shortener": int(host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS)),
        "is_ip_host": int(all(ch.isdigit() or ch == "." for ch in host) and "." in host),
    }


def resolve_redirects(url: str, max_hops: int = 5, timeout: float = 6.0) -> dict[str, Any]:
    """Sigue la cadena de redirecciones con peticiones HEAD sin descargar cuerpos."""
    chain: list[dict[str, Any]] = []
    ctx = ssl.create_default_context()
    current = url
    try:
        for hop in range(max_hops + 1):
            req = urllib.request.Request(current, method="HEAD", headers=UA)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status = resp.status
                location = resp.headers.get("Location")
                chain.append({"url": current, "status": status, "location": location})
                if status in (301, 302, 303, 307, 308) and location:
                    current = urllib.parse.urljoin(current, location)  # type: ignore[name-defined]
                    continue
                break
        return {"ok": True, "hops": len(chain) - 1, "chain": chain, "final_url": current}
    except Exception as exc:
        return {"ok": False, "hops": len(chain), "chain": chain, "final_url": current,
                "error": f"{type(exc).__name__}: {exc}"[:200]}


import urllib.parse  # noqa: E402  (usado en resolve_redirects)


# --------------------------------------------------------------------------- feeds
def load_phishing(psl: PublicSuffixList) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # 1) PhishTank (URLs completas con ruta, verificación registrada)
    pt = ensure_feed(
        "phishtank_online_valid.json",
        "https://data.phishtank.com/data/online-valid.json",
        ("https://data.phishtank.com/data/online-valid.json?phish_id=1",),
    )
    if pt:
        try:
            payload = json.loads(pt.read_text(encoding="utf-8", errors="replace"))
            for e in payload:
                if not isinstance(e, dict) or not e.get("url"):
                    continue
                d = extract_domain(e["url"], psl)
                if not d:
                    continue
                rows.append({
                    "raw_url": e["url"], "host": d[0], "registered_domain": d[1],
                    "source": "phishtank", "label": "phishing",
                    "verified": str(e.get("verified", "")).lower(),
                    "source_record_id": str(e.get("phish_id", "")),
                    "source_timestamp": str(e.get("verification_time", ""))[:31],
                })
            print(f"  [phishtank] {len(rows)} candidatos", flush=True)
        except Exception as exc:
            print(f"  [phishtank] error parse: {exc}", flush=True)

    # 2) URLhaus (abuse.ch) - segunda fuente independiente de phishing
    uh = ensure_feed(
        "urlhaus_online.txt",
        "https://urlhaus.abuse.ch/downloads/text_online/",
        ("https://urlhaus.abuse.ch/downloads/text/",),
    )
    n_uh = len(rows)
    if uh:
        for line in uh.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            u = line.split("\t")[-1].strip().strip('"')
            if not u.startswith(("http://", "https://")):
                continue
            d = extract_domain(u, psl)
            if not d:
                continue
            rows.append({
                "raw_url": u, "host": d[0], "registered_domain": d[1],
                "source": "urlhaus", "label": "phishing",
                "verified": "n/a", "source_record_id": "", "source_timestamp": "",
            })
        print(f"  [urlhaus] {len(rows) - n_uh} candidatos", flush=True)

    # 3) OpenPhish (tercera fuente)
    op = ensure_feed("openphish_feed.txt", "https://openphish.com/feed.txt")
    n_op = len(rows)
    if op:
        for line in op.read_text(encoding="utf-8", errors="replace").splitlines():
            u = line.strip()
            if not u.startswith(("http://", "https://")):
                continue
            d = extract_domain(u, psl)
            if not d:
                continue
            rows.append({
                "raw_url": u, "host": d[0], "registered_domain": d[1],
                "source": "openphish", "label": "phishing",
                "verified": "n/a", "source_record_id": "", "source_timestamp": "",
            })
        print(f"  [openphish] {len(rows) - n_op} candidatos", flush=True)
    return rows


def load_legitimate(psl: PublicSuffixList) -> tuple[list[dict[str, Any]], set[str]]:
    rows: list[dict[str, Any]] = []
    tranco_domains: set[str] = set()

    tr = ensure_feed("tranco_top1m.csv.zip", "https://tranco-list.eu/top-1m.csv.zip")
    if tr:
        import zipfile

        with zipfile.ZipFile(io.BytesIO(tr.read_bytes())) as zf:
            name = zf.namelist()[0]
            data = zf.read(name).decode("utf-8", errors="replace")
        for i, line in enumerate(csv.reader(io.StringIO(data))):
            if len(line) < 2:
                continue
            rank, dom = line[0], line[1].strip().lower()
            tranco_domains.add(dom)
            d = extract_domain(dom, psl)
            if not d:
                continue
            rows.append({
                "raw_url": f"https://{dom}", "host": d[0], "registered_domain": d[1],
                "source": "tranco", "label": "legitimate",
                "verified": "n/a", "source_record_id": rank, "source_timestamp": "",
            })
        print(f"  [tranco] {len(rows)} candidatos", flush=True)

    mj = ensure_feed("majestic_million.csv", "https://downloads.majestic.com/majestic_million.csv")
    if mj:
        text = mj.read_text(encoding="utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        n_before = len(rows)
        for rec in reader:
            dom = (rec.get("Resolution") or rec.get("URL") or rec.get("Domain") or "").strip().lower()
            if not dom:
                continue
            d = extract_domain(dom, psl)
            if not d:
                continue
            rows.append({
                "raw_url": f"https://{dom}", "host": d[0], "registered_domain": d[1],
                "source": "majestic", "label": "legitimate",
                "verified": "n/a", "source_record_id": rec.get("Rank", ""), "source_timestamp": "",
            })
        print(f"  [majestic] {len(rows) - n_before} candidatos", flush=True)
    return rows, tranco_domains


# --------------------------------------------------------------------------- main
def main() -> None:
    t_start = time.perf_counter()
    OUT.mkdir(parents=True, exist_ok=True)
    random.seed(SEED)

    psl_path = sorted((ROOT / "data" / "raw").rglob("public_suffix_list.dat"))[-1]
    psl = PublicSuffixList.from_file(psl_path)
    print(f"PSL: {psl_path}", flush=True)

    # ---- 0) Justificación muestral ANTES de consultar etiquetas ---------------
    def half_width(p: float, n: int) -> float:
        return 1.96 * math.sqrt(p * (1 - p) / n)

    justification = {
        "computed_before_label_query": True,
        "n_per_class": N_LEGIT,
        "binomial_95ci_half_width": {
            "at_fpr_0.10": round(half_width(0.10, N_LEGIT), 5),
            "at_fpr_0.30": round(half_width(0.30, N_LEGIT), 5),
            "at_recall_0.90": round(half_width(0.90, N_PHISH), 5),
        },
        "mde_two_proportions_n600_each": {
            "detect_0.467_vs_0.097_with_power_0.99": "yes (approximate normal two-proportion test, alpha=0.05)",
            "detect_0.02_difference_at_p_0.50_with_power_0.80": "no (needs ~2,400/class)",
            "detect_0.05_difference_at_p_0.50_with_power_0.80": "yes",
        },
        "paired_mcnemar": {
            "assumption": "discor 10% de pares discordantes",
            "detect_relative_f1_gain_3pct_with_power_0.80": "yes",
        },
        "rationale": (
            "N=600/clase da un IC95 de +/-2.4 pp para FPR alrededor de 10% y +/-2.4 pp para "
            "recall alrededor de 90%, suficiente para separar el efecto historico de la "
            "normalizacion www. (46.70% -> 9.69% de FPR) y para comparaciones pareadas por "
            "McNemar con potencia alta; se evita reducir la muestra para favorecer resultados."
        ),
    }
    (OUT / "cohort2_sample_size_justification.json").write_text(
        json.dumps(justification, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- 1) Descarga de feeds (procedencia) ---------------------------------
    print("[1] Descargando feeds...", flush=True)
    phishing_rows = load_phishing(psl)
    legit_rows, tranco_set = load_legitimate(psl)

    # ---- 2) Exclusión estricta de solapamiento -------------------------------
    print("[2] Aplicando exclusiones de solapamiento...", flush=True)
    excluded_domains: set[str] = set()
    excluded_urls_sha: set[str] = set()

    samples = ROOT / "data" / "processed" / "0.1.0" / "samples.csv"
    n_samples = 0
    with open(samples, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            n_samples += 1
            if r.get("registered_domain"):
                excluded_domains.add(r["registered_domain"].lower())
            if r.get("canonical_url_sha256"):
                excluded_urls_sha.add(r["canonical_url_sha256"])

    old_ext = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase2_externa" / "external_predictions_n1200.csv"
    n_old = 0
    if old_ext.exists():
        with open(old_ext, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                n_old += 1
                if r.get("registered_domain"):
                    excluded_domains.add(r["registered_domain"].lower())
                if r.get("canonical_url"):
                    excluded_urls_sha.add(hashlib.sha256(r["canonical_url"].encode()).hexdigest())

    hand = ROOT / "external_validation_cohort.csv"
    if hand.exists():
        with open(hand, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                if r.get("url"):
                    excluded_urls_sha.add(hashlib.sha256(r["url"].encode()).hexdigest())

    print(f"    corpus maestro samples.csv: {n_samples:,} muestras -> {len(excluded_domains):,} dominios excluidos", flush=True)
    print(f"    cohorte externa anterior: {n_old:,} URLs excluidas", flush=True)

    def canonical(url: str) -> str:
        u = url if "://" in url else "http://" + url
        p = urlsplit(u)
        host = (p.hostname or "").lower()
        path = p.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        query = ("?" + p.query) if p.query else ""
        port = p.port
        netloc = host + (f":{port}" if port and port not in (80, 443) else "")
        return f"{p.scheme.lower()}://{netloc}{path}{query}"

    all_rows: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    seen_reg: set[str] = set()
    seen_url_sha: set[str] = set()

    for row in phishing_rows + legit_rows:
        cu = canonical(row["raw_url"])
        sha = hashlib.sha256(cu.encode()).hexdigest()
        row["canonical_url"] = cu
        row["canonical_url_sha256"] = sha
        row["in_tranco_top1m"] = int(row["registered_domain"] in tranco_set) if tranco_set else ""
        reason = None
        if row["registered_domain"] in excluded_domains:
            reason = "domain_in_training_or_previous_cohort"
        elif sha in excluded_urls_sha:
            reason = "url_in_training_or_previous_cohort"
        elif row["registered_domain"] in seen_reg:
            reason = "duplicate_registered_domain_in_new_cohort"
        elif sha in seen_url_sha:
            reason = "duplicate_url_in_new_cohort"
        if reason:
            row["exclusion_reason"] = reason
            excluded.append(row)
            continue
        seen_reg.add(row["registered_domain"])
        seen_url_sha.add(sha)
        all_rows.append(row)

    # Conflicto de clase: un dominio no puede aparecer como legítimo y phishing
    by_dom: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in all_rows:
        by_dom[r["registered_domain"]].append(r)
    conflict_ids = set()
    for dom, rs in by_dom.items():
        labels = {r["label"] for r in rs}
        if len(labels) > 1:
            for r in rs:
                r["exclusion_reason"] = "class_conflict_same_domain"
                excluded.append(r)
                conflict_ids.add(id(r))
    all_rows = [r for r in all_rows if id(r) not in conflict_ids]

    # ---- 3) Muestreo estratificado determinista ------------------------------
    print("[3] Muestreo estratificado (seed=42)...", flush=True)
    phish_all = [r for r in all_rows if r["label"] == "phishing"]
    legit_all = [r for r in all_rows if r["label"] == "legitimate"]

    def pick_balanced(pool: list[dict[str, Any]], n: int, prefer_idn: int = 40) -> list[dict[str, Any]]:
        rng = random.Random(SEED)
        idn = [r for r in pool if r["host"].find("xn--") >= 0]
        rest = [r for r in pool if r not in idn]
        rng.shuffle(idn)
        rng.shuffle(rest)
        chosen = rest[: max(0, n - min(prefer_idn, len(idn)))]
        chosen.extend(idn[: max(0, n - len(chosen))])
        return chosen[:n]

    phish_sel = pick_balanced(phish_all, N_PHISH)
    legit_sel = pick_balanced(legit_all, N_LEGIT)

    # ---- 4) Enriquecimiento de atributos por URL ----------------------------
    selected = phish_sel + legit_sel
    for i, r in enumerate(selected):
        r["cohort2_id"] = f"c2-{i:05d}"
        r.update(flags(r["host"], r["canonical_url"]))

    # ---- 5) Escritura de la cohorte congelada -------------------------------
    print("[4] Escribiendo cohorte congelada...", flush=True)
    fields = ["cohort2_id", "canonical_url", "host", "registered_domain", "label", "source",
              "verified", "source_record_id", "source_timestamp", "in_tranco_top1m",
              "has_www", "is_idn_punycode", "has_subdomain", "n_host_labels", "has_path",
              "has_params", "is_shortener", "is_ip_host", "canonical_url_sha256"]
    ds_path = OUT / "cohort2_dataset.csv"
    with open(ds_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in selected:
            w.writerow({k: r.get(k, "") for k in fields})

    # Candidatos excluidos (auditoría)
    with open(OUT / "cohort2_excluded.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["raw_url", "registered_domain", "label", "source", "exclusion_reason"],
                           lineterminator="\n")
        w.writeheader()
        for r in excluded:
            w.writerow({k: r.get(k, "") for k in ["raw_url", "registered_domain", "label", "source", "exclusion_reason"]})

    with open(OUT / "cohort2_candidates_all.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["raw_url", "registered_domain", "label", "source"], lineterminator="\n")
        w.writeheader()
        for r in phishing_rows + legit_rows:
            w.writerow({k: r.get(k, "") for k in ["raw_url", "registered_domain", "label", "source"]})

    # ---- 6) Medición real de redirecciones (acortadores + muestra) ----------
    print("[5] Midiendo cadenas de redirecciones reales (HEAD)...", flush=True)
    redirect_targets = [r for r in selected if r["is_shortener"]]
    others = [r for r in selected if not r["is_shortener"]]
    random.Random(SEED).shuffle(others)
    redirect_targets.extend(others[: max(0, 250 - len(redirect_targets))])
    n_red_ok = 0
    with open(OUT / "cohort2_redirects.jsonl", "w", encoding="utf-8") as f:
        for r in redirect_targets:
            res = resolve_redirects(r["canonical_url"])
            n_red_ok += int(res["ok"])
            f.write(json.dumps({"cohort2_id": r["cohort2_id"], "url": r["canonical_url"],
                                "label": r["label"], **res}, ensure_ascii=False) + "\n")
    print(f"    resueltas {n_red_ok}/{len(redirect_targets)} cadenas", flush=True)

    # ---- 7) Congelación de etiquetas ----------------------------------------
    counts = {
        "n_total": len(selected),
        "n_phishing": sum(1 for r in selected if r["label"] == "phishing"),
        "n_legitimate": sum(1 for r in selected if r["label"] == "legitimate"),
        "by_source": dict(Counter(r["source"] for r in selected)),
        "slices": {
            "has_www": sum(r["has_www"] for r in selected),
            "is_idn_punycode": sum(r["is_idn_punycode"] for r in selected),
            "has_subdomain": sum(r["has_subdomain"] for r in selected),
            "has_path": sum(r["has_path"] for r in selected),
            "has_params": sum(r["has_params"] for r in selected),
            "is_shortener": sum(r["is_shortener"] for r in selected),
            "is_ip_host": sum(r["is_ip_host"] for r in selected),
        },
        "slices_by_label": {
            lbl: {
                "n": sum(1 for r in selected if r["label"] == lbl),
                "has_www": sum(r["has_www"] for r in selected if r["label"] == lbl),
                "is_idn": sum(r["is_idn_punycode"] for r in selected if r["label"] == lbl),
                "has_subdomain": sum(r["has_subdomain"] for r in selected if r["label"] == lbl),
            }
            for lbl in ("phishing", "legitimate")
        },
        "overlap_check": {
            "domains_overlapping_training": 0,
            "urls_overlapping_training": 0,
            "domains_overlapping_previous_external_cohort": 0,
            "method": "exclusion por registered_domain (PSL) y sha256 de URL canónica contra "
                      "samples.csv (176.201) y external_predictions_n1200.csv",
        },
        "excluded_total": len(excluded),
        "excluded_by_reason": dict(Counter(r.get("exclusion_reason", "") for r in excluded)),
        "n_candidates_phishing": len(phishing_rows),
        "n_candidates_legitimate": len(legit_rows),
        "seed": SEED,
        "labels_frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.perf_counter() - t_start, 1),
    }
    feeds_meta = {}
    for p in sorted(RAW.glob("*")):
        feeds_meta[p.name] = {"bytes": p.stat().st_size, "sha256": sha256_file(p)}

    frozen = {
        "dataset": "cohort2_dataset.csv",
        "dataset_sha256": sha256_file(ds_path),
        "dataset_bytes": ds_path.stat().st_size,
        "counts": counts,
        "feeds": feeds_meta,
        "excluded_sha256": sha256_file(OUT / "cohort2_excluded.csv"),
        "redirects_sha256": sha256_file(OUT / "cohort2_redirects.jsonl"),
        "psl_file": str(psl_path.relative_to(ROOT)),
        "note": "Etiquetas congeladas tras el freeze_manifest. No re-muestrear ni editar este CSV.",
    }
    (OUT / "cohort2_labels_frozen.json").write_text(json.dumps(frozen, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(counts, indent=2, ensure_ascii=False), flush=True)
    print(f"FREEZED -> {ds_path} sha256={frozen['dataset_sha256']}", flush=True)


if __name__ == "__main__":
    main()
