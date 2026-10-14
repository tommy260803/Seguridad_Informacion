"""Fase 2 - PASO D (medición complementaria): redirecciones HTTP 301/302 y acortadores.

Motivo: en phase2b la medición de cadenas usó urllib, que sigue automáticamente las
redirecciones, por lo que todos los hops se registraron como 0 (no distinguía 301/302).
Este script:
  1) Remide la cadena de redirecciones de los mismos 250 objetivos de la cohorte2
     con un opener que NO sigue redirecciones automáticamente, registrando cada salto
     (status, Location, tiempo) con peticiones HEAD reales.
  2) Construye un conjunto SUPLEMENTARIO de acortadores (2.480 candidatos detectados en
     los feeds; la cohorte congelada no incluyó ninguno) con un dominio-acortador por
     URL, y evalúa los 4 brazos de nivel URL sobre ese conjunto (descriptivo, N pequeño).
  3) Verifica que las reglas del sistema cubren esos acortadores
     (SHORTENERS_REQUIRING_REDIRECT / requires_redirect).

NO modifica la cohorte congelada, los modelos, los umbrales ni la normalización.
Salidas: artifacts/corrections_phase2/eval/redirects_manual_chains.jsonl,
         artifacts/corrections_phase2/eval/shortener_supplement.json,
         artifacts/corrections_phase2/eval/shortener_predictions.csv
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "artifacts" / "corrections_phase2"
EVAL = OUT / "eval"
UA = {"User-Agent": "PhishPe-Scientific-Validator/3.0 (research)"}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "s.id", "rb.gy", "shorturl.at", "t.ly", "v.gd", "soo.gd", "bl.ink",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def manual_chain(url: str, max_hops: int = 6, timeout: float = 8.0) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    chain: list[dict[str, Any]] = []
    current = url
    t_start = time.perf_counter()
    error = None
    try:
        for hop in range(max_hops + 1):
            req = urllib.request.Request(current, method="HEAD", headers=UA)
            t0 = time.perf_counter()
            try:
                with opener.open(req, timeout=timeout) as resp:
                    code, location = resp.status, resp.headers.get("Location")
            except urllib.error.HTTPError as he:
                code, location = he.code, (he.headers.get("Location") if he.headers else None)
            hop_ms = (time.perf_counter() - t0) * 1000.0
            chain.append({"hop": hop, "url": current, "status": int(code),
                          "location": location, "elapsed_ms": round(hop_ms, 2)})
            if int(code) in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue
            break
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"[:200]
    redirect_statuses = [c["status"] for c in chain if c["status"] in (301, 302, 303, 307, 308)]
    return {
        "start_url": url,
        "final_url": current,
        "hops": len([c for c in chain if c["status"] in (301, 302, 303, 307, 308)]),
        "redirect_statuses": redirect_statuses,
        "chain": chain,
        "total_ms": round((time.perf_counter() - t_start) * 1000.0, 2),
        "error": error,
    }


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def main() -> None:
    from phishguard_data.psl import PublicSuffixList

    EVAL.mkdir(parents=True, exist_ok=True)
    psl = PublicSuffixList.from_file(sorted((ROOT / "data" / "raw").rglob("public_suffix_list.dat"))[-1])

    # ------------------------------------------------ 1) remedición de cadenas
    targets: list[dict[str, Any]] = []
    old = EVAL / "cohort2_redirects_target_ids.json"
    prev = OUT / "cohort2" / "cohort2_redirects.jsonl"
    if prev.exists():
        with open(prev, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line)
                targets.append({"cohort2_id": d["cohort2_id"], "url": d["url"], "label": d["label"],
                                "origin": "cohort2_main"})
    print(f"[1] Remidiendo {len(targets)} cadenas sin auto-seguimiento...", flush=True)
    results = []
    for t in targets:
        res = manual_chain(t["url"])
        results.append({**t, **res})
    with open(EVAL / "redirects_manual_chains.jsonl", "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    by_label: dict[str, Counter] = {"phishing": Counter(), "legitimate": Counter()}
    for r in results:
        lbl = r["label"]
        by_label[lbl]["measured"] += 1
        if r["hops"] > 0:
            by_label[lbl]["with_redirect"] += 1
            by_label[lbl][f"status_{r['redirect_statuses'][0]}"] += 1
        if r["error"]:
            by_label[lbl]["errors"] += 1

    # ------------------------------------------------ 2) conjunto suplementario
    print("[2] Construyendo conjunto suplementario de acortadores...", flush=True)
    seen_domains: set[str] = set()
    supplement: list[dict[str, Any]] = []
    with open(OUT / "cohort2" / "cohort2_candidates_all.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            dom = (r["registered_domain"] or "").lower()
            if dom not in SHORTENER_DOMAINS or dom in seen_domains:
                continue
            seen_domains.add(dom)
            supplement.append({
                "supp_id": f"supp-short-{len(supplement):03d}",
                "canonical_url": r["raw_url"], "registered_domain": dom, "host": dom,
                "label": r["label"], "source": r["source"],
                "label_int": 1 if r["label"] == "phishing" else 0,
            })
            if len(supplement) >= 16:
                break
    print(f"    {len(supplement)} acortadores únicos", flush=True)

    chain_sup = []
    for s in supplement:
        chain_sup.append({"supp_id": s["supp_id"], **manual_chain(s["canonical_url"])})
    # dominios acortadores legítimos (bit.ly y cía suelen resolver a sitios legítimos);
    # se registran las cadenas sin usarlas como etiquetas de clase.

    # ------------------------------------------------ 3) evaluación descriptiva
    import joblib
    from contextlib import ExitStack
    from unittest.mock import patch

    from phishguard_ml import features as feat_mod
    from phishguard_ml import hybrid_model as hm_mod
    from phishguard_ml.detection_rules import DetectionRules
    from phishguard_ml.features import UrlFeatureContext, extract_url_features
    from phishguard_ml.hybrid_model import HybridM0Model

    shortener_rule_set = set(DetectionRules.SHORTENERS_REQUIRING_REDIRECT)

    f2_02 = load_module("fase2_02_d", ROOT / "scripts" / "fase2_02_build_and_evaluate_external.py")
    baseline_hg = load_module("baseline_homoglyphs_d",
                              OUT / "baseline_original" / "src__phishguard_ml__homoglyphs.py")

    m0 = joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")
    clf, names, tau = m0["model"], list(m0["feature_names"]), float(m0["threshold"])
    hybrid = HybridM0Model()

    rows_out = []
    for s in supplement:
        # M0 original (sin normalización) vs M0 normalizado
        ctx = UrlFeatureContext(s["canonical_url"], s["registered_domain"])
        f_norm = extract_url_features(ctx)
        X_norm = [[f_norm[k] for k in names]]
        with patch.object(feat_mod, "_strip_www", lambda h: h):
            ctx2 = UrlFeatureContext(s["canonical_url"], s["registered_domain"])
            f_org = extract_url_features(ctx2)
            X_org = [[f_org[k] for k in names]]
        p_norm = float(clf.predict_proba(X_norm)[:, 1][0])
        p_org = float(clf.predict_proba(X_org)[:, 1][0])

        # Config A (código base) vs Config C (código corregido)
        with ExitStack() as st:
            st.enter_context(patch.object(DetectionRules, "_check_server_geolocation", f2_02.no_op_geo))
            st.enter_context(patch.object(DetectionRules, "_check_domain_age", f2_02.no_op_age))
            st.enter_context(patch.object(feat_mod, "_strip_www", lambda h: h))
            st.enter_context(patch.object(hm_mod, "analyze_homoglyphs", baseline_hg.analyze_homoglyphs))
            res_a = hybrid.predict(s["canonical_url"], user_country="EC")
        with ExitStack() as st:
            st.enter_context(patch.object(DetectionRules, "_check_server_geolocation", f2_02.no_op_geo))
            st.enter_context(patch.object(DetectionRules, "_check_domain_age", f2_02.no_op_age))
            res_c = hybrid.predict(s["canonical_url"], user_country="EC")

        covered = s["registered_domain"] in shortener_rule_set
        rows_out.append({
            **s,
            "prob_M0_original": round(p_org, 6), "prob_M0_normalizado": round(p_norm, 6),
            "pred_M0_original": int(p_org >= tau), "pred_M0_normalizado": int(p_norm >= tau),
            "prob_configA": round(float(res_a["probability"]), 6), "decision_configA": res_a["decision"],
            "prob_configC": round(float(res_c["probability"]), 6), "decision_configC": res_c["decision"],
            "shortener_rule_covered": int(covered),
        })

    pred_file = EVAL / "shortener_predictions.csv"
    with open(pred_file, "w", encoding="utf-8", newline="") as f:
        fields = ["supp_id", "canonical_url", "registered_domain", "label", "source",
                  "prob_M0_original", "prob_M0_normalizado", "pred_M0_original", "pred_M0_normalizado",
                  "prob_configA", "decision_configA", "prob_configC", "decision_configC",
                  "shortener_rule_covered"]
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in rows_out:
            w.writerow({k: r.get(k, "") for k in fields})

    y = [r["label_int"] for r in rows_out]
    def acc(key_pred: str) -> float:
        if not y:
            return 0.0
        return round(sum(1 for i, r in enumerate(rows_out) if r[key_pred] == y[i]) / len(y), 6)

    summary = {
        "note": "Conjunto SUPLEMENTARIO fuera de la cohorte congelada; N pequeño => solo descriptivo, "
                "sin afirmaciones de significancia.",
        "n_shortener_urls": len(rows_out),
        "domains": sorted({r['registered_domain'] for r in rows_out}),
        "labels": dict(Counter(r["label"] for r in rows_out)),
        "shortener_rule_coverage": f"{sum(r['shortener_rule_covered'] for r in rows_out)}/{len(rows_out)}",
        "accuracy_descriptive": {
            "M0_original": acc("pred_M0_original"),
            "M0_normalizado": acc("pred_M0_normalizado"),
            "Config_A": round(sum(1 for i, r in enumerate(rows_out) if (r["decision_configA"] == "phishing") == y[i]) / max(1, len(y)), 6),
            "Config_C": round(sum(1 for i, r in enumerate(rows_out) if (r["decision_configC"] == "phishing") == y[i]) / max(1, len(y)), 6),
        },
        "predictions_sha256": sha256_file(pred_file),
        "redirect_measurement_main_cohort": {
            "n_measured": len(results),
            "by_label": {k: dict(v) for k, v in by_label.items()},
            "n_with_real_redirect": sum(1 for r in results if r["hops"] > 0),
            "hops_histogram": dict(Counter(r["hops"] for r in results if r["hops"] > 0)),
            "file": "artifacts/corrections_phase2/eval/redirects_manual_chains.jsonl",
            "file_sha256": sha256_file(EVAL / "redirects_manual_chains.jsonl"),
        },
        "redirect_measurement_shorteners": {
            "n": len(chain_sup),
            "n_with_real_redirect": sum(1 for r in chain_sup if r["hops"] > 0),
            "hops_histogram": dict(Counter(r["hops"] for r in chain_sup)),
        },
        "method": "HEAD con opener sin auto-seguimiento; cada salto (status + Location) registrado con "
                  "reloj monotónico. Peticiones HTTP reales a la red, sin cuerpos descargados.",
    }
    (EVAL / "shortener_supplement.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("n_shortener_urls", "labels", "shortener_rule_coverage",
                                              "accuracy_descriptive")}, indent=2), flush=True)
    print(f"Redirecciones reales en cohorte principal: {summary['redirect_measurement_main_cohort']['n_with_real_redirect']}"
          f"/{len(results)} | en acortadores: {summary['redirect_measurement_shorteners']['n_with_real_redirect']}"
          f"/{len(chain_sup)}", flush=True)


if __name__ == "__main__":
    main()
