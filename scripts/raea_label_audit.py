"""Auditoría de etiquetas y población experimental de RAEA-Phish (Fase 2).

Clasifica las 600 URLs sondeadas de la Cohorte 2 (train_avail + test_eval) en:
PHISHING_WEB_VERIFICADO, LEGITIMO_VERIFICADO, MALWARE_NO_PHISHING,
ETIQUETA_INCIERTA, NO_VERIFICABLE.

Criterios (ninguno usa solo la extensión del archivo; ninguno usa las salidas de M0-M2):
* phishtank: la URL canónica (o, en su defecto, el host) aparece en el volcado
  'online_valid' con verified == 'yes'  -> PHISHING_WEB_VERIFICADO (nivel comunidad).
* openphish: la URL/host aparece en el feed OpenPhish (feed exclusivo de phishing,
  verificación automatizada del proveedor) -> PHISHING_WEB_VERIFICADO (nivel automatizado).
  En ambos casos, si el recurso es un binario/script descargable (extensión ejecutable
  O content-type no HTML observado) -> ETIQUETA_INCIERTA (evidencia contradictoria).
  Si no se encuentra en el volcado congelado -> NO_VERIFICABLE.
* urlhaus: el alcance del feed es distribución de malware. Nunca se cuenta como phishing.
  MALWARE_NO_PHISHING si hay evidencia de recurso de carga útil (content-type no HTML
  observado por el sondeo, nombre de recurso ejecutable/script, o host IP:puerto);
  si el sondeo devolvió HTML con formulario de credenciales -> ETIQUETA_INCIERTA;
  en otro caso MALWARE_NO_PHISHING por alcance del feed.
* tranco/majestic: LEGITIMO_VERIFICADO solo si (a) el host NO aparece en ninguno de los
  tres feeds de amenazas y (b) el dominio registrado aparece en AMBOS rankings
  independientes (Tranco y Majestic). Con un solo ranking -> ETIQUETA_INCIERTA.
  Si aparece en un feed de amenazas -> ETIQUETA_INCIERTA.
  Es una verificación automatizada multi-fuente, no una inspección manual.

No se modifica ninguna etiqueta histórica: se añade una columna nueva.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_data.psl import PublicSuffixList  # noqa: E402
from phishguard_data.urls import canonicalize_url  # noqa: E402

FEEDS = ROOT / "artifacts" / "corrections_phase2" / "cohort2" / "raw_feeds"
OUT = ROOT / "artifacts" / "raea_final"
OUT.mkdir(parents=True, exist_ok=True)

psl = PublicSuffixList.from_file(ROOT / "data" / "raw" / "public_suffix_list.dat")

PAYLOAD_EXT = {
    "exe", "apk", "zip", "sh", "lnk", "scr", "msi", "bat", "jar", "dll", "bin", "ps1",
    "arm", "arm5", "arm6", "arm7", "i686", "x86", "mips", "mpsl", "m68k", "ppc", "sh4",
    "m", "i", "elf", "rar", "7z", "iso", "img", "vbs", "hta", "cmd", "js", "dat",
}


def canon(url: str):
    try:
        c = canonicalize_url(url, psl=psl)
        return c.value, c.registered_domain
    except Exception:
        return None, None


def host_of(url: str) -> str:
    h = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    h = h.rsplit("@", 1)[-1].split(":", 1)[0].lower().strip(".")
    return h[4:] if h.startswith("www.") else h


def resource_ext(url: str) -> str:
    path = url.split("://", 1)[-1].split("/", 1)[1] if "/" in url.split("://", 1)[-1] else ""
    path = path.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        return last.rsplit(".", 1)[-1].lower()
    return last.lower() if last in PAYLOAD_EXT else ""


def defang(s: str) -> str:
    return s.replace(".", "[.]") if s else s


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_feeds():
    print("Cargando feeds congelados...")
    pt = json.load(open(FEEDS / "phishtank_online_valid.json", encoding="utf-8"))
    pt_url, pt_host = {}, {}
    for e in pt:
        if e.get("verified") != "yes":
            continue
        cv, _ = canon(e["url"])
        rec = {"phish_id": e["phish_id"], "target": e.get("target", ""),
               "submission_time": e.get("submission_time", ""), "verification_time": e.get("verification_time", "")}
        if cv:
            pt_url.setdefault(cv, rec)
        pt_host.setdefault(host_of(e["url"]), rec)
    op_lines = [l.strip() for l in open(FEEDS / "openphish_feed.txt", encoding="utf-8") if l.strip()]
    op_url = {canon(u)[0] for u in op_lines} - {None}
    op_host = {host_of(u) for u in op_lines}
    uh_lines = [l.strip() for l in open(FEEDS / "urlhaus_online.txt", encoding="utf-8")
                if l.strip() and not l.startswith("#")]
    uh_host = {host_of(u) for u in uh_lines}
    with zipfile.ZipFile(FEEDS / "tranco_top1m.csv.zip") as z:
        name = z.namelist()[0]
        tranco = {}
        for row in csv.reader(io.TextIOWrapper(z.open(name), encoding="utf-8")):
            if len(row) >= 2:
                tranco[row[1].lower().strip()] = int(row[0])
    majestic = {}
    with open(FEEDS / "majestic_million.csv", encoding="utf-8", errors="ignore") as f:
        r = csv.reader(f)
        header = next(r)
        di = header.index("Domain")
        for row in r:
            if len(row) > di:
                majestic[row[di].lower().strip()] = int(row[0])
    print(f"  phishtank verificados: {len(pt_url)} URLs; openphish: {len(op_url)}; urlhaus hosts: {len(uh_host)}; "
          f"tranco: {len(tranco)}; majestic: {len(majestic)}")
    return pt_url, pt_host, op_url, op_host, uh_host, tranco, majestic


def load_probe_content():
    info = {}
    for l in open(ROOT / "artifacts" / "corrections_phase2" / "eval" / "probe_raw.jsonl", encoding="utf-8"):
        d = json.loads(l)
        c = d["probe"].get("content") or {}
        feats = c.get("features") or {}
        info[d["sample"]["cohort2_id"]] = {
            "content_status": c.get("status"),
            "content_type": c.get("content_type") or "",
            "content_error": c.get("error_code") or "",
            "password_inputs": float(feats.get("html_password_input_count", 0.0) or 0.0),
            "login_terms": float(feats.get("html_login_term_count", 0.0) or 0.0),
        }
    return info


def main():
    parts = pd.read_csv(ROOT / "artifacts" / "raea" / "raea_partitions.csv")
    meta = pd.read_csv(ROOT / "artifacts" / "corrections_phase2" / "cohort2" / "cohort2_dataset.csv").set_index("cohort2_id")
    probe = load_probe_content()
    pt_url, pt_host, op_url, op_host, uh_host, tranco, majestic = load_feeds()
    threat_hosts = set(pt_host) | op_host | uh_host

    rows = []
    for _, r in parts.iterrows():
        cid = r.cohort2_id
        m = meta.loc[cid]
        url = m.canonical_url
        host = host_of(url)
        rd = str(m.registered_domain).lower()
        ext = resource_ext(url)
        pc = probe.get(cid, {})
        non_html = pc.get("content_error") == "non_html_content_type"
        is_ip = str(m.is_ip_host) in ("1", "1.0", "True")
        has_port = ":" in url.split("://", 1)[-1].split("/", 1)[0]
        cred_form = pc.get("password_inputs", 0) > 0
        src = r.source
        evidence, crit, cat, level = [], "", "", ""
        threat_cat = ""
        rec = {}

        if src in ("phishtank", "openphish"):
            threat_cat = "phishing (feed específico)"
            if src == "phishtank":
                rec = pt_url.get(url) or {}
                if rec:
                    evidence.append(f"phishtank_id={rec['phish_id']} verified=yes (match URL)")
                elif host in pt_host:
                    rec = pt_host[host]
                    evidence.append(f"phishtank_id={rec['phish_id']} verified=yes (match host)")
                found = bool(rec)
                level = "verificación_comunitaria_phishtank"
            else:
                found = url in op_url or host in op_host
                if found:
                    evidence.append("presente en feed OpenPhish congelado")
                level = "verificación_automatizada_openphish"
            payload = (ext in PAYLOAD_EXT) or non_html
            if payload:
                evidence.append(f"recurso_descargable ext={ext or '-'} non_html={non_html}")
            if cred_form:
                evidence.append("sondeo: formulario con campo password (solo anotación)")
            if not found:
                cat, crit = "NO_VERIFICABLE", "No se encontró en el volcado congelado del feed"
            elif payload:
                cat, crit = "ETIQUETA_INCIERTA", "Feed de phishing pero el recurso es una carga útil descargable"
            else:
                cat, crit = "PHISHING_WEB_VERIFICADO", "Presente en feed específico de phishing; recurso web"
        elif src == "urlhaus":
            threat_cat = "distribución de malware (alcance URLhaus)"
            level = "alcance_del_feed_urlhaus"
            if non_html:
                evidence.append("sondeo: content-type no HTML (carga útil)")
            if ext in PAYLOAD_EXT:
                evidence.append(f"recurso ejecutable/script ext={ext}")
            if is_ip and has_port:
                evidence.append("host IP:puerto")
            if pc.get("content_type") == "text/html" and cred_form:
                cat, crit = "ETIQUETA_INCIERTA", "Feed de malware pero el sondeo observó HTML con formulario de credenciales"
                evidence.append("sondeo: HTML con campo password")
            elif evidence:
                cat, crit = "MALWARE_NO_PHISHING", "Feed de malware + evidencia de recurso de carga útil"
            else:
                cat, crit = "MALWARE_NO_PHISHING", "Feed de malware; sin evidencia de página de phishing"
        else:  # tranco / majestic
            threat_cat = "ninguna"
            level = "verificación_automatizada_multifuente"
            in_t = rd in tranco or host in tranco
            in_m = rd in majestic or host in majestic
            in_threat = host in threat_hosts or rd in threat_hosts
            evidence.append(f"tranco={'rank ' + str(tranco.get(rd, tranco.get(host))) if in_t else 'no'}")
            evidence.append(f"majestic={'rank ' + str(majestic.get(rd, majestic.get(host))) if in_m else 'no'}")
            evidence.append(f"en_feeds_amenaza={in_threat}")
            if in_threat:
                cat, crit = "ETIQUETA_INCIERTA", "Host presente en un feed de amenazas"
            elif in_t and in_m:
                cat, crit = "LEGITIMO_VERIFICADO", "En Tranco y Majestic; ausente de PhishTank/OpenPhish/URLhaus"
            else:
                cat, crit = "ETIQUETA_INCIERTA", "Solo un ranking de popularidad; consenso insuficiente"

        rows.append({
            "cohort2_id": cid,
            "partition": r.partition_raea,
            "source": src,
            "historical_label": r.label,
            "verified_category": cat,
            "threat_category": threat_cat,
            "verification_level": level,
            "verification_criterion": crit,
            "evidence": "; ".join(evidence),
            "resource_type": ("payload_descargable" if (ext in PAYLOAD_EXT or non_html) else "pagina_web"),
            "content_status_observed": pc.get("content_status"),
            "content_error_observed": pc.get("content_error"),
            "registered_domain_ref": rd if r.label == "legitimate" else defang(rd),
            "canonical_url_sha256": m.canonical_url_sha256,
            "source_timestamp": rec.get("submission_time", "") if rec else "",
            "verification_time": rec.get("verification_time", "") if rec else "",
            "phishtank_target": rec.get("target", "") if rec else "",
            "labels_frozen_at_utc": "2026-10-14T03:25:00Z",
        })

    df = pd.DataFrame(rows)
    # Duplicados y solapamiento de dominios entre particiones
    df["dup_url_in_cohort"] = df.duplicated("canonical_url_sha256", keep=False).astype(int)
    rd_parts = df.groupby("registered_domain_ref")["partition"].nunique()
    df["domain_in_both_partitions"] = df["registered_domain_ref"].map(lambda d: int(rd_parts.get(d, 1) > 1))
    df["included_phishing_web_population"] = df["verified_category"].isin(
        ["PHISHING_WEB_VERIFICADO", "LEGITIMO_VERIFICADO"]).astype(int)
    # Población de sensibilidad: phishing verificado + legítimos presuntos (un ranking,
    # ausentes de los tres feeds de amenazas). Declarada como análisis de sensibilidad.
    presumed_legit = (df["historical_label"] == "legitimate") & df["evidence"].str.contains("en_feeds_amenaza=False")
    df["included_sensitivity_population"] = (
        (df["verified_category"] == "PHISHING_WEB_VERIFICADO") | presumed_legit).astype(int)
    df.to_csv(OUT / "DATOS_Y_ETIQUETAS.csv", index=False)

    summary = {
        "n_total": len(df),
        "by_partition_category": {f"{k[0]}|{k[1]}": int(v) for k, v in df.groupby(["partition", "verified_category"]).size().items()},
        "by_source_category": {f"{k[0]}|{k[1]}": int(v) for k, v in df.groupby(["source", "verified_category"]).size().items()},
        "duplicate_urls": int(df.dup_url_in_cohort.sum()),
        "domains_shared_between_partitions": int(df[df.domain_in_both_partitions == 1].registered_domain_ref.nunique()),
        "feed_sha256": {p.name: sha256_file(p) for p in FEEDS.iterdir() if p.is_file()},
    }
    (OUT / "label_audit_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "feed_sha256"}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
