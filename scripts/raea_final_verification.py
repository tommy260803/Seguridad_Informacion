"""Verificación final de RAEA-Phish: ablaciones auténticas, comparadores justos y estadística.

Entradas (todas existentes; no se fabrican datos):
  artifacts/raea/raea_partitions.csv
  artifacts/corrections_phase2/eval/probe_predictions.csv   (p_m0/p_m1/p_m2 congeladas, estados y latencias medidas)
  artifacts/corrections_phase2/cohort2/cohort2_dataset.csv
  artifacts/raea_final/DATOS_Y_ETIQUETAS.csv                (scripts/raea_label_audit.py)
  configs/raea_final_experiment.json                        (pre-registro)

Salidas en artifacts/raea_final/:
  PREDICCIONES_Y_DECISIONES.csv, RESULTADOS_COMPARATIVOS.csv, ABLACIONES_VERIFICADAS.csv,
  ESTADISTICA_Y_RIESGO.csv, run_metadata.json

Naturaleza de la evaluación: REPLAY OFFLINE. Las probabilidades provienen de los modelos
congelados ejecutados durante el sondeo real de la Cohorte 2; los estados de adquisición y las
latencias por modalidad son los MEDIDOS en ese sondeo. La latencia de cada política es la suma
de las latencias medidas de las modalidades que la política habría solicitado: es una
reconstrucción, no una medición extremo a extremo de la política.
"""
from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import binomtest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from phishguard_orchestrator.raea.engine import run_raea  # noqa: E402
from phishguard_orchestrator.raea.models import Action, RAEAConfig  # noqa: E402
from scripts.run_raea_comparative_experiments import (  # noqa: E402
    simulate_b3_entropy_cascade,
    simulate_b4_conservative,
)
from scripts.train_and_validate_raea_estimators import extract_features_for_sample  # noqa: E402

OUT = ROOT / "artifacts" / "raea_final"
OUT.mkdir(parents=True, exist_ok=True)
CFG = json.loads((ROOT / "configs" / "raea_final_experiment.json").read_text(encoding="utf-8"))
CONFIG_VERSION = CFG["config_version"]
BASE = CFG["base_costs"]
C_FP, GAMMA, C_ABS, LAMBDA = BASE["c_fp"], BASE["gamma"], BASE["c_abstain"], BASE["lambda_cost"]
ACQ = CFG["normalized_acquisition_cost"]
RNG = np.random.default_rng(CFG["seed"])
B = int(CFG["bootstrap_replicates"])

ABLATIONS = {
    "A1": ("RAEA sin estimador de disponibilidad", RAEAConfig(enable_availability=False)),
    "A2": ("RAEA sin costes asimétricos (gamma=1)", RAEAConfig(enable_asymmetric_cost=False)),
    "A3": ("RAEA sin abstención", RAEAConfig(enable_abstention=False)),
    "A4": ("RAEA sin beneficio informativo esperado", RAEAConfig(enable_information_value=False)),
    "A5": ("RAEA sin guarda benigna en M0", RAEAConfig(enforce_benign_guard=False)),
    "A6": ("RAEA completo", RAEAConfig()),
}


# --------------------------------------------------------------------------- datos
def load_data() -> pd.DataFrame:
    parts = pd.read_csv(ROOT / "artifacts" / "raea" / "raea_partitions.csv").set_index("cohort2_id")
    probe = pd.read_csv(ROOT / "artifacts" / "corrections_phase2" / "eval" / "probe_predictions.csv").set_index("cohort2_id")
    meta = pd.read_csv(ROOT / "artifacts" / "corrections_phase2" / "cohort2" / "cohort2_dataset.csv").set_index("cohort2_id")
    labels = pd.read_csv(OUT / "DATOS_Y_ETIQUETAS.csv").set_index("cohort2_id")
    df = parts[["partition_raea", "label", "source"]].join(
        probe[["canonical_url", "infra_status", "content_status", "complete_case", "p_m0", "p_m1", "p_m2",
               "lat_m0_ms", "lat_infra_ms", "lat_content_ms"]]
    ).join(meta[["is_ip_host", "is_shortener", "is_idn_punycode"]]).join(
        labels[["verified_category", "included_phishing_web_population", "included_sensitivity_population"]])
    assert len(df) == 600 and df["p_m1"].notna().all()
    df["y"] = (df["label"] == "phishing").astype(int)
    return df


def build_x0(row) -> dict:
    x0 = extract_features_for_sample(str(row.canonical_url))
    x0["p_m0"] = float(row.p_m0)  # probabilidad congelada observada en el sondeo
    x0["is_ip_host"] = float(row.is_ip_host)
    x0["is_shortener"] = float(row.is_shortener)
    x0["is_idn_punycode"] = float(row.is_idn_punycode)
    x0["in_tranco_top1m"] = 0.0  # evita fuga: los legítimos se muestrearon de Tranco/Majestic
    return x0


def realized_cost(requested, row) -> float:
    c = 0.0
    if "network" in requested:
        c += ACQ["network"]["success"] if row.infra_status == "success" else ACQ["network"]["failure"]
    if "html" in requested:
        c += ACQ["html"]["success"] if row.content_status == "success" else ACQ["html"]["failure"]
    return c


def replay_latency(requested, row) -> float:
    lat = float(row.lat_m0_ms)
    if "network" in requested:
        lat += float(row.lat_infra_ms)
    if "html" in requested:
        lat += float(row.lat_content_ms)
    return lat


def acquired_ok(requested, row):
    ok = []
    for m in requested:
        if m == "network" and row.infra_status == "success":
            ok.append(m)
        if m == "html" and row.content_status == "success":
            ok.append(m)
    return ok


def rec(cid, row, policy, decision, prob, actions, requested, extra=None):
    req = [m for m in requested if m != "url"]
    ok = acquired_ok(req, row)
    r = {
        "cohort2_id": cid,
        "partition": row.partition_raea,
        "policy": policy,
        "historical_label": int(row.y),
        "verified_category": row.verified_category,
        "in_pop_phishing_web": int(row.included_phishing_web_population),
        "in_pop_sensitivity": int(row.included_sensitivity_population),
        "prediction": {"phishing": 1, "legitimate": 0}.get(decision, ""),
        "selective_state": "abstained" if decision == "abstain" else "decided",
        "final_probability": round(float(prob), 6),
        "action_sequence": "|".join(actions),
        "modalities_requested": "|".join(req),
        "modalities_acquired_ok": "|".join(ok),
        "acquisition_failures": len(req) - len(ok) - req.count("visual"),
        "visual_requests_without_data": req.count("visual"),
        "n_modalities_requested_incl_url": 1 + len([m for m in req if m != "visual"]),
        "normalized_cost_realized": round(realized_cost(req, row), 4),
        "latency_ms_replay": round(replay_latency(req, row), 3),
        "latency_source": "suma de latencias medidas por modalidad (replay offline)",
        "config_version": CONFIG_VERSION,
    }
    if extra:
        r.update(extra)
    return r


def chow(p, gamma=GAMMA, c_abs=C_ABS, c_fp=C_FP):
    risks = {"phishing": c_fp * (1 - p), "legitimate": gamma * c_fp * p, "abstain": c_abs}
    return min(risks, key=risks.get)


def run_raea_row(cid, row, x0, cfg: RAEAConfig, policy_name):
    offline = {"infra_status": row.infra_status, "content_status": row.content_status,
               "p_m0": float(row.p_m0), "p_m1": float(row.p_m1), "p_m2": float(row.p_m2),
               "lat_infra_ms": float(row.lat_infra_ms), "lat_content_ms": float(row.lat_content_ms)}
    res = run_raea(str(row.canonical_url), x0, float(row.p_m0), config=cfg, offline_data=offline)
    decision = "abstain" if res.abstained else res.decision
    t0 = res.transitions[0]
    est_av = [t.estimated_availability for t in res.transitions if t.estimated_availability is not None]
    extra = {
        "eff_enable_availability": cfg.enable_availability,
        "eff_enable_asymmetric_cost": cfg.enable_asymmetric_cost,
        "eff_enable_abstention": cfg.enable_abstention,
        "eff_enable_information_value": cfg.enable_information_value,
        "eff_enforce_benign_guard": cfg.enforce_benign_guard,
        "step0_benign_blocked": int(math.isinf(t0.risk_benign)),
        "step0_risk_benign": t0.risk_benign if not math.isinf(t0.risk_benign) else "inf",
        "step0_risk_abstain": t0.risk_abstain if not math.isinf(t0.risk_abstain) else "inf",
        "estimated_availability_seq": "|".join(f"{a:.3f}" for a in est_av),
        "has_lexical_risk": int(bool(x0.get("has_ip_host") or x0.get("is_ip_host") or x0.get("is_shortener")
                                     or x0.get("is_idn_punycode") or x0.get("host_label_count", 2) >= 4)),
    }
    return rec(cid, row, policy_name, decision, res.probability_phishing,
               [t.action.value for t in res.transitions], list(res.modalities_consulted), extra)


# --------------------------------------------------------------------------- políticas
def run_all(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for cid, row in df.iterrows():
        x0 = build_x0(row)
        p0, p1, p2 = float(row.p_m0), float(row.p_m1), float(row.p_m2)
        d = lambda p, t=0.5: "phishing" if p >= t else "legitimate"  # noqa: E731
        rows.append(rec(cid, row, "B0_M0", d(p0), p0, ["stop"], ["url"]))
        rows.append(rec(cid, row, "B1_M1", d(p1), p1, ["acquire_network", "stop"], ["url", "network"]))
        rows.append(rec(cid, row, "B1_M1_bayes", d(p1, 1.0 / (1.0 + GAMMA)), p1,
                        ["acquire_network", "stop"], ["url", "network"]))
        rows.append(rec(cid, row, "B2_M2", d(p2), p2, ["acquire_network", "acquire_html", "stop"],
                        ["url", "network", "html"], {"complete_case": int(row.complete_case)}))
        pr, pb, ab, st, mods = simulate_b3_entropy_cascade(p0, p1, p2)
        rows.append(rec(cid, row, "B3_entropy", "abstain" if ab else d(pb), pb,
                        [f"acquire_{m}" for m in mods[1:]] + ["abstain" if ab else "stop"], mods))
        pr, pb, ab, st, mods = simulate_b4_conservative(p0, p1, p2)
        rows.append(rec(cid, row, "B4_conservative", "abstain" if ab else d(pb), pb,
                        [f"acquire_{m}" for m in mods[1:]] + ["abstain" if ab else "stop"], mods))
        dec = chow(p1)
        rows.append(rec(cid, row, "B5_M1_chow", dec, p1, ["acquire_network", "abstain" if dec == "abstain" else "stop"],
                        ["url", "network"]))
        rows.append(rec(cid, row, "B6_RAEA", "x", 0, [], ["url"]))  # marcador, se reemplaza abajo
        rows.pop()
        rows.append(run_raea_row(cid, row, x0, RAEAConfig(), "B6_RAEA"))
        for aid, (_, cfg) in ABLATIONS.items():
            rows.append(run_raea_row(cid, row, x0, cfg, aid))
    return pd.DataFrame(rows)


def add_b5_cov(pred: pd.DataFrame, df: pd.DataFrame, pop_col: str | None, tag: str):
    """B5_cov: M1 con abstención por confianza; umbral fijado en train para igualar la cobertura de RAEA en train."""
    tr = df[df.partition_raea == "train_avail"]
    if pop_col:
        tr = tr[tr[pop_col] == 1]
    raea_tr = pred[(pred.policy == "B6_RAEA") & pred.cohort2_id.isin(tr.index)]
    cov = float((raea_tr.selective_state == "decided").mean())
    conf_tr = (tr.p_m1 - 0.5).abs() * 2
    thr = float(np.quantile(conf_tr, 1 - cov)) if cov < 1 else 0.0
    out = []
    for cid, row in df.iterrows():
        p1 = float(row.p_m1)
        dec = "abstain" if abs(p1 - 0.5) * 2 < thr else ("phishing" if p1 >= 0.5 else "legitimate")
        out.append(rec(cid, row, f"B5_M1_cov{tag}", dec, p1, ["acquire_network", "abstain" if dec == "abstain" else "stop"],
                       ["url", "network"], {"b5cov_threshold_conf": round(thr, 6), "b5cov_target_coverage_train": round(cov, 6)}))
    return pd.DataFrame(out), thr, cov


# --------------------------------------------------------------------------- métricas
def losses(sub: pd.DataFrame, gamma=GAMMA, c_abs=C_ABS, c_fp=C_FP) -> np.ndarray:
    y = sub.historical_label.values
    ab = (sub.selective_state == "abstained").values
    pr = pd.to_numeric(sub.prediction, errors="coerce").fillna(-1).values
    l = np.zeros(len(sub))
    l[(~ab) & (y == 1) & (pr == 0)] = gamma * c_fp
    l[(~ab) & (y == 0) & (pr == 1)] = c_fp
    l[ab] = c_abs
    return l


def cm(y, p):
    tp = int(((y == 1) & (p == 1)).sum()); fp = int(((y == 0) & (p == 1)).sum())
    tn = int(((y == 0) & (p == 0)).sum()); fn = int(((y == 1) & (p == 0)).sum())
    return tp, fp, tn, fn


def prf(tp, fp, tn, fn):
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec_ = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    fnr = fn / (fn + tp) if fn + tp else float("nan")
    return prec, rec_, f1, fpr, fnr


def metrics(sub: pd.DataFrame) -> dict:
    y = sub.historical_label.values
    ab = (sub.selective_state == "abstained").values
    pr = pd.to_numeric(sub.prediction, errors="coerce").fillna(-1).astype(int).values
    n, nab = len(sub), int(ab.sum())
    tp, fp, tn, fn = cm(y[~ab], pr[~ab])
    prec, rec_, f1, fpr, fnr = prf(tp, fp, tn, fn)
    out = {"N": n, "n_pos": int(y.sum()), "n_neg": int((1 - y).sum()), "n_decided": n - nab, "n_abstained": nab,
           "abstained_pos": int((ab & (y == 1)).sum()), "abstained_neg": int((ab & (y == 0)).sum()),
           "coverage": (n - nab) / n,
           "sel_TP": tp, "sel_FP": fp, "sel_TN": tn, "sel_FN": fn,
           "sel_precision": prec, "sel_recall": rec_, "sel_F1": f1, "sel_FPR": fpr, "sel_FNR": fnr}
    assert tp + fp + tn + fn == n - nab
    for name, fill in (("failopen", 0), ("failclosed", 1)):
        pf = np.where(ab, fill, pr)
        a = cm(y, pf)
        p_, r_, f_, fpr_, fnr_ = prf(*a)
        out.update({f"{name}_TP": a[0], f"{name}_FP": a[1], f"{name}_TN": a[2], f"{name}_FN": a[3],
                    f"{name}_precision": p_, f"{name}_recall": r_, f"{name}_F1": f_,
                    f"{name}_FPR": fpr_, f"{name}_FNR": fnr_})
    l = losses(sub)
    out["risk_selective_penalized"] = float(l.mean())
    out["risk_conditional_decided"] = float(l[~ab].mean()) if (~ab).any() else float("nan")
    out["mean_normalized_cost"] = float(sub.normalized_cost_realized.mean())
    out["risk_operational"] = out["risk_selective_penalized"] + LAMBDA * out["mean_normalized_cost"]
    out["mean_modalities_requested_incl_url"] = float(sub.n_modalities_requested_incl_url.mean())
    out["mean_modalities_acquired_ok"] = float(sub.modalities_acquired_ok.fillna("").map(lambda s: len([x for x in s.split("|") if x])).mean())
    out["acquisition_failures_total"] = int(sub.acquisition_failures.sum())
    out["visual_requests_without_data"] = int(sub.visual_requests_without_data.sum())
    out["latency_ms_p50_replay"] = float(sub.latency_ms_replay.median())
    out["latency_ms_p95_replay"] = float(sub.latency_ms_replay.quantile(0.95))
    out["latency_ms_mean_replay"] = float(sub.latency_ms_replay.mean())
    return out


def populations(pred_test: pd.DataFrame) -> dict:
    return {
        "ORIGINAL_TEST_N300": pred_test,
        "PHISHING_WEB_TEST": pred_test[pred_test.in_pop_phishing_web == 1],
        "PHISHING_WEB_TEST_BROAD": pred_test[pred_test.in_pop_sensitivity == 1],
    }


def paired_boot(a: np.ndarray, b: np.ndarray):
    d = a - b
    n = len(d)
    idx = RNG.integers(0, n, size=(B, n))
    bs = d[idx].mean(axis=1)
    lo, hi = np.percentile(bs, [2.5, 97.5])
    p_less = (np.sum(bs >= 0) + 1) / (B + 1)  # H1: media(a-b) < 0
    p_two = min(1.0, 2 * min((np.sum(bs >= 0) + 1) / (B + 1), (np.sum(bs <= 0) + 1) / (B + 1)))
    return float(d.mean()), float(lo), float(hi), float(p_less), float(p_two)


def mcnemar_exact(c_a: np.ndarray, c_b: np.ndarray):
    n10 = int((c_a & ~c_b).sum()); n01 = int((~c_a & c_b).sum())
    p = binomtest(n10, n10 + n01, 0.5).pvalue if n10 + n01 else 1.0
    return n10, n01, float(p)


def holm(ps):
    order = np.argsort(ps); m = len(ps); adj = np.empty(m); run = 0.0
    for k, i in enumerate(order):
        run = max(run, min(1.0, (m - k) * ps[i])); adj[i] = run
    return adj


# --------------------------------------------------------------------------- main
def main():
    df = load_data()
    print("Ejecutando políticas y ablaciones sobre 600 URLs (replay offline)...")
    pred = run_all(df)
    extra_rows, b5meta = [], {}
    for pop_col, tag in ((None, "_orig"), ("included_phishing_web_population", "_pw"), ("included_sensitivity_population", "_broad")):
        sub, thr, cov = add_b5_cov(pred, df, pop_col, tag)
        extra_rows.append(sub); b5meta[tag] = {"threshold_conf": thr, "train_coverage_target": cov}
    pred = pd.concat([pred] + extra_rows, ignore_index=True)
    pred.to_csv(OUT / "PREDICCIONES_Y_DECISIONES.csv", index=False)

    test = pred[pred.partition == "test_eval"]
    pops = populations(test)
    b5_for_pop = {"ORIGINAL_TEST_N300": "B5_M1_cov_orig", "PHISHING_WEB_TEST": "B5_M1_cov_pw",
                  "PHISHING_WEB_TEST_BROAD": "B5_M1_cov_broad"}
    base_policies = ["B0_M0", "B1_M1", "B1_M1_bayes", "B2_M2", "B3_entropy", "B4_conservative", "B5_M1_chow", "B6_RAEA"]

    # ---- resultados comparativos
    res = []
    for pname, ptab in pops.items():
        for pol in base_policies + [b5_for_pop[pname]]:
            s = ptab[ptab.policy == pol]
            res.append({"population": pname, "policy": pol, **metrics(s)})
        s = ptab[(ptab.policy == "B2_M2") & (ptab.complete_case == 1)]
        if len(s):
            res.append({"population": pname + "|complete_case", "policy": "B2_M2", **metrics(s)})
        # Descriptivo: M1 a cobertura igualada a RAEA en test (sin usar etiquetas)
        r = ptab[ptab.policy == "B6_RAEA"]; m1 = ptab[ptab.policy == "B1_M1"].copy()
        k = int((r.selective_state == "abstained").sum())
        conf = (m1.final_probability - 0.5).abs()
        ab_idx = conf.nsmallest(k).index
        m1.loc[ab_idx, "selective_state"] = "abstained"; m1.loc[ab_idx, "prediction"] = ""
        res.append({"population": pname, "policy": "B1_M1_equalcov_descriptive", **metrics(m1)})
    res_df = pd.DataFrame(res)
    res_df.to_csv(OUT / "RESULTADOS_COMPARATIVOS.csv", index=False)

    # ---- ablaciones con verificación de componentes
    abl = []
    for pname, ptab in pops.items():
        a6 = ptab[ptab.policy == "A6"].set_index("cohort2_id")
        for aid, (desc, cfg) in ABLATIONS.items():
            s = ptab[ptab.policy == aid].set_index("cohort2_id")
            m = metrics(s.reset_index())
            same = s.loc[a6.index]
            diff_traj = int((same.action_sequence != a6.action_sequence).sum())
            diff_dec = int(((same.selective_state != a6.selective_state) |
                            (same.prediction.astype(str) != a6.prediction.astype(str))).sum())
            av = s.estimated_availability_seq.fillna("").astype(str)
            checks = {
                "check_flags_applied": str({k: v for k, v in asdict(cfg).items() if k.startswith(("enable", "enforce"))}),
                "check_A1_all_est_avail_eq_1": bool(av[av != ""].map(lambda x: all(float(v) == 1.0 for v in x.split("|"))).all()) if aid == "A1" else "",
                "check_A3_no_abstention": bool(m["n_abstained"] == 0) if aid == "A3" else "",
                "check_A3_risk_abstain_inf": bool((s.step0_risk_abstain.astype(str) == "inf").all()) if aid == "A3" else "",
                "check_A4_no_acquisitions": bool((s.modalities_requested.fillna("") == "").all()) if aid == "A4" else "",
                "check_A5_benign_never_blocked": bool((s.step0_benign_blocked == 0).all()) if aid == "A5" else "",
                "n_step0_benign_blocked": int(s.step0_benign_blocked.sum()),
            }
            abl.append({"population": pname, "variant": aid, "description": desc, **m,
                        "urls_trajectory_differs_from_A6": diff_traj, "urls_decision_differs_from_A6": diff_dec, **checks})
    pd.DataFrame(abl).to_csv(OUT / "ABLACIONES_VERIFICADAS.csv", index=False)

    # ---- estadística y riesgo
    st = []
    for pname, ptab in pops.items():
        get = lambda pol: ptab[ptab.policy == pol].set_index("cohort2_id").sort_index()  # noqa: E731
        r = get("B6_RAEA")
        comps = ["B1_M1", "B1_M1_bayes", "B5_M1_chow", b5_for_pop[pname], "B3_entropy", "B2_M2"]
        for c in comps:
            o = get(c).loc[r.index]
            family = "primary" if pname == "PHISHING_WEB_TEST" and c in ("B1_M1", "B5_M1_chow") else "secondary"
            d, lo, hi, pl, p2 = paired_boot(losses(r), losses(o))
            st.append({"population": pname, "comparison": f"B6_RAEA - {c}", "metric": "risk_selective_penalized",
                       "scenario": f"gamma={GAMMA},c_abst={C_ABS}", "estimate": d, "ci95_low": lo, "ci95_high": hi,
                       "p_one_sided_raea_lower": pl, "p_two_sided": p2, "test": "bootstrap pareado por URL",
                       "family": family, "hypothesis": {"B1_M1": "H1", "B5_M1_chow": "H2"}.get(c, "") if family == "primary" else ""})
            d, lo, hi, pl, p2 = paired_boot(r.normalized_cost_realized.values, o.normalized_cost_realized.values)
            st.append({"population": pname, "comparison": f"B6_RAEA - {c}", "metric": "normalized_cost_realized",
                       "scenario": "", "estimate": d, "ci95_low": lo, "ci95_high": hi, "p_one_sided_raea_lower": pl,
                       "p_two_sided": p2, "test": "bootstrap pareado por URL",
                       "family": "primary" if (pname == "PHISHING_WEB_TEST" and c == "B1_M1") else "secondary",
                       "hypothesis": "H3" if (pname == "PHISHING_WEB_TEST" and c == "B1_M1") else ""})
            for name, fill in (("failopen", 0), ("failclosed", 1)):
                def correct(t):
                    pr = pd.to_numeric(t.prediction, errors="coerce").fillna(fill).astype(int).values
                    pr = np.where((t.selective_state == "abstained").values, fill, pr)
                    return pr == t.historical_label.values
                n10, n01, p = mcnemar_exact(correct(r), correct(o))
                st.append({"population": pname, "comparison": f"B6_RAEA - {c}", "metric": f"accuracy_forced_{name}",
                           "scenario": "", "estimate": (n10 - n01) / len(r), "ci95_low": "", "ci95_high": "",
                           "p_one_sided_raea_lower": "", "p_two_sided": p,
                           "test": f"McNemar exacto (RAEA gana={n10}, comparador gana={n01})", "family": "secondary", "hypothesis": ""})
        # errores decididos vs abstenciones (sin costes)
        for pol in base_policies + [b5_for_pop[pname]]:
            s = get(pol)
            for g in CFG["cost_scenarios"]["gamma"]:
                for ca in CFG["cost_scenarios"]["c_abstain"]:
                    st.append({"population": pname, "comparison": pol, "metric": "risk_selective_penalized",
                               "scenario": f"gamma={g},c_abst={ca}", "estimate": float(losses(s, g, ca).mean()),
                               "ci95_low": "", "ci95_high": "", "p_one_sided_raea_lower": "", "p_two_sided": "",
                               "test": "escenario de costes pre-declarado", "family": "risk_scenario", "hypothesis": ""})
    st_df = pd.DataFrame(st)
    prim = st_df[st_df.family == "primary"].index
    st_df.loc[prim, "p_holm"] = holm(st_df.loc[prim, "p_one_sided_raea_lower"].astype(float).values)
    st_df.to_csv(OUT / "ESTADISTICA_Y_RIESGO.csv", index=False)

    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    meta = {"commit_base": commit, "config_version": CONFIG_VERSION, "b5_cov": b5meta,
            "inputs_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in [
                "artifacts/raea/raea_partitions.csv", "artifacts/corrections_phase2/eval/probe_predictions.csv",
                "artifacts/corrections_phase2/cohort2/cohort2_dataset.csv", "artifacts/raea/availability_estimator.joblib",
                "artifacts/raea_final/DATOS_Y_ETIQUETAS.csv", "configs/raea_final_experiment.json"]}}
    (OUT / "run_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    show = ["population", "policy", "N", "coverage", "abstained_pos", "abstained_neg", "sel_FN", "sel_FP", "sel_F1",
            "failopen_F1", "failclosed_F1", "risk_selective_penalized", "mean_normalized_cost", "mean_modalities_requested_incl_url"]
    pd.set_option("display.width", 250)
    print(res_df[show].round(4).to_string())
    print(pd.DataFrame(abl)[["population", "variant", "coverage", "sel_FN", "sel_FP", "failopen_F1", "risk_selective_penalized",
                             "mean_modalities_requested_incl_url", "urls_trajectory_differs_from_A6", "urls_decision_differs_from_A6"]].round(4).to_string())
    print(st_df[st_df.family == "primary"].to_string())


if __name__ == "__main__":
    main()
