"""Verificación directa de los DOS defectos que la auditoría independiente reprodujo a mano.

Se ejecuta como script (además de las 32 pruebas de regresión de pytest) y deja constancia
en artifacts/corrections_phase2/eval/manual_audit_regressions.json:
  1. BUG-03: analyze_homoglyphs('www.xn--pple-43d.com', 'xn--pple-43d.com') -> is_spoofing=True
     (antes: False, porque el regex no decodificaba etiquetas Punycode con guion)
  2. BUG-04: cambiar abstention_threshold entre 0.01 / 0.20 / 0.99 debe cambiar la decisión
     (antes: la decisión era 'abstain' con cualquier valor porque el motor comparaba con
     uncertainty_threshold)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.homoglyphs import analyze_homoglyphs, to_visual_skeleton  # noqa: E402
from phishguard_orchestrator.engine import decide_next  # noqa: E402
from phishguard_orchestrator.models import AdaptivePolicy  # noqa: E402

out: dict = {}

# ---------------------------------------------------------------- BUG-03
skeleton = to_visual_skeleton("www.xn--pple-43d.com")
res = analyze_homoglyphs("www.xn--pple-43d.com", "xn--pple-43d.com")
out["bug03_punycode"] = {
    "input_host": "www.xn--pple-43d.com",
    "input_registered_domain": "xn--pple-43d.com",
    "visual_skeleton_repr": repr(skeleton),
    "decoded_contains_apple": "apple" in skeleton,
    "is_spoofing": res["is_spoofing"],
    "homoglyph_brand_spoofing_detected": res["homoglyph_brand_spoofing_detected"],
    "closest_brand_target": res["closest_brand_target"],
    "visual_edit_distance": res["visual_edit_distance"],
    "audit_expected_is_spoofing": True,
    "PASS": res["is_spoofing"] is True and res["homoglyph_brand_spoofing_detected"] is True,
}

# controles negativos (no debe introducir falsos positivos)
neg = []
for host, reg in [("www.apple.com", "apple.com"), ("accounts.google.com", "google.com"),
                  ("muenchen.de", "muenchen.de"), ("xn--mnchen-3ya.de", "mnchen-3ya.de"),
                  ("portal.espol.edu.ec", "espol.edu.ec")]:
    r = analyze_homoglyphs(host, reg)
    neg.append({"host": host, "registered": reg, "is_spoofing": r["is_spoofing"]})
out["bug03_negative_controls"] = {"cases": neg, "PASS": all(c["is_spoofing"] is False for c in neg)}

# BUG-08: hosts cortos (acortadores) no deben marcar suplantacion de marca
neg8 = []
for host, reg in [("t.ly", "t.ly"), ("t.is", "t.is"), ("s.id", "s.id"),
                  ("is.gd", "is.gd"), ("ow.ly", "ow.ly")]:
    r = analyze_homoglyphs(host, reg)
    neg8.append({"host": host, "registered": reg, "is_spoofing": r["is_spoofing"],
                 "closest_brand_target": r["closest_brand_target"],
                 "visual_edit_distance": r["visual_edit_distance"]})
from phishguard_ml.homoglyphs import levenshtein_distance  # noqa: E402

out["bug08_shortener_false_positives"] = {
    "cases": neg8,
    "levenshtein_reference": {"lev('t','microsoft')": levenshtein_distance("t", "microsoft"),
                              "lev('googlee','google')": levenshtein_distance("googlee", "google"),
                              "lev('apple','apple')": levenshtein_distance("apple", "apple")},
    "expected_reference": {"lev('t','microsoft')": 8, "lev('googlee','google')": 1,
                           "lev('apple','apple')": 0},
    "PASS": (all(c["is_spoofing"] is False for c in neg8)
             and levenshtein_distance("t", "microsoft") == 8
             and levenshtein_distance("googlee", "google") == 1
             and levenshtein_distance("apple", "apple") == 0),
}


# ---------------------------------------------------------------- BUG-04
def final_action(abstention_threshold: float) -> tuple[str, str]:
    policy = AdaptivePolicy(uncertainty_threshold=0.15, abstention_threshold=abstention_threshold, budget=0.0)
    consulted = ("url", "infrastructure", "content", "visual")
    action, reason, _c, _u = decide_next(0.85, consulted, policy)  # H(0.85) ~= 0.61
    return action, reason


cases = {str(t): final_action(t) for t in (0.01, 0.20, 0.99)}
out["bug04_abstention_threshold"] = {
    "test_probability": 0.85,
    "entropy_at_probability": 0.609837,
    "consulted_all_modalities": True,
    "cases": {k: {"action": v[0], "reason": v[1]} for k, v in cases.items()},
    "decisions_differ_across_thresholds": len({v[0] for v in cases.values()}) > 1,
    "audit_expected": "0.01 -> abstain, 0.99 -> decide (el umbral debe gobernar)",
    "PASS": cases["0.01"][0] == "abstain" and cases["0.99"][0] == "decide",
}

# umbral por defecto de la política validada
policy_default = AdaptivePolicy()
out["bug04_policy_defaults"] = {
    "uncertainty_threshold": policy_default.uncertainty_threshold,
    "abstention_threshold": policy_default.abstention_threshold,
    "distinct": policy_default.uncertainty_threshold != policy_default.abstention_threshold,
}

out["overall_PASS"] = bool(out["bug03_punycode"]["PASS"] and out["bug03_negative_controls"]["PASS"]
                           and out["bug08_shortener_false_positives"]["PASS"]
                           and out["bug04_abstention_threshold"]["PASS"]
                           and out["bug04_policy_defaults"]["distinct"])

dest = ROOT / "artifacts" / "corrections_phase2" / "eval" / "manual_audit_regressions.json"
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(out, indent=2, ensure_ascii=False))
