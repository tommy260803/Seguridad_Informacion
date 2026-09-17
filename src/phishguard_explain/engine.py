from __future__ import annotations

from collections.abc import Iterable

from phishguard_explain.models import EvidenceItem, Explanation


class ExplanationError(ValueError):
    pass


def build_explanation(decision: str, probability_phishing: float, evidence: Iterable[EvidenceItem], *, limit: int = 5) -> Explanation:
    if decision not in {"phishing", "legitimate", "uncertain"}:
        raise ExplanationError("decision must be phishing, legitimate or uncertain")
    if not 0.0 <= probability_phishing <= 1.0 or limit < 1:
        raise ExplanationError("invalid probability or reason limit")
    items = list(evidence)
    if len({item.evidence_id for item in items}) != len(items):
        raise ExplanationError("evidence_id values must be unique")
    ranked = sorted((item for item in items if item.reliable), key=lambda item: (-abs(item.contribution), item.evidence_id))[:limit]
    reasons = tuple({"evidence_id": item.evidence_id, "source": item.source, "feature": item.feature, "value": item.value, "contribution": item.contribution} for item in ranked)
    ids = tuple(item["evidence_id"] for item in reasons)
    if decision == "phishing":
        summary = f"Riesgo de phishing ({probability_phishing:.3f}); se priorizaron {len(reasons)} evidencias trazables."
    elif decision == "legitimate":
        summary = f"Riesgo bajo ({probability_phishing:.3f}); se priorizaron {len(reasons)} evidencias trazables."
    else:
        summary = f"Resultado incierto ({probability_phishing:.3f}); la evidencia no permite una decisión concluyente."
    return Explanation(decision, summary, reasons, ids)
