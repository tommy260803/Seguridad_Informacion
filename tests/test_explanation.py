import pytest

from phishguard_explain.engine import ExplanationError, build_explanation
from phishguard_explain.models import EvidenceItem


def test_explanation_ranks_reliable_evidence_and_keeps_references() -> None:
    explanation = build_explanation("phishing", 0.91, [
        EvidenceItem("e2", "content", "password_inputs", 2, 0.8),
        EvidenceItem("e1", "url", "punycode", 1, 0.9),
        EvidenceItem("e3", "visual", "edge_density", 0.1, 0.99, reliable=False),
    ])
    assert explanation.evidence_ids == ("e1", "e2")
    assert explanation.reasons[0]["source"] == "url"
    assert "0.910" in explanation.summary


def test_explanation_rejects_duplicate_ids_or_unknown_decisions() -> None:
    item = EvidenceItem("same", "url", "length", 20, 0.1)
    with pytest.raises(ExplanationError):
        build_explanation("maybe", 0.5, [item])
    with pytest.raises(ExplanationError):
        build_explanation("uncertain", 0.5, [item, item])
