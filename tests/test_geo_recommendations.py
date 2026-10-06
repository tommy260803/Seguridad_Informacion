import pytest
from phishguard_ml.detection_rules import (
    DetectionRules,
    get_geo_context,
    find_local_brand_suggestions,
    analyze_url_rules,
)
from phishguard_ml.hybrid_model import predict_hybrid


def test_bcp_foreign_and_local_recommendation():
    """bcp.com should indicate foreign server and recommend viabcp.com for Peruvian users."""
    suggestions = find_local_brand_suggestions("bcp.com", user_country="PE")
    assert len(suggestions) > 0
    assert suggestions[0]["suggested_domain"] == "viabcp.com"
    assert "Banco de Credito del Peru" in suggestions[0]["brand_name"]


def test_viabcp_official_no_self_suggestion():
    """When on viabcp.com, no suggestion should be made to Peruvians."""
    suggestions = find_local_brand_suggestions("viabcp.com", user_country="PE")
    assert len(suggestions) == 0


def test_multi_country_brand_suggestion():
    """bbva.mx visited by Peruvian user should suggest bbva.pe."""
    suggestions = find_local_brand_suggestions("bbva.mx", user_country="PE")
    assert len(suggestions) > 0
    assert any(s["suggested_domain"] == "bbva.pe" for s in suggestions)


def test_chile_brand_suggestion():
    """bci.com visited by Chilean user should suggest bci.cl."""
    suggestions = find_local_brand_suggestions("bci.com", user_country="CL")
    assert len(suggestions) > 0
    assert suggestions[0]["suggested_domain"] == "bci.cl"


def test_hybrid_prediction_includes_geo_and_suggestions():
    """Hybrid model predict should return geo_context and local_suggestions."""
    res = predict_hybrid("https://bcp.com", user_country="PE")
    assert "geo_context" in res
    assert "local_suggestions" in res
    assert res["geo_context"]["is_foreign"] is True
    assert res["decision"] == "warning"
    assert any(s["suggested_domain"] == "viabcp.com" for s in res["local_suggestions"])
