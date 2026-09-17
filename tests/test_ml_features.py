import numpy as np

from phishguard_ml.features import FEATURE_NAMES, UrlFeatureContext, extract_url_features, feature_matrix


def test_extract_url_features_records_structural_signals() -> None:
    features = extract_url_features(
        UrlFeatureContext(
            "http://brand.example@xn--exmple-cua.com:8080/login/verify.php?a=1&b=",
            "xn--exmple-cua.com",
        )
    )

    assert tuple(features) == FEATURE_NAMES
    assert features["has_userinfo"] == 1.0
    assert features["has_nondefault_port"] == 1.0
    assert features["has_punycode"] == 1.0
    assert features["query_parameter_count"] == 2.0
    assert features["suspicious_token_count"] >= 2.0
    assert features["path_has_file_extension"] == 1.0


def test_feature_matrix_is_finite_and_stable() -> None:
    rows = [
        UrlFeatureContext("https://example.com/", "example.com"),
        UrlFeatureContext("http://192.0.2.1/a?x=1", "192.0.2.1"),
    ]

    first = feature_matrix(rows)
    second = feature_matrix(rows)

    assert first.shape == (2, len(FEATURE_NAMES))
    assert np.array_equal(first, second)
    assert np.isfinite(first).all()
