import joblib
import numpy as np
from pathlib import Path
from typing import Any, Dict

from phishguard_data.urls import canonicalize_url
from phishguard_data.psl import PublicSuffixList
from phishguard_ml.features import UrlFeatureContext, FEATURE_NAMES, FEATURE_PROFILES, extract_url_features
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features
from phishguard_ml.visual import VISUAL_FEATURE_NAMES, extract_visual_features
from phishguard_orchestrator.engine import AdaptivePolicy, decide_next
from phishguard_api.models import JobStatus, Event

_AUTHORITY_ONLY = list(FEATURE_PROFILES["authority_only"])

class UnifiedModelManager:
    def __init__(self):
        self.psl = self._load_psl()
        self.m0_model = self._load_model([
            Path("artifacts/url-baseline-0.2.0/model.joblib"),
            Path("artifacts/url-baseline-0.2.0/conventional/model.joblib")
        ])
        self.m1_model = self._load_model(Path("artifacts/m1-baseline/model.joblib"))
        self.m2_model = self._load_model(Path("artifacts/m2-baseline/model.joblib"))
        self.m3_model = self._load_model(Path("artifacts/m3-baseline/model.joblib"))
        
    def _load_psl(self) -> PublicSuffixList:
        psl_paths = list(Path("data/raw").rglob("public_suffix_list.dat"))
        if not psl_paths:
            print("WARNING: No public_suffix_list.dat found. URL canonicalization may fail.")
            return None
        latest_psl = sorted(psl_paths)[-1]
        print(f"Cargando PSL desde: {latest_psl}")
        return PublicSuffixList.from_file(latest_psl)
        
    def _load_model(self, paths: Path | list[Path]) -> Any:
        candidate_paths = [paths] if isinstance(paths, Path) else paths
        for path in candidate_paths:
            if path.exists():
                print(f"Modelo cargado exitosamente: {path}")
                return joblib.load(path)
        print(f"ADVERTENCIA: Modelo no encontrado en {candidate_paths}. Usando heurística fallback (M5).")
        return None

# Instancia global
registry = UnifiedModelManager()

def _extract_url_base_features(url: str) -> Dict[str, float]:
    if not registry.psl:
        raise ValueError("PSL no está cargado")
    canonical = canonicalize_url(url, psl=registry.psl)
    context = UrlFeatureContext(canonical_url=canonical.value, registered_domain=canonical.registered_domain)
    features = extract_url_features(context)
    # Descontar prefijo 'www.' para no penalizar dominios web estándar
    host_labels = canonical.value.split("://", 1)[-1].split("/", 1)[0].split(":")[0].split(".")
    if len(host_labels) > 2 and host_labels[0].lower() == "www":
        features["subdomain_count"] = max(0.0, features["subdomain_count"] - 1.0)
        features["host_label_count"] = max(2.0, features["host_label_count"] - 1.0)
    return features

def predict_m0(url: str) -> float:
    """Extrae características de la URL y predice con M0"""
    if not registry.m0_model:
        return 0.5
    features = _extract_url_base_features(url)
    feature_names = registry.m0_model.get("feature_names", FEATURE_NAMES)
    feature_array = np.array([[features[name] for name in feature_names]])
    model = registry.m0_model["model"]
    prob = float(model.predict_proba(feature_array)[0][1])
    return prob

def predict_m1(url_features: Dict[str, float], infra_features: Dict[str, float], prev_prob: float) -> float:
    """M1: Concatenación URL authority_only + Infra"""
    if not registry.m1_model:
        prob = prev_prob
        if infra_features.get("has_ip_host", 0.0) == 1.0:
            prob = min(0.99, prob + 0.3)
        if infra_features.get("tls_verification_failure_count", 0.0) > 0:
            prob = min(0.99, prob + 0.2)
        return prob
    feature_names = registry.m1_model["feature_names"]
    url_part = [url_features.get(name, 0.0) for name in _AUTHORITY_ONLY]
    infra_part = [infra_features.get(name, 0.0) for name in INFRA_FEATURE_NAMES]
    feature_array = np.array([url_part + infra_part])
    model = registry.m1_model["model"]
    threshold = registry.m1_model.get("threshold", 0.5)
    prob = float(model.predict_proba(feature_array)[0][1])
    return prob

def predict_m2(url_features: Dict[str, float], infra_features: Dict[str, float], content_features: Dict[str, float], prev_prob: float) -> float:
    """M2: Concatenación URL authority_only + Infra + Content"""
    if not registry.m2_model:
        prob = prev_prob
        if content_features.get("html_password_input_count", 0.0) > 0:
            prob = min(0.99, prob + 0.4)
        else:
            prob = prob * 0.4
        return prob
    url_part = [url_features.get(name, 0.0) for name in _AUTHORITY_ONLY]
    infra_part = [infra_features.get(name, 0.0) for name in INFRA_FEATURE_NAMES]
    content_part = [content_features.get(name, 0.0) for name in CONTENT_FEATURE_NAMES]
    feature_array = np.array([url_part + infra_part + content_part])
    model = registry.m2_model["model"]
    prob = float(model.predict_proba(feature_array)[0][1])
    return prob

def predict_m3(url_features: Dict[str, float], infra_features: Dict[str, float], content_features: Dict[str, float], visual_features: Dict[str, float], prev_prob: float) -> float:
    """M3: Concatenación URL authority_only + Infra + Content + Visual"""
    if not registry.m3_model:
        return prev_prob
    url_part = [url_features.get(name, 0.0) for name in _AUTHORITY_ONLY]
    infra_part = [infra_features.get(name, 0.0) for name in INFRA_FEATURE_NAMES]
    content_part = [content_features.get(name, 0.0) for name in CONTENT_FEATURE_NAMES]
    visual_part = [visual_features.get(name, 0.0) for name in VISUAL_FEATURE_NAMES]
    feature_array = np.array([url_part + infra_part + content_part + visual_part])
    model = registry.m3_model["model"]
    prob = float(model.predict_proba(feature_array)[0][1])
    return prob
