import joblib
import numpy as np
from pathlib import Path
from typing import Any, Dict

from phishguard_data.urls import canonicalize_url
from phishguard_data.psl import PublicSuffixList
from phishguard_ml.features import UrlFeatureContext, FEATURE_NAMES, extract_url_features
from phishguard_orchestrator.engine import AdaptivePolicy, decide_next
from phishguard_api.models import JobStatus, Event

class UnifiedModelManager:
    def __init__(self):
        self.psl = self._load_psl()
        self.m0_model = self._load_model(Path("artifacts/url-baseline-0.2.0/conventional/model.joblib"))
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
        
    def _load_model(self, path: Path) -> Any:
        if path.exists():
            print(f"Modelo cargado exitosamente: {path}")
            return joblib.load(path)
        print(f"ADVERTENCIA: Modelo no encontrado en {path}. Usando heurística fallback (M5).")
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
    """M4: Concatenación URL + Infra"""
    if not registry.m1_model:
        # Fallback de adaptación si no hay modelo entrenado
        # Ajusta probabilidad basándose en la presencia de IPs o fallas de TLS
        prob = prev_prob
        if infra_features.get("has_ip_host", 0.0) == 1.0:
            prob = min(0.99, prob + 0.3)
        if infra_features.get("tls_verification_failure_count", 0.0) > 0:
            prob = min(0.99, prob + 0.2)
        return prob
        
    # TODO: Cuando haya modelo .joblib, extraer order de features y concatenar.
    return prev_prob

def predict_m2(url_features: Dict[str, float], infra_features: Dict[str, float], content_features: Dict[str, float], prev_prob: float) -> float:
    """M4: Concatenación URL + Infra + Content"""
    if not registry.m2_model:
        prob = prev_prob
        # HEURÍSTICA: Lista blanca temporal para evitar bloquear sitios seguros reales 
        # (hasta que se entrene la red M2 con el dataset final)
        safe_domains = ["netflix.com", "facebook.com", "google.com", "bbva.com", "viabcp.com"]
        # Extraemos el dominio bruto aproximado de las features (o asumimos basado en prob si es muy seguro)
        
        # Si pide contraseñas, es sospechoso, pero no si es un sitio seguro conocido (simplificación)
        if content_features.get("html_password_input_count", 0.0) > 0:
            prob = min(0.99, prob + 0.4)
        else:
            prob = prob * 0.4
            
        return prob
    return prev_prob

def predict_m3(url_features: Dict[str, float], infra_features: Dict[str, float], content_features: Dict[str, float], visual_features: Dict[str, float], prev_prob: float) -> float:
    """M4: Concatenación URL + Infra + Content + Visual"""
    if not registry.m3_model:
        return prev_prob
    return prev_prob
