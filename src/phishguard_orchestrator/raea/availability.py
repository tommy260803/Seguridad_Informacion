from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional
import joblib
import numpy as np

from phishguard_orchestrator.raea.models import RAEAConfig


class AvailabilityEstimator:
    """Predice la probabilidad de disponibilidad exitosa de una modalidad a partir de x0."""

    def __init__(self, model_path: Optional[Path] = None, config: Optional[RAEAConfig] = None):
        self.config = config or RAEAConfig()
        self.model_path = model_path or Path("artifacts/raea/availability_estimator.joblib")
        self.model_data: Optional[Dict[str, Any]] = None
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path.exists():
            try:
                self.model_data = joblib.load(self.model_path)
            except Exception as e:
                self.model_data = None
        else:
            self.model_data = None

    def predict_availability(self, modality: str, x0_features: Dict[str, float]) -> float:
        """
        Retorna pi_m(x0) = P(s_m == success | x0).
        Si la ablación A1 está activa, retorna 1.0 (asume disponibilidad perfecta).
        """
        if not self.config.enable_availability:
            # Ablación A1: sin estimador de disponibilidad (asume 100% como en literatura clásica)
            return 1.0

        mod_key = "infra" if modality in ("network", "infrastructure") else "content" if modality in ("html", "content") else "visual"

        # Para visual, la disponibilidad depende de que el contenido DOM haya sido exitoso
        if mod_key == "visual":
            p_dom = self.predict_availability("html", x0_features)
            return float(max(0.05, p_dom * 0.85))

        if self.model_data and "infra_model" in self.model_data and "content_model" in self.model_data:
            feat_names = self.model_data.get("feature_names", [
                "host_length", "url_length", "host_entropy", "has_ip_host",
                "uses_https", "p_m0", "dot_count", "host_label_count", "subdomain_count"
            ])
            vec = np.array([[float(x0_features.get(k, 0.0)) for k in feat_names]])
            model = self.model_data["infra_model"] if mod_key == "infra" else self.model_data["content_model"]
            try:
                prob = float(model.predict_proba(vec)[0, 1])
                return float(max(0.01, min(0.99, prob)))
            except Exception:
                pass

        # Heurística analítica de respaldo basada en el análisis empírico
        # Si tiene host por IP o no usa HTTPS, la probabilidad de caída/bloqueo es alta
        has_ip = bool(x0_features.get("has_ip_host", 0.0))
        uses_https = bool(x0_features.get("uses_https", 0.0))
        p0 = float(x0_features.get("p_m0", 0.5))

        if mod_key == "infra":
            base = 0.85 if uses_https else 0.55
            if has_ip:
                base -= 0.35
            base -= 0.20 * p0
            return float(max(0.05, min(0.95, base)))
        else: # content
            base = 0.70 if uses_https else 0.40
            if has_ip:
                base -= 0.30
            base -= 0.35 * p0
            return float(max(0.02, min(0.95, base)))
