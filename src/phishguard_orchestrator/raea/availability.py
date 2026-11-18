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
        self.model_path = model_path
        self.model_data: Optional[Dict[str, Any]] = None
        self._load_model()

    def _load_model(self) -> None:
        candidate_paths = []
        if self.model_path is not None:
            candidate_paths.append(Path(self.model_path))
        
        here = Path(__file__).resolve()
        candidate_paths.extend([
            Path("MODELOS/AVAILABILITY/availability_estimator.joblib"),
            Path("MODELOS/AVAILABILITY/model.joblib"),
            Path("artifacts/raea/availability_estimator.joblib"),
            Path("artifacts/models_reproduced/availability_estimator.joblib"),
            Path("04_MODELOS/availability/availability_estimator.joblib"),
            here.parents[2] / "MODELOS" / "AVAILABILITY" / "availability_estimator.joblib",
            here.parents[3] / "MODELOS" / "AVAILABILITY" / "availability_estimator.joblib",
            here.parents[4] / "MODELOS" / "AVAILABILITY" / "availability_estimator.joblib",
            here.parents[2] / "artifacts" / "raea" / "availability_estimator.joblib",
            here.parents[3] / "artifacts" / "raea" / "availability_estimator.joblib",
            here.parents[4] / "artifacts" / "raea" / "availability_estimator.joblib",
            here.parents[2] / "04_MODELOS" / "availability" / "availability_estimator.joblib",
            here.parents[3] / "04_MODELOS" / "availability" / "availability_estimator.joblib",
            here.parents[4] / "04_MODELOS" / "availability" / "availability_estimator.joblib",
        ])

        for p in candidate_paths:
            if p.exists():
                try:
                    self.model_data = joblib.load(p)
                    self.model_path = p
                    break
                except Exception:
                    continue

    def predict_availability(self, modality: str, x0_features: Dict[str, float]) -> float:
        """
        Retorna pi_m(x0) = P(s_m == success | x0).
        Si la ablación A1 está activa, retorna 1.0 (asume disponibilidad perfecta).
        """
        if not self.config.enable_availability:
            # Ablación A1: sin estimador de disponibilidad (asume 100% como en literatura clásica)
            return 1.0

        mod_key = "infra" if modality in ("network", "infrastructure") else "content" if modality in ("html", "content") else "visual"

        # Si se solicita usar la tasa marginal constante empírica (Baseline A_const)
        if getattr(self.config, "constant_availability_rates", None) is not None:
            rates = self.config.constant_availability_rates
            return float(rates.get(mod_key, 0.5))

        # Para visual, la disponibilidad depende de que el contenido DOM haya sido exitoso
        if mod_key == "visual":
            p_dom = self.predict_availability("html", x0_features)
            return float(max(0.05, p_dom * 0.85))

        if self.model_data and "infra_model" in self.model_data and "content_model" in self.model_data:
            feat_names = self.model_data.get("feature_names", [
                "host_length", "url_length", "host_entropy", "has_ip_host",
                "uses_https", "p_m0", "dot_count", "host_label_count", "subdomain_count"
            ])
            # Valores por defecto para URLs típicas cuando el llamador pasa características parciales
            feat_defaults = {
                "host_length": 18.0,
                "url_length": 45.0,
                "host_entropy": 3.2,
                "has_ip_host": 0.0,
                "uses_https": 1.0,
                "p_m0": float(x0_features.get("p_m0", 0.5)),
                "dot_count": 2.0,
                "host_label_count": 2.0,
                "subdomain_count": 0.0,
            }
            vec = np.array([[float(x0_features.get(k, feat_defaults.get(k, 0.0))) for k in feat_names]])
            model = self.model_data["infra_model"] if mod_key == "infra" else self.model_data["content_model"]
            try:
                prob = float(model.predict_proba(vec)[0, 1])
                return float(max(0.01, min(0.99, prob)))
            except Exception:
                pass

        # Heurística analítica de respaldo basada en el análisis empírico
        # Si tiene host por IP o no usa HTTPS, se ajusta la estimación previa sin bloquear la adquisición de red
        has_ip = bool(x0_features.get("has_ip_host", 0.0))
        uses_https = bool(x0_features.get("uses_https", 0.0))
        p0 = float(x0_features.get("p_m0", 0.5))

        if mod_key == "infra":
            base = 0.88 if uses_https else 0.72
            if has_ip:
                base -= 0.15
            base -= 0.15 * p0
            return float(max(0.10, min(0.95, base)))
        else: # content
            base = 0.75 if uses_https else 0.50
            if has_ip:
                base -= 0.20
            base -= 0.25 * p0
            return float(max(0.05, min(0.95, base)))
