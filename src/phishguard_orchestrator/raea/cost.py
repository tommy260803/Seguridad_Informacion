from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from phishguard_orchestrator.raea.models import RAEAConfig


class AcquisitionCostEstimator:
    """Calcula el coste esperado ponderado por disponibilidad para cada modalidad."""

    def __init__(self, params_path: Optional[Path] = None, config: Optional[RAEAConfig] = None):
        self.config = config or RAEAConfig()
        self.params_path = params_path or Path("artifacts/raea/cost_parameters.json")
        self.cost_params = self._load_params()

    def _load_params(self) -> Dict[str, Any]:
        default_params = {
            "infrastructure": {
                "c_succ_ms": 1509.1,
                "c_fail_ms": 1180.2,
                "normalized_cost_succ": 0.20,
                "normalized_cost_fail": 0.80,
            },
            "content": {
                "c_succ_ms": 1957.1,
                "c_fail_ms": 1005.0,
                "normalized_cost_succ": 0.50,
                "normalized_cost_fail": 1.20,
            },
            "visual": {
                "c_succ_ms": 1782.4,
                "c_fail_ms": 2510.0,
                "normalized_cost_succ": 1.50,
                "normalized_cost_fail": 2.50,
            },
        }
        if self.params_path.exists():
            try:
                with open(self.params_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return default_params
        return default_params

    def estimate_cost(self, modality: str, availability: float) -> float:
        """
        Calcula el coste normalizado esperado E[C(m) | x0] dado pi_m(x0).
        """
        mod_key = "infrastructure" if modality in ("network", "infrastructure") else "content" if modality in ("html", "content") else "visual"
        params = self.cost_params.get(mod_key, {
            "normalized_cost_succ": 0.5,
            "normalized_cost_fail": 1.0,
        })
        c_succ = params.get("normalized_cost_succ", 0.5)
        c_fail = params.get("normalized_cost_fail", 1.0)

        expected_cost = availability * c_succ + (1.0 - availability) * c_fail
        return float(expected_cost)
