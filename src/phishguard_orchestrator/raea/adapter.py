from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from phishguard_orchestrator.raea.models import AcquisitionStatus


class EvidenceAcquisitionAdapter:
    """Adaptador desacoplado para adquirir modalidades tanto en modo offline como en vivo."""

    def __init__(self, offline_data: Optional[Dict[str, Any]] = None):
        self.offline_data = offline_data or {}

    def acquire_modality(
        self,
        modality: str,
        url: str,
    ) -> Tuple[AcquisitionStatus, Dict[str, Any], float, float]:
        """
        Retorna (status, features_dict, elapsed_ms, new_probability).
        """
        # Si disponemos de datos offline precomputados
        if self.offline_data:
            if modality == "network":
                st_str = self.offline_data.get("infra_status", "error")
                status = AcquisitionStatus(st_str) if st_str in AcquisitionStatus._value2member_map_ else AcquisitionStatus.ERROR
                p_next = float(self.offline_data.get("p_m1", self.offline_data.get("p_m0", 0.5)))
                lat = float(self.offline_data.get("lat_infra_ms", 200.0))
                return status, {}, lat, p_next
            elif modality == "html":
                st_str = self.offline_data.get("content_status", "error")
                status = AcquisitionStatus(st_str) if st_str in AcquisitionStatus._value2member_map_ else AcquisitionStatus.ERROR
                p_next = float(self.offline_data.get("p_m2", self.offline_data.get("p_m1", 0.5)))
                lat = float(self.offline_data.get("lat_content_ms", 500.0))
                return status, {}, lat, p_next
            elif modality == "visual":
                p_next = float(self.offline_data.get("p_m3", self.offline_data.get("p_m2", 0.5)))
                return AcquisitionStatus.SUCCESS, {}, 1800.0, p_next

        # En modo en vivo sin datos offline
        return AcquisitionStatus.ERROR, {}, 100.0, 0.5
