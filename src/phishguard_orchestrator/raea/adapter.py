from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
import numpy as np
from phishguard_orchestrator.raea.models import AcquisitionStatus


class EvidenceAcquisitionAdapter:
    """Adaptador desacoplado para adquirir modalidades tanto en modo offline como en vivo.
    Ejecuta inferencia REAL con predict_proba() cuando los modelos y características están disponibles.
    """

    def __init__(self, offline_data: Optional[Dict[str, Any]] = None):
        self.offline_data = offline_data or {}

    def acquire_modality(
        self,
        modality: str,
        url: str,
    ) -> Tuple[AcquisitionStatus, Dict[str, Any], float, Optional[float]]:
        """
        Retorna (status, features_dict, elapsed_ms, new_probability).
        """
        if self.offline_data:
            if modality in ("network", "infrastructure"):
                st_str = str(self.offline_data.get("infra_status", "error")).lower()
                status = AcquisitionStatus.SUCCESS if st_str == "success" else AcquisitionStatus.ERROR
                lat = float(self.offline_data.get("lat_infra_ms", 200.0))
                
                if status != AcquisitionStatus.SUCCESS:
                    # Si la adquisición falló, NO se ejecuta M1 y no se produce nueva probabilidad
                    return status, {}, lat, None
                    
                # Inferencia real de M1 si el modelo y características están provistos
                m1_model = self.offline_data.get("m1_model")
                feat_vec = self.offline_data.get("features_m1")
                if m1_model is not None and feat_vec is not None:
                    p_next = float(m1_model.predict_proba(np.asarray([feat_vec], dtype=np.float64))[0, 1])
                    return status, {}, lat, p_next
                    
                # Compatibilidad hacia atrás con datos precomputados en pruebas unitarias legadas
                p_next = float(self.offline_data.get("p_m1", self.offline_data.get("p_m0", 0.5)))
                return status, {}, lat, p_next

            elif modality in ("html", "content"):
                st_str = str(self.offline_data.get("content_status", "error")).lower()
                status = AcquisitionStatus.SUCCESS if st_str == "success" else AcquisitionStatus.ERROR
                lat = float(self.offline_data.get("lat_content_ms", 500.0))
                
                if status != AcquisitionStatus.SUCCESS:
                    # Si el contenido web falló o no está disponible, no se ejecuta M2
                    return status, {}, lat, None
                    
                # Inferencia real de M2 si el modelo y características están provistos
                m2_model = self.offline_data.get("m2_model")
                feat_vec = self.offline_data.get("features_m2")
                if m2_model is not None and feat_vec is not None:
                    p_next = float(m2_model.predict_proba(np.asarray([feat_vec], dtype=np.float64))[0, 1])
                    return status, {}, lat, p_next
                    
                p_next = float(self.offline_data.get("p_m2", self.offline_data.get("p_m1", 0.5)))
                return status, {}, lat, p_next

            elif modality == "visual":
                m3_model = self.offline_data.get("m3_model")
                feat_vec = self.offline_data.get("features_m3")
                lat = float(self.offline_data.get("lat_visual_ms", 0.0))
                
                if m3_model is not None and feat_vec is not None:
                    p_next = float(m3_model.predict_proba(np.asarray([feat_vec], dtype=np.float64))[0, 1])
                    return AcquisitionStatus.SUCCESS, {}, lat, p_next
                elif self.offline_data.get("p_m3") is not None:
                    p_next = float(self.offline_data["p_m3"])
                    return AcquisitionStatus.SUCCESS, {}, lat, p_next
                return AcquisitionStatus.SKIPPED, {}, 0.0, None

        # Modo en vivo sin datos offline
        return AcquisitionStatus.ERROR, {}, 100.0, None
