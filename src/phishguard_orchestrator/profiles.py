"""
SLA-Aware Inspection Profiles for PhishGuard Adaptive Orchestrator.
Allows client applications to balance latency constraints against inspection depth.
"""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any

from phishguard_orchestrator.engine import AdaptivePolicy

class InspectionProfile(str, Enum):
    """Supported operation modes based on operational SLA constraints."""
    REAL_TIME_BROWSER = "real_time_browser"     # SLA <= 5ms: Max speed, M0 + Bloom, edge browser extensions
    ENTERPRISE_GATEWAY = "enterprise_gateway"   # SLA ~ 30ms: Balanced adaptive cascade for firewalls/proxies
    DEEP_FORENSIC = "deep_forensic"             # SLA ~ 1.2s: Exhaustive inspection (M0-M3 + LLM) for SOCs

@dataclass(frozen=True)
class ProfileConfig:
    profile: InspectionProfile
    target_sla_ms: float
    policy: AdaptivePolicy
    description: str

_PROFILE_REGISTRY: Dict[InspectionProfile, ProfileConfig] = {
    InspectionProfile.REAL_TIME_BROWSER: ProfileConfig(
        profile=InspectionProfile.REAL_TIME_BROWSER,
        target_sla_ms=5.0,
        policy=AdaptivePolicy(
            budget=0.0,
            minimum_confidence=0.75,
            uncertainty_threshold=0.25
        ),
        description="Ultra-low latency profile for client-side web extensions (SLA <= 5ms)"
    ),
    InspectionProfile.ENTERPRISE_GATEWAY: ProfileConfig(
        profile=InspectionProfile.ENTERPRISE_GATEWAY,
        target_sla_ms=35.0,
        policy=AdaptivePolicy(
            budget=2.0,
            minimum_confidence=0.85,
            uncertainty_threshold=0.15
        ),
        description="Standard balanced adaptive cascade for network security gateways (SLA ~ 35ms)"
    ),
    InspectionProfile.DEEP_FORENSIC: ProfileConfig(
        profile=InspectionProfile.DEEP_FORENSIC,
        target_sla_ms=1500.0,
        policy=AdaptivePolicy(
            budget=3.0,
            minimum_confidence=0.999,
            uncertainty_threshold=0.001
        ),
        description="Exhaustive forensic audit mode forcing all modalities for SOC incident response (SLA ~ 1.5s)"
    ),
}

def get_profile_config(profile: str | InspectionProfile = InspectionProfile.ENTERPRISE_GATEWAY) -> ProfileConfig:
    """Retrieve profile configuration with fallback to enterprise gateway."""
    if isinstance(profile, str):
        try:
            profile = InspectionProfile(profile.lower())
        except ValueError:
            profile = InspectionProfile.ENTERPRISE_GATEWAY
    return _PROFILE_REGISTRY.get(profile, _PROFILE_REGISTRY[InspectionProfile.ENTERPRISE_GATEWAY])
