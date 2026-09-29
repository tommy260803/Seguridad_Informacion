"""
Commercial Threat Intelligence Baseline Connector (Google Safe Browsing & Feeds).
Provides comparative benchmarking against industry-standard threat feeds.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional
import httpx

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

class GoogleSafeBrowsingClient:
    """Client for Google Safe Browsing API v4 with deterministic fallback."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GSB_API_KEY")
        self.client_id = "PhishGuard-Research"
        self.client_version = "1.0.0"

    async def lookup(self, url: str, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Check if URL is flagged by Google Safe Browsing.
        Returns standardized result dict with match status, threat types, and response latency.
        """
        start = time.perf_counter()

        if not self.api_key:
            # Deterministic heuristic baseline when no commercial API key is provided
            elapsed = (time.perf_counter() - start) * 1000
            # Common suspicious heuristics for simulation
            is_suspicious = any(token in url.lower() for token in [
                "-login", "-verify", "paypal.com-", "secure-account", "update-bank"
            ])
            return {
                "provider": "google_safe_browsing_simulated",
                "is_malicious": is_suspicious,
                "threat_types": ["SOCIAL_ENGINEERING"] if is_suspicious else [],
                "latency_ms": elapsed,
                "status": "simulated_success",
                "api_key_configured": False
            }

        payload = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{GSB_ENDPOINT}?key={self.api_key}",
                    json=payload
                )
                elapsed = (time.perf_counter() - start) * 1000

                if response.status_code == 200:
                    data = response.json()
                    matches = data.get("matches", [])
                    threat_types = [m.get("threatType") for m in matches if "threatType" in m]
                    return {
                        "provider": "google_safe_browsing",
                        "is_malicious": len(matches) > 0,
                        "threat_types": threat_types,
                        "latency_ms": elapsed,
                        "status": "success",
                        "api_key_configured": True
                    }
                else:
                    return {
                        "provider": "google_safe_browsing",
                        "is_malicious": False,
                        "threat_types": [],
                        "latency_ms": elapsed,
                        "status": f"http_error_{response.status_code}",
                        "api_key_configured": True
                    }
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return {
                "provider": "google_safe_browsing",
                "is_malicious": False,
                "threat_types": [],
                "latency_ms": elapsed,
                "status": f"error: {str(exc)[:100]}",
                "api_key_configured": True
            }

# Global singleton
gsb_client = GoogleSafeBrowsingClient()
