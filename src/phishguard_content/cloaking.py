"""
Anti-Cloaking and Sandbox Evasion Detection Engine for PhishGuard.
Detects modern phishing evasion tactics (navigator.webdriver checks, fake CAPTCHAs,
delayed DOM payload injection, and crawler fingerprinting).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_WEBDRIVER_PATTERNS = [
    re.compile(r"navigator\.webdriver", re.IGNORECASE),
    re.compile(r"window\.cdc_adoQpoasnfa76pfcZLmcfl", re.IGNORECASE), # Chrome automated driver signature
    re.compile(r"window\.__nightmare", re.IGNORECASE),
    re.compile(r"window\.callPhantom", re.IGNORECASE),
    re.compile(r"_phantom", re.IGNORECASE),
    re.compile(r"navigator\.userAgent\.indexOf\(['\"]Headless", re.IGNORECASE),
]

_FAKE_CHALLENGE_PATTERNS = [
    re.compile(r"checking your browser before accessing", re.IGNORECASE),
    re.compile(r"ddos protection by", re.IGNORECASE),
    re.compile(r"turnstile-fake|fake-challenge|verify_human", re.IGNORECASE),
    re.compile(r"please complete the security check to continue", re.IGNORECASE),
]

_DELAYED_INJECTION_PATTERNS = [
    re.compile(r"setTimeout\s*\([^,]+,\s*[5-9]\d{3,}\)", re.IGNORECASE), # delay >= 5000ms
    re.compile(r"setInterval\s*\([^,]+,\s*[5-9]\d{3,}\)", re.IGNORECASE),
]

class CloakingDetector:
    """Analyzes HTML and JavaScript content for active anti-analysis cloaking mechanisms."""

    def analyze_content(self, html_content: str | bytes) -> Dict[str, Any]:
        if isinstance(html_content, bytes):
            text = html_content.decode("utf-8", errors="ignore")
        else:
            text = html_content or ""

        detected_techniques: List[str] = []
        score = 0.0

        # 1. Check for anti-headless/webdriver checks
        for pat in _WEBDRIVER_PATTERNS:
            if pat.search(text):
                detected_techniques.append("anti_crawler_webdriver_detection")
                score += 0.40
                break

        # 2. Check for fake interstitial challenges
        for pat in _FAKE_CHALLENGE_PATTERNS:
            if pat.search(text):
                detected_techniques.append("fake_security_challenge_interstitial")
                score += 0.35
                break

        # 3. Check for delayed DOM injection (evading fast automated sandboxes)
        for pat in _DELAYED_INJECTION_PATTERNS:
            if pat.search(text):
                detected_techniques.append("delayed_dom_payload_injection")
                score += 0.25
                break

        # 4. Check for obfuscated eval/atob unpacking
        if "eval(atob(" in text or "eval(unescape(" in text:
            detected_techniques.append("obfuscated_payload_eval_unpacking")
            score += 0.30

        is_cloaked = score >= 0.40
        return {
            "cloaking_detected": float(is_cloaked),
            "cloaking_score": min(1.0, float(score)),
            "detected_techniques": detected_techniques,
            "evasion_risk": "HIGH" if score >= 0.60 else ("MEDIUM" if is_cloaked else "LOW")
        }

# Global singleton
cloaking_detector = CloakingDetector()
