"""
Hybrid M0+Brand+Rules Model
Combines the existing M0 lexical model with brand impersonation detection and advanced rules.
"""
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any

from phishguard_ml.brand_features import extract_brand_features, PHISHING_TARGET_BRANDS
from phishguard_ml.detection_rules import analyze_url_rules
from phishguard_ml.features import UrlFeatureContext, FEATURE_NAMES, FEATURE_PROFILES, extract_url_features
from phishguard_data.urls import canonicalize_url
from phishguard_data.psl import PublicSuffixList

# Build set of known brand names from PHISHING_TARGET_BRANDS keys
# These are official brand names (facebook, bbva, santander, etc.)
_KNOWN_BRAND_NAMES = set(PHISHING_TARGET_BRANDS.keys())

# Also load brand names from brand-country-map.json config
try:
    import json as _json
    from pathlib import Path as _Path
    _config_path = _Path("configs/brand-country-map.json")
    if _config_path.exists():
        with open(_config_path) as _f:
            _config = _json.load(_f)
        for _country_brands in _config.get("brands", {}).values():
            for _brand_key, _brand_data in _country_brands.items():
                _ld = _brand_data.get("local_domain", "")
                _name = _ld.replace("www.", "").split(".")[0].lower()
                if _name and len(_name) >= 2:
                    _KNOWN_BRAND_NAMES.add(_name)
except Exception:
    pass


class HybridM0Model:
    """
    Hybrid model combining M0 lexical analysis with brand impersonation and rules.
    
    Architecture:
    - M0 (existing): Lexical features only (11 features, authority_only profile)
    - Brand Module: Levenshtein/Jaro similarity for typosquatting detection
    - Rules Module: Pattern-based detection for various attack vectors
    - Decision: Weighted combination of all three
    """
    
    def __init__(self):
        self.m0_model = self._load_m0()
        self.psl = self._load_psl()
        
    def _load_m0(self) -> Dict[str, Any]:
        """Load the existing M0 model."""
        m0_path = Path("artifacts/url-baseline-0.2.0/conventional/model.joblib")
        if m0_path.exists():
            print(f"Loading M0 model from {m0_path}")
            return joblib.load(m0_path)
        print(f"WARNING: M0 model not found at {m0_path}")
        return None
    
    def _load_psl(self) -> PublicSuffixList:
        """Load Public Suffix List for URL canonicalization."""
        psl_paths = list(Path("data/raw").rglob("public_suffix_list.dat"))
        if not psl_paths:
            print("WARNING: No public_suffix_list.dat found")
            return None
        latest_psl = sorted(psl_paths)[-1]
        return PublicSuffixList.from_file(latest_psl)
    
    def predict(self, url: str, user_country: str = "") -> Dict[str, Any]:
        """
        Predict phishing probability using hybrid approach.
        
        Returns:
            Dict with keys:
            - probability: float (0-1)
            - decision: 'phishing' or 'legitimate'
            - m0_probability: M0 model probability
            - brand_analysis: dict with brand detection results
            - rules_analysis: dict with rules results
            - model: 'M0+Brand+Rules'
        """
        # 1. Get M0 prediction
        m0_prob = self._predict_m0(url)
        
        # 2. Get brand analysis
        try:
            parsed = __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            brand_features = extract_brand_features(hostname)
        except Exception as e:
            brand_features = {
                "min_brand_distance": 999,
                "closest_brand": "",
                "brand_similarity": 0.0,
                "is_brand_impersonation": 0,
                "typosquatting_score": 0.0
            }
        
        # 3. Get rules analysis
        try:
            rules_analysis = analyze_url_rules(url, user_country=user_country)
            rules_score = rules_analysis["aggregate_score"]
        except Exception as e:
            rules_analysis = {"aggregate_score": 0.0, "triggered_rules": []}
            rules_score = 0.0
        
        # 4. Check for high-signal new rules (ccTLD, geolocation, domain age, financial)
        high_signal_rules = {"country_code_tld", "server_geolocation", "domain_age"}
        triggered_high_signal = [
            r for r in rules_analysis.get("triggered_rules", [])
            if r.get("rule") in high_signal_rules
        ]
        high_signal_boost = sum(r.get("confidence", 0) for r in triggered_high_signal) * 0.3
        
        # Financial-specific boost (actual phishing signals only)
        financial_rules = {"financial_phishing"}
        triggered_financial = [
            r for r in rules_analysis.get("triggered_rules", [])
            if r.get("rule") in financial_rules
        ]
        financial_boost = sum(r.get("confidence", 0) for r in triggered_financial) * 0.4
        
        # Brand-country mismatch is INFO only (not a phishing signal)
        brand_mismatch = next(
            (r for r in rules_analysis.get("all_rules", []) if r.get("rule") == "brand_country_mismatch"),
            None
        )
        
        # 5. Combine predictions using intelligent fusion
        brand_score = brand_features["typosquatting_score"] if brand_features["is_brand_impersonation"] else 0.0
        
        # Financial phishing takes highest priority
        if financial_boost > 0.5:
            final_prob = max(0.7 * financial_boost + 0.3 * m0_prob, m0_prob)
        elif brand_features["is_brand_impersonation"] and brand_score > 0.7:
            # High-confidence brand impersonation: override M0
            final_prob = max(brand_score * 0.95, m0_prob)
        elif brand_features["is_brand_impersonation"]:
            # Medium-confidence brand impersonation: blend with higher weight
            final_prob = 0.3 * m0_prob + 0.7 * brand_score
        elif rules_score > 0.5 or high_signal_boost > 0.3:
            # High rules score OR high-signal rules triggered: boost probability
            final_prob = max(0.5 * m0_prob + 0.5 * rules_score + high_signal_boost + financial_boost, m0_prob)
        else:
            # Default: weighted average with financial boost
            final_prob = 0.6 * m0_prob + 0.25 * brand_score + 0.15 * rules_score + high_signal_boost + financial_boost
        
        # Ensure probability is in valid range
        final_prob = max(0.0, min(1.0, final_prob))
        
        decision = "phishing" if final_prob >= 0.5 else "legitimate"
        
        # EXACT BRAND MATCH OVERRIDE: if hostname (without TLD) is a known brand name,
        # force decision to legitimate. Prevents M0 from flagging real brand domains.
        try:
            from urllib.parse import urlsplit
            parsed_url = urlsplit(url)
            host = (parsed_url.hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
            domain_parts = host.split(".")
            domain_name = domain_parts[0] if domain_parts else ""
            if domain_name in _KNOWN_BRAND_NAMES:
                decision = "legitimate"
                final_prob = min(final_prob, 0.45)
        except Exception:
            pass
        
        return {
            "probability": round(final_prob, 6),
            "decision": decision,
            "m0_probability": round(m0_prob, 6),
            "brand_analysis": brand_features if brand_features["is_brand_impersonation"] else None,
            "brand_mismatch": brand_mismatch.get("details") if brand_mismatch and brand_mismatch.get("triggered") and brand_mismatch.get("details") else None,
            "rules_analysis": rules_analysis,
            "model": "M0+Brand+Rules"
        }
    
    def _predict_m0(self, url: str) -> float:
        """Get M0 model prediction."""
        if not self.m0_model or not self.psl:
            return 0.5
        
        try:
            canonical = canonicalize_url(url, psl=self.psl)
            context = UrlFeatureContext(
                canonical_url=canonical.value, 
                registered_domain=canonical.registered_domain
            )
            features = extract_url_features(context)
            
            # Adjust for www subdomain
            host_labels = canonical.value.split("://", 1)[-1].split("/", 1)[0].split(":")[0].split(".")
            if len(host_labels) > 2 and host_labels[0].lower() == "www":
                features["subdomain_count"] = max(0.0, features["subdomain_count"] - 1.0)
                features["host_label_count"] = max(2.0, features["host_label_count"] - 1.0)
            
            # Extract features using M0's feature names
            feature_names = self.m0_model.get("feature_names", list(FEATURE_PROFILES["authority_only"]))
            feature_array = np.array([[features.get(name, 0.0) for name in feature_names]])
            
            model = self.m0_model["model"]
            prob = float(model.predict_proba(feature_array)[0][1])
            return prob
        except Exception as e:
            print(f"M0 prediction error: {e}")
            return 0.5


# Singleton instance
hybrid_model = HybridM0Model()


def predict_hybrid(url: str, user_country: str = "") -> Dict[str, Any]:
    """Public API for hybrid prediction."""
    return hybrid_model.predict(url, user_country=user_country)


if __name__ == "__main__":
    # Test
    test_urls = [
        "https://www.facebuuk.com/",
        "https://www.facebook.com/",
        "https://www.gogle.com/",
        "https://www.google.com/",
        "https://secure-login.facebook.com.verify.tk/account",
        "http://192.168.1.1/login",
        "https://stikes-mangtap.web.app/",
    ]
    
    for url in test_urls:
        result = predict_hybrid(url)
        print(f"{url:55} -> {result['decision']:10} ({result['probability']:.1%})")
        if result['brand_analysis']:
            print(f"  Brand: {result['brand_analysis']['closest_brand']}")
        if result['rules_analysis']:
            print(f"  Rules: {result['rules_analysis']['summary']}")
