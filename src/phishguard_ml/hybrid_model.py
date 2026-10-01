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
from phishguard_ml.homoglyphs import analyze_homoglyphs
from phishguard_data.reputation import get_reputation
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
        # 1. Get Global Tranco Reputation & Canonical Domain
        rep = get_reputation(url, psl=self.psl)
        host = rep["host"]
        reg_domain = rep["registered_domain"]
        tranco_rank = rep["tranco_rank"]
        trust_score = rep["trust_score"]
        is_user_hosting = rep["is_user_hosting"]

        # 2. Get Homoglyph / Punycode Confusable analysis
        try:
            homoglyphs_data = analyze_homoglyphs(host, reg_domain)
        except Exception:
            homoglyphs_data = {"is_spoofing": False, "target_brand": "none", "visual_skeleton": host}

        # 3. Get M0 lexical prediction
        m0_prob = self._predict_m0(url)
        
        # 4. Get brand impersonation analysis
        try:
            brand_features = extract_brand_features(host)
        except Exception:
            brand_features = {
                "min_brand_distance": 999,
                "closest_brand": "",
                "brand_similarity": 0.0,
                "is_brand_impersonation": 0,
                "typosquatting_score": 0.0
            }
        
        # If registered domain is an authentic top-tier brand from Tranco, disable brand impersonation
        if trust_score >= 0.85 and not is_user_hosting:
            brand_features["is_brand_impersonation"] = 0
            brand_features["typosquatting_score"] = 0.0
        
        # 5. Get rules analysis
        try:
            rules_analysis = analyze_url_rules(url, user_country=user_country)
            rules_score = rules_analysis.get("aggregate_score", 0.0)
        except Exception:
            rules_analysis = {"aggregate_score": 0.0, "triggered_rules": [], "all_rules": []}
            rules_score = 0.0
        
        # High-signal rules
        high_signal_rules = {"country_code_tld", "server_geolocation", "domain_age"}
        triggered_high_signal = [
            r for r in rules_analysis.get("triggered_rules", [])
            if r.get("rule") in high_signal_rules
        ]
        
        # Don't penalize server_geolocation for top-tier global domains with CDN edge nodes
        if trust_score >= 0.70 and not is_user_hosting:
            triggered_high_signal = [r for r in triggered_high_signal if r.get("rule") != "server_geolocation"]
            
        high_signal_boost = sum(r.get("confidence", 0) for r in triggered_high_signal) * 0.3
        
        # Financial phishing boost
        financial_rules = {"financial_phishing"}
        triggered_financial = [
            r for r in rules_analysis.get("triggered_rules", [])
            if r.get("rule") in financial_rules
        ]
        financial_boost = sum(r.get("confidence", 0) for r in triggered_financial) * 0.4
        
        brand_mismatch = next(
            (r for r in rules_analysis.get("all_rules", []) if r.get("rule") == "brand_country_mismatch"),
            None
        )
        
        brand_score = brand_features["typosquatting_score"] if brand_features["is_brand_impersonation"] else 0.0

        # 6. Intelligent Multimodal Fusion
        # CASE A: Critical Homoglyph / Confusable Spoofing Attack
        if homoglyphs_data.get("is_spoofing"):
            final_prob = 0.97
            decision = "phishing"
        
        # CASE B: Top-Tier Global Prevalent Domain (Wikipedia, Google, GitHub, Microsoft, etc.)
        elif trust_score >= 0.70 and not is_user_hosting and not brand_features["is_brand_impersonation"]:
            # Known authentic infrastructure. Suppress lexical M0 overfit noise.
            max_allowed_prob = 0.08 if trust_score >= 0.88 else 0.18
            final_prob = min(m0_prob * (1.0 - trust_score), max_allowed_prob)
            decision = "legitimate"

        # CASE C: Financial Phishing Attack (High Confidence Signals)
        elif financial_boost > 0.5:
            final_prob = max(0.7 * financial_boost + 0.3 * m0_prob, m0_prob, 0.85)
            decision = "phishing"

        # CASE D: Brand Impersonation on unranked / low-reputation domain
        elif brand_features["is_brand_impersonation"] and brand_score > 0.65:
            final_prob = max(brand_score * 0.95, m0_prob, 0.80)
            decision = "phishing"

        elif brand_features["is_brand_impersonation"]:
            final_prob = 0.35 * m0_prob + 0.65 * brand_score
            decision = "phishing" if final_prob >= 0.5 else "legitimate"

        # CASE E: Rules or Infrastructure Anomalies
        elif rules_score > 0.5 or high_signal_boost > 0.3:
            final_prob = max(0.4 * m0_prob + 0.4 * rules_score + high_signal_boost + financial_boost, m0_prob)
            decision = "phishing" if final_prob >= 0.5 else "legitimate"

        # CASE F: General / Neutral Domain
        else:
            base_prob = 0.65 * m0_prob + 0.20 * rules_score + high_signal_boost + financial_boost
            # Attenuate slightly by trust score if present in Tranco
            if trust_score > 0.0:
                base_prob = base_prob * (1.0 - (trust_score * 0.75))
            final_prob = max(0.0, min(1.0, base_prob))
            decision = "phishing" if final_prob >= 0.5 else "legitimate"

        # Escalate to 'warning' if foreign domain has local brand collisions or regional mismatch
        local_sug = rules_analysis.get("local_suggestions", [])
        geo_ctx = rules_analysis.get("geo_context", {})
        has_brand_mismatch = bool(brand_mismatch and brand_mismatch.get("triggered"))
        if (has_brand_mismatch or (local_sug and geo_ctx.get("is_foreign"))) and decision == "legitimate":
            decision = "warning"

        # Final sanity bounds
        final_prob = round(max(0.0, min(1.0, final_prob)), 6)

        # Risk breakdown components (0-100%) for UI visualization
        risk_breakdown = {
            "lexical": int(round(m0_prob * 100)),
            "reputation_risk": int(round((1.0 - trust_score) * 100)),
            "brand_risk": int(round(brand_score * 100)),
            "infrastructure_risk": int(round(min(1.0, rules_score + high_signal_boost) * 100))
        }

        return {
            "probability": final_prob,
            "decision": decision,
            "m0_probability": round(m0_prob, 6),
            "reputation": rep,
            "homoglyphs": homoglyphs_data,
            "risk_breakdown": risk_breakdown,
            "brand_analysis": brand_features if brand_features["is_brand_impersonation"] else None,
            "brand_mismatch": brand_mismatch.get("details") if brand_mismatch and brand_mismatch.get("triggered") and brand_mismatch.get("details") else None,
            "geo_context": rules_analysis.get("geo_context"),
            "local_suggestions": rules_analysis.get("local_suggestions", []),
            "rules_analysis": rules_analysis,
            "model": "M0+Tranco+Brand+Rules"
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
