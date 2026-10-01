"""
Advanced Detection Rules Module
Implements rule-based detection for various phishing patterns.
"""
from __future__ import annotations

import re
import socket
import json
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlsplit


@dataclass
class RuleResult:
    """Result from a detection rule."""
    rule_name: str
    triggered: bool
    confidence: float  # 0-1
    reason: str
    details: Dict[str, any] = None


class DetectionRules:
    """
    Collection of rule-based detection methods for phishing URLs.
    Each rule returns a RuleResult with confidence score.
    """
    
    # Global caches (shared across instances, persist for the process lifetime)
    _geo_cache: Dict[str, dict] = {}
    _whois_cache: Dict[str, dict] = {}
    
    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = frozenset({
        "xyz", "top", "buzz", "club", "online", "site", "website", "space",
        "tech", "store", "fun", "icu", "cam", "lol", "sbs", "rest",
        "uno", "cfd", "bar", "biz", "info", "tk", "ml", "ga", "cf", "gq"
    })
    
    # High-risk TLDs (almost always malicious for brand impersonation)
    HIGH_RISK_TLDS = frozenset({
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz"
    })
    
    # Legitimate TLDs
    SAFE_TLDS = frozenset({
        "com", "net", "org", "edu", "gov", "mil", "int"
    })

    # High-risk ccTLDs - historically abused anonymous/free registration domains (Freenom)
    HIGH_RISK_CCTLDS = frozenset({
        "tk", "ml", "ga", "cf", "gq"
    })

    # Medium-risk ccTLDs - legacy or cheap registration domains with moderate abuse history
    MEDIUM_RISK_CCTLDS = frozenset({
        "cc", "ws", "su", "to", "la"
    })
    
    # Suspicious path keywords
    SUSPICIOUS_PATH_KEYWORDS = frozenset({
        "login", "signin", "signin", "verify", "confirm", "secure",
        "account", "update", "password", "credential", "auth",
        "banking", "transfer", "payment", "wallet", "crypto",
        "restore", "recover", "unlock", "activate"
    })
    
    # URL shortener domains
    URL_SHORTENERS = frozenset({
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
        "buff.ly", "ow.ly", "t.ly", "cutt.ly", "shorturl.at",
        "rb.gy", "freebitco.in", "tiny.cc", "lnkd.in"
    })
    
    # Homograph characters (Cyrillic, Greek that look like Latin)
    HOMOGRAPH_CHARS = {
        'а': 'a',  # Cyrillic а
        'е': 'e',  # Cyrillic е
        'о': 'o',  # Cyrillic о
        'р': 'p',  # Cyrillic р
        'с': 'c',  # Cyrillic с
        'у': 'y',  # Cyrillic у
        'х': 'x',  # Cyrillic х
        'ѕ': 's',  # Cyrillic ѕ
        'і': 'i',  # Cyrillic і
        'ј': 'j',  # Cyrillic ј
        'α': 'a',  # Greek alpha
        'ε': 'e',  # Greek epsilon
        'ο': 'o',  # Greek omicron
        'ρ': 'p',  # Greek rho
        'σ': 's',  # Greek sigma
        'υ': 'y',  # Greek upsilon
        'κ': 'k',  # Greek kappa
    }

    # Config loaded from external JSON file (no hardcoding)
    BRAND_COUNTRY_MAP = {}
    OFFICIAL_DOMAINS_MAP = {}
    MULTI_COUNTRY_BRANDS = {}
    COUNTRY_NAMES = {}
    COUNTRY_CODE_MAP = {}  # Maps 2-letter codes to config keys (PE → PERU)
    KEY_TO_CODE_MAP = {}   # Maps config keys to 2-letter codes (PERU → PE)
    RAW_BRANDS_CONFIG = {} # Raw brand tree per country
    
    @classmethod
    def _normalize_country_code(cls, code: str) -> str:
        """Convert a 2-letter country code to the config key format (PE → PERU)."""
        if not cls.COUNTRY_CODE_MAP:
            cls._load_brand_config()
        clean = (code or "").strip().upper().replace(" ", "_")
        return cls.COUNTRY_CODE_MAP.get(clean, clean)
    
    @classmethod
    def _load_brand_config(cls) -> None:
        """Load brand-country mapping from external JSON config file."""
        if cls.BRAND_COUNTRY_MAP:
            return  # Already loaded
        
        # Search for config file in multiple locations
        config_name = "brand-country-map.json"
        search_paths = [
            Path("configs") / config_name,
            Path(__file__).parent.parent.parent / "configs" / config_name,
            Path.home() / ".phishguard" / config_name,
        ]
        
        for config_path in search_paths:
            if config_path.exists():
                try:
                    with open(config_path, "r", encoding="utf-8-sig") as f:
                        data = json.load(f)
                    
                    raw_brands = data.get("brands", {})
                    flat_brands = {}
                    official_map = {}
                    multi_country = {}

                    for country_code, country_brands in raw_brands.items():
                        if not isinstance(country_brands, dict):
                            continue
                        for brand_key, brand_info in country_brands.items():
                            if not isinstance(brand_info, dict):
                                continue
                            
                            local_domain = brand_info.get("local_domain", "").strip().lower()
                            base_brand = brand_key.split("_")[0]
                            full_name = brand_info.get("full_name", brand_key)
                            category = brand_info.get("category", "bank")
                            
                            if local_domain:
                                clean_ld = local_domain.replace("www.", "")
                                official_map[clean_ld] = {
                                    "brand_key": brand_key,
                                    "base_brand": base_brand,
                                    "full_name": full_name,
                                    "country": country_code,
                                    "local_domain": local_domain,
                                    "category": category
                                }
                                if base_brand not in multi_country:
                                    multi_country[base_brand] = {}
                                multi_country[base_brand][country_code] = local_domain

                            # Build expected_countries from parent country group
                            if brand_key not in flat_brands:
                                flat_brands[brand_key] = {
                                    "expected_countries": [country_code],
                                    "full_name": full_name,
                                    "local_domain": local_domain,
                                    "category": category,
                                    "also_known_as": brand_info.get("also_known_as", []),
                                }
                            else:
                                flat_brands[brand_key]["expected_countries"].append(country_code)
                    
                    cls.BRAND_COUNTRY_MAP = flat_brands
                    cls.OFFICIAL_DOMAINS_MAP = official_map
                    cls.MULTI_COUNTRY_BRANDS = multi_country
                    cls.COUNTRY_NAMES = data.get("countries", {})
                    cls.RAW_BRANDS_CONFIG = raw_brands
                    
                    # Build 2-letter code → config key mapping (PE → PERU, CR → COSTA_RICA)
                    country_keys = set(raw_brands.keys())
                    code_map = {}
                    for code, name in cls.COUNTRY_NAMES.items():
                        config_key = name.upper().replace(" ", "_")
                        if config_key in country_keys:
                            code_map[code] = config_key
                    cls.COUNTRY_CODE_MAP = code_map
                    cls.KEY_TO_CODE_MAP = {v: k for k, v in code_map.items()}
                    
                    return
                except (json.JSONDecodeError, IOError):
                    continue
        
        # Fallback: empty config (no brands to match)
        cls.BRAND_COUNTRY_MAP = {}
        cls.OFFICIAL_DOMAINS_MAP = {}
        cls.MULTI_COUNTRY_BRANDS = {}
        cls.COUNTRY_NAMES = {}
        cls.COUNTRY_CODE_MAP = {}
        cls.KEY_TO_CODE_MAP = {}
        cls.RAW_BRANDS_CONFIG = {}
    
    def analyze(self, url: str, user_country: str = "") -> List[RuleResult]:
        """
        Run all detection rules on a URL.
        
        Args:
            url: The URL to analyze
            user_country: User's country code (e.g., "PE", "MX")
            
        Returns:
            List of RuleResult objects
        """
        results = []
        
        # Parse URL
        try:
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception:
            return [RuleResult(
                rule_name="url_parse",
                triggered=True,
                confidence=0.8,
                reason="URL mal formada"
            )]
        
        # Run fast rules synchronously
        results.append(self._check_homograph(hostname))
        results.append(self._check_suspicious_tld(hostname))
        results.append(self._check_country_code_tld(hostname))
        results.append(self._check_url_shortener(hostname))
        results.append(self._check_suspicious_path(path))
        results.append(self._check_ip_address(hostname))
        results.append(self._check_subdomain_abuse(hostname))
        results.append(self._check_at符号(url))
        results.append(self._check_excessive_subdomains(hostname))
        results.append(self._check_suspicious_query(query))
        results.append(self._check_long_url(url))
        
        # Run slow rules concurrently (geolocation, whois, brand_mismatch)
        from concurrent.futures import ThreadPoolExecutor, as_completed
        slow_rules = {
            "geo": lambda: self._check_server_geolocation(hostname),
            "age": lambda: self._check_domain_age(hostname),
            "brand": lambda: self._check_brand_country_mismatch(hostname, url, user_country),
        }
        slow_results = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(fn): key for key, fn in slow_rules.items()}
            for future in as_completed(futures, timeout=8):
                key = futures[future]
                try:
                    slow_results[key] = future.result()
                except Exception:
                    slow_results[key] = None
        
        geo_result = slow_results.get("geo")
        brand_mismatch = slow_results.get("brand")
        
        if geo_result:
            results.append(geo_result)
        if slow_results.get("age"):
            results.append(slow_results["age"])
        if brand_mismatch:
            results.append(brand_mismatch)
        results.append(self._check_financial_phishing(hostname, path, brand_mismatch or RuleResult(
            rule_name="brand_country_mismatch", triggered=False, confidence=0.0, reason="Skipped"
        )))
        
        return results
    
    def _check_homograph(self, hostname: str) -> RuleResult:
        """Check for homograph/IDN attacks using non-Latin characters."""
        has_homograph = False
        found_chars = []
        
        for char in hostname:
            if char in self.HOMOGRAPH_CHARS:
                has_homograph = True
                found_chars.append(f"{char} → {self.HOMOGRAPH_CHARS[char]}")
        
        return RuleResult(
            rule_name="homograph_attack",
            triggered=has_homograph,
            confidence=0.95 if has_homograph else 0.0,
            reason=f"Caracteres homográficos detectados: {', '.join(found_chars)}" if has_homograph else "Sin caracteres homográficos",
            details={"found_chars": found_chars} if has_homograph else None
        )
    
    def _check_suspicious_tld(self, hostname: str) -> RuleResult:
        """Check for suspicious top-level domains."""
        # Extract TLD
        parts = hostname.split(".")
        if len(parts) < 2:
            return RuleResult(
                rule_name="suspicious_tld",
                triggered=False,
                confidence=0.0,
                reason="TLD no detectado"
            )
        
        tld = parts[-1]
        
        if tld in self.HIGH_RISK_TLDS:
            return RuleResult(
                rule_name="suspicious_tld",
                triggered=True,
                confidence=0.8,
                reason=f"TLD de alto riesgo: .{tld}",
                details={"tld": tld, "risk_level": "high"}
            )
        elif tld in self.SUSPICIOUS_TLDS:
            return RuleResult(
                rule_name="suspicious_tld",
                triggered=True,
                confidence=0.5,
                reason=f"TLD sospechoso: .{tld}",
                details={"tld": tld, "risk_level": "medium"}
            )
        
        return RuleResult(
            rule_name="suspicious_tld",
            triggered=False,
            confidence=0.0,
            reason=f"TLD legítimo: .{tld}"
        )
    
    def _check_url_shortener(self, hostname: str) -> RuleResult:
        """Check if URL uses a shortener service."""
        is_shortener = hostname in self.URL_SHORTENERS or any(
            hostname.endswith(f".{s}") for s in self.URL_SHORTENERS
        )
        
        return RuleResult(
            rule_name="url_shortener",
            triggered=is_shortener,
            confidence=0.6 if is_shortener else 0.0,
            reason=f"Servicio acortador detectado: {hostname}" if is_shortener else "Sin acortador",
            details={"shortener": hostname} if is_shortener else None
        )
    
    def _check_suspicious_path(self, path: str) -> RuleResult:
        """Check for suspicious path keywords."""
        found_keywords = [kw for kw in self.SUSPICIOUS_PATH_KEYWORDS if kw in path]
        
        return RuleResult(
            rule_name="suspicious_path",
            triggered=len(found_keywords) > 0,
            confidence=min(0.7, 0.3 + 0.1 * len(found_keywords)),
            reason=f"Palabras clave sospechosas en path: {', '.join(found_keywords)}" if found_keywords else "Path limpio",
            details={"keywords": found_keywords} if found_keywords else None
        )
    
    def _check_ip_address(self, hostname: str) -> RuleResult:
        """Check if hostname is an IP address."""
        # Simple IP check
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))
        
        return RuleResult(
            rule_name="ip_address",
            triggered=is_ip,
            confidence=0.9 if is_ip else 0.0,
            reason=f"IP directa detectada: {hostname}" if is_ip else "Hostname no es IP",
            details={"ip": hostname} if is_ip else None
        )
    
    def _check_subdomain_abuse(self, hostname: str) -> RuleResult:
        """Check for excessive or suspicious subdomains."""
        parts = hostname.split(".")
        subdomain_count = max(0, len(parts) - 2)
        
        # Check for suspicious subdomain patterns
        suspicious_patterns = [
            r'^www\d+',  # www1, www2, etc.
            r'^secure',  # secure.domain.com
            r'^login',   # login.domain.com
            r'^auth',    # auth.domain.com
            r'^verify',  # verify.domain.com
        ]
        
        has_suspicious = False
        for part in parts[:-2]:  # Check subdomains only
            for pattern in suspicious_patterns:
                if re.match(pattern, part, re.IGNORECASE):
                    has_suspicious = True
                    break
        
        return RuleResult(
            rule_name="subdomain_abuse",
            triggered=subdomain_count > 3 or has_suspicious,
            confidence=0.6 if has_suspicious else (0.4 if subdomain_count > 3 else 0.0),
            reason=f"Subdominios excesivos ({subdomain_count}) o sospechosos" if subdomain_count > 3 or has_suspicious else "Subdominios normales",
            details={"subdomain_count": subdomain_count, "has_suspicious": has_suspicious}
        )
    
    def _check_at符号(self, url: str) -> RuleResult:
        """Check for @ symbol in URL (used to hide real destination)."""
        has_at = "@" in url
        
        return RuleResult(
            rule_name="at_symbol",
            triggered=has_at,
            confidence=0.85 if has_at else 0.0,
            reason="Símbolo @ detectado (posible ocultación de URL real)" if has_at else "Sin símbolo @",
            details={"url": url} if has_at else None
        )
    
    def _check_excessive_subdomains(self, hostname: str) -> RuleResult:
        """Check for excessive subdomain depth."""
        parts = hostname.split(".")
        depth = len(parts)
        
        return RuleResult(
            rule_name="excessive_subdomains",
            triggered=depth > 5,
            confidence=0.5 if depth > 5 else 0.0,
            reason=f"Profundidad de subdominios excesiva: {depth}" if depth > 5 else "Profundidad normal",
            details={"depth": depth}
        )
    
    def _check_suspicious_query(self, query: str) -> RuleResult:
        """Check for suspicious query parameters."""
        suspicious_params = [
            'token', 'session', 'sid', 'sessionid', 'auth',
            'access_token', 'api_key', 'key', 'secret'
        ]
        
        found_params = [p for p in suspicious_params if p in query.lower()]
        
        return RuleResult(
            rule_name="suspicious_query",
            triggered=len(found_params) > 0,
            confidence=0.4 if found_params else 0.0,
            reason=f"Parámetros sospechosos: {', '.join(found_params)}" if found_params else "Query limpio",
            details={"params": found_params} if found_params else None
        )
    
    def _check_long_url(self, url: str) -> RuleResult:
        """Check for excessively long URLs."""
        is_long = len(url) > 200
        
        return RuleResult(
            rule_name="long_url",
            triggered=is_long,
            confidence=0.3 if is_long else 0.0,
            reason=f"URL excesivamente larga: {len(url)} caracteres" if is_long else "Longitud normal",
            details={"length": len(url)}
        )
    
    def _check_country_code_tld(self, hostname: str) -> RuleResult:
        """
        Check for high-risk country-code TLDs (ccTLDs).
        Many phishing campaigns use ccTLDs from countries with lax enforcement.
        """
        parts = hostname.split(".")
        if len(parts) < 2:
            return RuleResult(
                rule_name="country_code_tld",
                triggered=False,
                confidence=0.0,
                reason="TLD no detectado"
            )
        
        tld = parts[-1]
        
        if tld in self.HIGH_RISK_CCTLDS:
            return RuleResult(
                rule_name="country_code_tld",
                triggered=True,
                confidence=0.7,
                reason=f"ccTLD de alto riesgo: .{tld} (comunmente abusado en phishing)",
                details={"tld": tld, "risk_level": "high", "category": "country_code"}
            )
        elif tld in self.MEDIUM_RISK_CCTLDS:
            return RuleResult(
                rule_name="country_code_tld",
                triggered=True,
                confidence=0.4,
                reason=f"ccTLD de riesgo medio: .{tld} (registro barato/abuso moderado)",
                details={"tld": tld, "risk_level": "medium", "category": "country_code"}
            )
        
        return RuleResult(
            rule_name="country_code_tld",
            triggered=False,
            confidence=0.0,
            reason=f"ccTLD no clasificado: .{tld}"
        )
    
    def _check_server_geolocation(self, hostname: str) -> RuleResult:
        """
        Check server geolocation via DNS resolution + free IP geolocation API.
        Servers in certain regions have higher phishing association.
        Uses in-process cache to avoid repeated API calls.
        """
        # Check cache first
        cache_key = hostname
        if cache_key in self._geo_cache:
            cached = self._geo_cache[cache_key]
            return RuleResult(
                rule_name="server_geolocation",
                triggered=cached["triggered"],
                confidence=cached["confidence"],
                reason=cached["reason"],
                details=cached.get("details")
            )
        
        try:
            # Resolve hostname to IP
            ip_address = socket.gethostbyname(hostname)
            
            # Use free ip-api.com API for geolocation (no key required, 45 req/min)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            import urllib.request
            api_url = f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,regionName,isp"
            req = urllib.request.Request(api_url, headers={"User-Agent": "PhishGuard/1.0"})
            
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                data = json.loads(response.read().decode())
            
            if data.get("status") != "success":
                result = RuleResult(
                    rule_name="server_geolocation",
                    triggered=False,
                    confidence=0.0,
                    reason="No se pudo obtener geolocalización"
                )
                self._geo_cache[cache_key] = {"triggered": False, "confidence": 0.0, "reason": result.reason}
                return result
            
            country_code = data.get("countryCode", "").upper()
            country_name = data.get("country", "Unknown")
            isp = data.get("isp", "Unknown")
            
            # Countries with high phishing association
            high_risk_countries = {"CN", "RU", "KP", "IR"}
            medium_risk_countries = {"BR", "IN", "ID", "VN", "NG", "PK", "EG", "PH"}
            
            if country_code in high_risk_countries:
                result = RuleResult(
                    rule_name="server_geolocation",
                    triggered=True,
                    confidence=0.6,
                    reason=f"Servidor en país de alto riesgo: {country_name} ({country_code})",
                    details={
                        "ip": ip_address,
                        "country": country_name,
                        "country_code": country_code,
                        "isp": isp,
                        "risk_level": "high"
                    }
                )
            elif country_code in medium_risk_countries:
                result = RuleResult(
                    rule_name="server_geolocation",
                    triggered=True,
                    confidence=0.3,
                    reason=f"Servidor en país de riesgo medio: {country_name} ({country_code})",
                    details={
                        "ip": ip_address,
                        "country": country_name,
                        "country_code": country_code,
                        "isp": isp,
                        "risk_level": "medium"
                    }
                )
            else:
                result = RuleResult(
                    rule_name="server_geolocation",
                    triggered=False,
                    confidence=0.0,
                    reason=f"Servidor en país de bajo riesgo: {country_name} ({country_code})",
                    details={
                        "ip": ip_address,
                        "country": country_name,
                        "country_code": country_code,
                        "isp": isp
                    }
                )
            
            # Cache result
            self._geo_cache[cache_key] = {
                "triggered": result.triggered,
                "confidence": result.confidence,
                "reason": result.reason,
                "details": result.details
            }
            return result
            
        except (socket.gaierror, TimeoutError, Exception) as e:
            return RuleResult(
                rule_name="server_geolocation",
                triggered=False,
                confidence=0.0,
                reason=f"Error al verificar geolocalización: {type(e).__name__}"
            )
    
    def _check_domain_age(self, hostname: str) -> RuleResult:
        """
        Check domain age via WHOIS lookup with timeout.
        Newly registered domains are strongly associated with phishing campaigns.
        Uses in-process cache to avoid repeated lookups.
        """
        # Check cache first
        if hostname in self._whois_cache:
            cached = self._whois_cache[hostname]
            return RuleResult(
                rule_name="domain_age",
                triggered=cached["triggered"],
                confidence=cached["confidence"],
                reason=cached["reason"],
                details=cached.get("details")
            )
        
        try:
            import whois
            from datetime import datetime, timezone
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
            
            with ThreadPoolExecutor(1) as executor:
                future = executor.submit(whois.whois, hostname)
                try:
                    w = future.result(timeout=5)
                except (FuturesTimeout, Exception):
                    result = RuleResult(
                        rule_name="domain_age",
                        triggered=False,
                        confidence=0.0,
                        reason="WHOIS timeout o error de conexión"
                    )
                    self._whois_cache[hostname] = {"triggered": False, "confidence": 0.0, "reason": result.reason}
                    return result
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date is None:
                result = RuleResult(
                    rule_name="domain_age",
                    triggered=False,
                    confidence=0.0,
                    reason="Fecha de creación no disponible en WHOIS"
                )
                self._whois_cache[hostname] = {"triggered": False, "confidence": 0.0, "reason": result.reason}
                return result
            
            # Ensure timezone-aware
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            
            # Risk thresholds based on domain age
            if age_days <= 7:
                details = {"creation_date": creation_date.isoformat(), "age_days": age_days, "risk_level": "critical"}
                result = RuleResult(rule_name="domain_age", triggered=True, confidence=0.9, reason=f"Dominio registrado hace solo {age_days} días (muy nuevo)", details=details)
            elif age_days <= 30:
                details = {"creation_date": creation_date.isoformat(), "age_days": age_days, "risk_level": "high"}
                result = RuleResult(rule_name="domain_age", triggered=True, confidence=0.7, reason=f"Dominio registrado hace {age_days} días (nuevo)", details=details)
            elif age_days <= 90:
                details = {"creation_date": creation_date.isoformat(), "age_days": age_days, "risk_level": "medium"}
                result = RuleResult(rule_name="domain_age", triggered=True, confidence=0.4, reason=f"Dominio registrado hace {age_days} días (reciente)", details=details)
            else:
                details = {"creation_date": creation_date.isoformat(), "age_days": age_days}
                result = RuleResult(rule_name="domain_age", triggered=False, confidence=0.0, reason=f"Dominio estable ({age_days} días)", details=details)
            
            self._whois_cache[hostname] = {"triggered": result.triggered, "confidence": result.confidence, "reason": result.reason, "details": result.details}
            return result
            
        except ImportError:
            return RuleResult(
                rule_name="domain_age",
                triggered=False,
                confidence=0.0,
                reason="Módulo whois no disponible"
            )
        except Exception as e:
            return RuleResult(
                rule_name="domain_age",
                triggered=False,
                confidence=0.0,
                reason=f"Error en consulta WHOIS: {type(e).__name__}"
            )
    
    def _check_brand_country_mismatch(self, hostname: str, url: str, user_country: str = "") -> RuleResult:
        """
        Detect brand-country mismatch from the USER's perspective.
        
        CRITICAL DESIGN RULE:
        A mismatch ONLY occurs when the user visits a VERIFIED OFFICIAL DOMAIN of a
        multinational brand that belongs to a DIFFERENT country than the user's location.
        Example: User in Peru visiting official Mexican BBVA (bbva.mx) instead of Peru (bbva.pe).
        
        Unrelated third-party domains (e.g., bcp.com in China, gnb.com, bci.com) that share 
        short acronyms or words with a bank are NOT regional versions and MUST NOT trigger this rule.
        """
        self._load_brand_config()
        
        clean_host = hostname.replace("www.", "").strip().lower()
        if not clean_host or "." not in clean_host:
            return RuleResult(
                rule_name="brand_country_mismatch",
                triggered=False,
                confidence=0.0,
                reason="Dominio no analizable"
            )
        
        # 1. Check if the current hostname (or its registrable domain) is an official cataloged domain
        matched_official = self.OFFICIAL_DOMAINS_MAP.get(clean_host)
        if not matched_official:
            parts = clean_host.split(".")
            # Check eTLD+1 or eTLD+2 (e.g. banca.bbva.pe -> bbva.pe, portal.bbva.com.mx -> bbva.com.mx)
            for i in range(1, len(parts) - 1):
                sub_candidate = ".".join(parts[i:])
                if sub_candidate in self.OFFICIAL_DOMAINS_MAP:
                    matched_official = self.OFFICIAL_DOMAINS_MAP[sub_candidate]
                    break
        
        # If the domain is NOT an official domain of ANY brand in our knowledge base,
        # it CANNOT be a regional version of any bank. Rule does NOT trigger.
        if not matched_official:
            return RuleResult(
                rule_name="brand_country_mismatch",
                triggered=False,
                confidence=0.0,
                reason="Marca bancaria conocida no detectada en el dominio"
            )
        
        # 2. It IS an official banking portal. Check user country context.
        portal_country = matched_official["country"]
        base_brand = matched_official["base_brand"]
        full_name = matched_official["full_name"]
        category = matched_official["category"]
        official_domain = matched_official["local_domain"]
        
        portal_country_name = self.COUNTRY_NAMES.get(portal_country, portal_country)
        
        if not user_country:
            return RuleResult(
                rule_name="brand_country_mismatch",
                triggered=False,
                confidence=0.0,
                reason="País del usuario no especificado para comparar",
                details={
                    "is_official": True,
                    "brand_full_name": full_name,
                    "portal_country": portal_country
                }
            )
        
        normalized_user_country = self._normalize_country_code(user_country)
        user_country_name = self.COUNTRY_NAMES.get(normalized_user_country, normalized_user_country)
        
        # 3. User is visiting the local official version for their own country
        if normalized_user_country == portal_country:
            return RuleResult(
                rule_name="brand_country_mismatch",
                triggered=False,
                confidence=0.0,
                reason=f"Usuario en {user_country_name} visitando versión local oficial de {full_name}",
                details={
                    "is_official": True,
                    "brand_key": matched_official["brand_key"],
                    "brand_full_name": full_name,
                    "category": category,
                    "local_domain": official_domain,
                    "current_domain": clean_host
                }
            )
        
        # 4. User is in Country A, visiting official portal of Country B
        # Does this brand have an official branch in the user's country?
        brand_branches = self.MULTI_COUNTRY_BRANDS.get(base_brand, {})
        user_country_local_domain = brand_branches.get(normalized_user_country)
        
        if user_country_local_domain:
            # Genuine mismatch: Brand operates in both countries with different domains
            brand_details = {
                "is_official": True,
                "brand_key": matched_official["brand_key"],
                "brand_full_name": full_name,
                "category": category,
                "local_domain": user_country_local_domain,
                "current_domain": clean_host,
                "portal_country": portal_country,
                "user_country": normalized_user_country,
                "suggestion": f"Si buscas {full_name} en {user_country_name}, visita directamente https://{user_country_local_domain}"
            }
            return RuleResult(
                rule_name="brand_country_mismatch",
                triggered=True,
                confidence=0.45,
                reason=f"Usuario en {user_country_name} visitando versión oficial de {full_name} ({portal_country_name}). Versión oficial local: {user_country_local_domain}",
                details=brand_details
            )
        else:
            # Brand is legitimate but does not operate in user's country (e.g., Peruvian user on Banco de Chile)
            return RuleResult(
                rule_name="brand_country_mismatch",
                triggered=False,
                confidence=0.0,
                reason=f"Portal oficial legítimo de {full_name} ({portal_country_name})",
                details={
                    "is_official": True,
                    "brand_full_name": full_name,
                    "portal_country": portal_country
                }
            )
    
    # Financial-specific phishing keywords (Spanish + English)
    FINANCIAL_KEYWORDS = frozenset({
        # Banking
        "banco", "bank", "bancario", "banking", "cuenta", "account",
        "tarjeta", "card", "credito", "credit", "debito", "debit",
        "prestamo", "loan", "hipoteca", "mortgage",
        # Credentials / Auth
        "login", "acceso", "ingresar", "signin", "autenticar", "auth",
        "usuario", "user", "password", "clave", "contrasena", "pin",
        "otp", "验证码",
        # Financial operations
        "transferencia", "transfer", "pago", "payment", "envio", "send",
        "retiro", "withdraw", "deposito", "deposit", "saldo", "balance",
        "extracto", "statement", "movimiento", "transaction", "transaccion",
        # Verification / Security
        "verificar", "verify", "confirmar", "confirm", "validar", "validate",
        "seguridad", "security", "proteger", "protect", "seguro", "secure",
        "verificacion", "verification", "autenticacion", "authentication",
        # Documents / Identity
        "dni", "cedula", "pasaporte", "passport", "identidad", "identity",
        "ruc", "rfc", "ci", "dpi", "curp",
        # Crypto / Wallets
        "wallet", "billetera", "cripto", "crypto", "bitcoin", "usdt", "usdc",
        "binance", "coinbase", "metamask",
        # Investment
        "inversion", "investment", "trading", "bolsa", "stock", "acciones",
        "acciones", "forex", "criptomonedas",
    })
    
    def _check_financial_phishing(self, hostname: str, path: str, brand_mismatch: RuleResult) -> RuleResult:
        """
        Detect financial phishing patterns.
        Boosts score when financial keywords appear in URLs combined with suspicious signals.
        """
        # Check if this is a financial domain (brand mismatch detected with financial category)
        is_financial_brand = (
            brand_mismatch.triggered and 
            brand_mismatch.details and 
            brand_mismatch.details.get("is_financial", False)
        )
        
        # Find financial keywords in path and hostname
        combined = f"{hostname} {path}"
        found_keywords = [kw for kw in self.FINANCIAL_KEYWORDS if kw in combined.lower()]
        
        if not found_keywords:
            return RuleResult(
                rule_name="financial_phishing",
                triggered=False,
                confidence=0.0,
                reason="Sin palabras clave financieras detectadas"
            )
        
        # Financial phishing detected when keywords + suspicious context
        if is_financial_brand:
            return RuleResult(
                rule_name="financial_phishing",
                triggered=True,
                confidence=0.85,
                reason=f"Phishing financiero: marca financiera suplantada + keywords: {', '.join(found_keywords[:5])}",
                details={
                    "type": "brand_impersonation",
                    "keywords": found_keywords,
                    "brand": brand_mismatch.details.get("brand_full_name"),
                    "category": brand_mismatch.details.get("brand_category"),
                    "risk_level": "critical"
                }
            )
        
        # Financial keywords without brand impersonation = medium risk
        if len(found_keywords) >= 3:
            return RuleResult(
                rule_name="financial_phishing",
                triggered=True,
                confidence=0.6,
                reason=f"Phishing financiero: múltiples keywords financieras ({len(found_keywords)}): {', '.join(found_keywords[:5])}",
                details={
                    "type": "keyword_pattern",
                    "keywords": found_keywords,
                    "risk_level": "high"
                }
            )
        
        return RuleResult(
            rule_name="financial_phishing",
            triggered=False,
            confidence=0.0,
            reason=f"Keywords financieras encontradas pero sin contexto sospechoso: {', '.join(found_keywords[:3])}"
        )
    
    def get_aggregate_score(self, results: List[RuleResult]) -> Tuple[float, str]:
        """
        Calculate aggregate risk score from all rule results.
        
        Returns:
            Tuple of (score, summary)
        """
        if not results:
            return 0.0, "Sin resultados"
        
        # Weighted average of triggered rules
        total_confidence = sum(r.confidence for r in results if r.triggered)
        max_possible = len(results) * 0.5  # Assuming average confidence of 0.5
        
        score = min(1.0, total_confidence / max_possible if max_possible > 0 else 0)
        
        # Generate summary
        triggered_rules = [r for r in results if r.triggered]
        if triggered_rules:
            rule_names = [r.rule_name for r in triggered_rules]
            summary = f"Reglas activadas: {', '.join(rule_names)}"
        else:
            summary = "Sin reglas activadas"
        
        return score, summary

    def get_geo_context(self, hostname: str, user_country: str = "") -> Dict[str, any]:
        """
        Determines the geographical origin of the domain/server and compares it
        against the user's configured country.
        """
        self._load_brand_config()
        clean_host = (hostname or "").replace("www.", "").strip().lower()
        if not clean_host:
            return {
                "user_country": "",
                "user_country_name": "",
                "origin_country": "UNKNOWN",
                "origin_country_name": "Desconocido",
                "is_foreign": False,
                "ip": "",
                "isp": "",
                "message": "Dominio no analizable"
            }
        
        # 1. Geolocation of server IP (using cached or fresh check)
        geo_rule = self._check_server_geolocation(clean_host)
        geo_details = geo_rule.details or {}
        
        server_cc = (geo_details.get("country_code") or "").upper()
        server_name = geo_details.get("country") or ""
        ip = geo_details.get("ip") or ""
        isp = geo_details.get("isp") or ""
        
        # 2. Check if ccTLD explicitly specifies a country
        tld_cc = ""
        host_parts = clean_host.split(".")
        if len(host_parts) >= 2:
            last_part = host_parts[-1].upper()
            if last_part in self.COUNTRY_NAMES:
                tld_cc = last_part
                
        origin_code = tld_cc or server_cc or "UNKNOWN"
        origin_name = self.COUNTRY_NAMES.get(origin_code, server_name or origin_code)
        
        # 3. User country normalization
        norm_user_key = self._normalize_country_code(user_country) if user_country else ""
        user_cc = ""
        user_name = ""
        if norm_user_key:
            user_cc = self.KEY_TO_CODE_MAP.get(norm_user_key, user_country.upper())
            user_name = self.COUNTRY_NAMES.get(user_cc, norm_user_key.title())
            
        is_foreign = False
        if user_cc and origin_code and origin_code != "UNKNOWN":
            is_foreign = (origin_code != user_cc and norm_user_key != origin_code)
            
        if is_foreign and origin_name and user_name:
            message = f"Servidor alojado en {origin_name} ({origin_code}) | Tu ubicación: {user_name} ({user_cc})"
        elif origin_name and origin_name != "UNKNOWN":
            message = f"Servidor alojado en {origin_name} ({origin_code})"
        else:
            message = "Ubicación geográfica del servidor no identificada"
            
        return {
            "user_country": user_cc,
            "user_country_name": user_name,
            "origin_country": origin_code,
            "origin_country_name": origin_name,
            "is_foreign": is_foreign,
            "ip": ip,
            "isp": isp,
            "message": message
        }

    def find_local_brand_suggestions(self, hostname: str, user_country: str = "") -> List[Dict[str, any]]:
        """
        Identify if a foreign/visited domain has lexical, acronym, or phonetic
        similarity to any official banking or financial entities in the user's country.
        Example: bcp.com visited in Peru -> recommends viabcp.com (Banco de Crédito del Perú).
        """
        self._load_brand_config()
        if not user_country:
            return []
            
        clean_host = (hostname or "").replace("www.", "").strip().lower()
        if not clean_host or "." not in clean_host:
            return []
            
        country_key = self._normalize_country_code(user_country)
        country_brands = self.RAW_BRANDS_CONFIG.get(country_key, {})
        if not country_brands:
            return []
            
        user_cc = self.KEY_TO_CODE_MAP.get(country_key, user_country.upper())
        user_name = self.COUNTRY_NAMES.get(user_cc, country_key.title())
        
        # Extract stem/label from clean_host
        parts = clean_host.split(".")
        if len(parts) >= 3 and parts[-1] in {"pe", "mx", "co", "cl", "ar", "br", "ec", "bo", "uk"} and parts[-2] in {"com", "gob", "org", "net", "edu", "co"}:
            stem = parts[-3]
        elif len(parts) >= 2:
            stem = parts[-2]
        else:
            stem = parts[0]
            
        stopwords = {"de", "del", "la", "el", "los", "las", "y", "en", "para", "por"}
        suggestions = []
        
        from phishguard_ml.brand_features import _levenshtein_distance, _jaro_similarity
        
        for brand_key, brand_info in country_brands.items():
            if not isinstance(brand_info, dict):
                continue
            local_domain = brand_info.get("local_domain", "").strip().lower().replace("www.", "")
            if not local_domain:
                continue
                
            # If the user is ALREADY visiting the official local domain, no suggestion needed
            if clean_host == local_domain or clean_host.endswith("." + local_domain):
                return []
                
            full_name = brand_info.get("full_name", brand_key)
            category = brand_info.get("category", "bank")
            aliases = [a.lower().strip() for a in brand_info.get("also_known_as", [])]
            base_key = brand_key.split("_")[0].lower()
            
            # Extract stem of local_domain
            ld_parts = local_domain.split(".")
            if len(ld_parts) >= 3 and ld_parts[-1] in {"pe", "mx", "co", "cl", "ar", "br", "ec", "bo", "uk"} and ld_parts[-2] in {"com", "gob", "org", "net", "edu", "co"}:
                ld_stem = ld_parts[-3]
            elif len(ld_parts) >= 2:
                ld_stem = ld_parts[-2]
            else:
                ld_stem = ld_parts[0]
                
            # Compute initials/acronym from full_name
            name_words = [w for w in full_name.lower().split() if w not in stopwords]
            acronym = "".join(w[0] for w in name_words if w)
            
            matched = False
            match_reason = ""
            confidence = 0.0
            
            # 1. Exact match on acronym, brand key, or alias
            if stem == base_key:
                matched = True
                confidence = 0.98
                match_reason = f"La sigla '{stem.upper()}' coincide con la entidad oficial {full_name} en {user_name}."
            elif stem == acronym and len(stem) >= 2:
                matched = True
                confidence = 0.96
                match_reason = f"El acrónimo '{stem.upper()}' corresponde a {full_name} en {user_name}."
            elif stem in aliases:
                matched = True
                confidence = 0.95
                match_reason = f"El término coincide con el identificador conocido de {full_name}."
            # 2. Substring containment
            elif len(stem) >= 3 and (stem in ld_stem or ld_stem in stem):
                matched = True
                confidence = 0.90
                match_reason = f"El término '{stem}' coincide con parte del dominio oficial de {full_name} ({local_domain})."
            # 3. Levenshtein / Jaro Typo similarity
            elif len(stem) >= 4 and len(ld_stem) >= 4:
                dist = _levenshtein_distance(stem, ld_stem)
                jaro = _jaro_similarity(stem, ld_stem)
                if dist <= 2 or jaro >= 0.84:
                    matched = True
                    confidence = 0.85
                    match_reason = f"Posible variación o error tipográfico respecto a {full_name} ({local_domain})."
                    
            if matched:
                suggestions.append({
                    "brand_name": full_name,
                    "suggested_domain": local_domain,
                    "url": f"https://{local_domain}",
                    "category": category,
                    "reason": match_reason,
                    "confidence": confidence
                })
                
        # Deduplicate by suggested_domain, keeping highest confidence
        unique_map = {}
        for s in suggestions:
            dom = s["suggested_domain"]
            if dom not in unique_map or s["confidence"] > unique_map[dom]["confidence"]:
                unique_map[dom] = s
                
        sorted_suggestions = sorted(unique_map.values(), key=lambda x: x["confidence"], reverse=True)
        return sorted_suggestions[:3]


# Singleton instance
detection_rules = DetectionRules()


def analyze_url_rules(url: str, user_country: str = "") -> Dict[str, any]:
    """
    Public API for rule-based analysis.
    
    Returns:
        Dict with aggregate_score, triggered_rules, detailed_results,
        geo_context, and local_suggestions
    """
    try:
        hostname = (urlsplit(url).hostname or "").lower()
    except Exception:
        hostname = ""
        
    results = detection_rules.analyze(url, user_country=user_country)
    score, summary = detection_rules.get_aggregate_score(results)
    
    geo_context = detection_rules.get_geo_context(hostname, user_country=user_country)
    local_suggestions = detection_rules.find_local_brand_suggestions(hostname, user_country=user_country)
    
    return {
        "aggregate_score": round(score, 4),
        "summary": summary,
        "geo_context": geo_context,
        "local_suggestions": local_suggestions,
        "triggered_rules": [
            {
                "rule": r.rule_name,
                "confidence": r.confidence,
                "reason": r.reason,
                "details": r.details
            }
            for r in results if r.triggered
        ],
        "all_rules": [
            {
                "rule": r.rule_name,
                "triggered": r.triggered,
                "confidence": r.confidence,
                "reason": r.reason,
                "details": r.details
            }
            for r in results
        ]
    }


def get_geo_context(hostname: str, user_country: str = "") -> Dict[str, any]:
    """Public helper for domain/server geo-origin inspection."""
    return detection_rules.get_geo_context(hostname, user_country=user_country)


def find_local_brand_suggestions(hostname: str, user_country: str = "") -> List[Dict[str, any]]:
    """Public helper to find local brand suggestions for a given hostname and user country."""
    return detection_rules.find_local_brand_suggestions(hostname, user_country=user_country)


if __name__ == "__main__":
    # Test
    test_urls = [
        "https://www.facebuuk.com/",
        "https://www.facebook.com/",
        "http://192.168.1.1/login",
        "https://secure-login.facebook.com.verify.tk/account",
        "https://bit.ly/3xyz123",
        "https://xn--80ak6aa92e.com/",  # IDN example
        "https://www.google.com/search?q=test",
        "https://banco-login.cn/phishing",  # ccTLD China
        "https://secure-account.ru/login",  # ccTLD Russia
        "https://login.xyz/verify",  # Suspicious gTLD
    ]
    
    for url in test_urls:
        result = analyze_url_rules(url)
        print(f"\n{url}")
        print(f"  Score: {result['aggregate_score']:.2f}")
        print(f"  Summary: {result['summary']}")
        if result['triggered_rules']:
            for rule in result['triggered_rules']:
                print(f"    - {rule['rule']}: {rule['reason']}")
