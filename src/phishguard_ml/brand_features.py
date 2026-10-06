from __future__ import annotations

import re
from typing import List, Tuple

# Marcas comunes targets de phishing
PHISHING_TARGET_BRANDS = {
    "facebook": ["facebook", "fb", "facebok", "facebuk", "faceboook", "fasebook"],
    "google": ["google", "gogle", "googel", "goolge"],
    "microsoft": ["microsoft", "msn", "micrsoft", "mircosoft"],
    "apple": ["apple", "icloud", "itunes"],
    "amazon": ["amazon", "amazn", "amazone"],
    "paypal": ["paypal", "paybal", "paypall"],
    "netflix": ["netflix", "netflx", "netflik"],
    "instagram": ["instagram", "instagr", "instegram"],
    "whatsapp": ["whatsapp", "whatsap", "whtsapp"],
    "twitter": ["twitter", "twiter", "twittre"],
    "linkedin": ["linkedin", "linkdin", "linkedn"],
    "github": ["github", "githbu", "gihtub"],
    "dropbox": ["dropbox", "dropbpx", "dropbok"],
    "yahoo": ["yahoo", "yaho", "yaoo"],
    "outlook": ["outlook", "outlok", "outlooek"],
    "hotmail": ["hotmail", "hotmal", "hotmil"],
    "live": ["live", "lve", "liev"],
    "aol": ["aol", "aool"],
    "icloud": ["icloud", "iclod", "iclouud"],
    "bank": ["banco", "bank"],
    "bbva": ["bbva", "bbva-login", "bbva-secure", "bbva-acceso"],
    "santander": ["santander", "santander-secure", "santander-acceso"],
    "interbank": ["interbank", "interbank-login"],
    "viabcp": ["viabcp", "bcp-enlinea", "bcpbanca", "viabcp-acceso"],
    "bancolombia": ["bancolombia", "bancolombiasecure"],
    "davivienda": ["davivienda"],
    "scotiabank": ["scotiabank", "scotiabank-login"],
    "banamex": ["banamex", "citibanamex"],
    "banorte": ["banorte"],
    "caixabank": ["caixabank"],
    "falabella": ["bancofalabella", "falabella-banco"],
    "bancodechile": ["bancodechile", "bancochile"],
    "crypto": ["binance", "coinbase", "kraken", "localbitcoin"],
    "dhl": ["dhl", "dhll"],
    "fedex": ["fedex", "fedx"],
    "ups": ["ups", "upss"],
}

def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calcula la distancia de Levenshtein entre dos strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _jaro_similarity(s1: str, s2: str) -> float:
    """Calcula la similitud de Jaro entre dos strings."""
    if s1 == s2:
        return 1.0

    len_s1, len_s2 = len(s1), len(s2)
    if len_s1 == 0 or len_s2 == 0:
        return 0.0

    match_distance = max(len_s1, len_s2) // 2 - 1
    if match_distance < 0:
        match_distance = 0

    s1_matches = [False] * len_s1
    s2_matches = [False] * len_s2

    matches = 0
    transpositions = 0

    for i in range(len_s1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len_s2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len_s1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    return (matches / len_s1 + matches / len_s2 + (matches - transpositions / 2) / matches) / 3


def extract_brand_features(hostname: str) -> dict:
    """
    Extrae features de impersonación de marcas de un hostname.
    
    Returns:
        dict con las siguientes keys:
        - min_brand_distance: distancia Levenshtein mínima a cualquier marca
        - closest_brand: nombre de la marca más cercana
        - brand_similarity: similitud Jaro con la marca más cercana
        - is_brand_impersonation: 1 si hay impersonación sospechosa
        - typosquatting_score: score compuesto (0-1)
    """
    # Limpiar hostname - remover www. y TLDs comunes
    domain = hostname.lower()
    # Remover www.
    if domain.startswith("www."):
        domain = domain[4:]
    # Remover TLDs comunes para obtener solo el nombre del dominio
    for tld in [".com", ".net", ".org", ".co", ".io", ".pe", ".es", ".mx", ".cl", ".ar",
                ".br", ".uy", ".py", ".ec", ".bo", ".ve", ".pa", ".cr", ".hn", ".sv",
                ".gt", ".ni", ".cu", ".do", ".pr"]:
        if domain.endswith(tld):
            domain = domain[:-len(tld)]
            break
    
    min_distance = float("inf")
    closest_brand = ""
    best_similarity = 0.0
    
    # Verificar coincidencia exacta con el nombre oficial de la marca
    exact_match = False
    for brand_name, variants in PHISHING_TARGET_BRANDS.items():
        if domain == brand_name or domain in variants:
            exact_match = True
            break
    
    # Also check brands from config JSON (local domain names)
    if not exact_match:
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
                        if domain == _name:
                            exact_match = True
                            break
                    if exact_match:
                        break
        except Exception:
            pass
    
    # Detectar impersonación: el dominio contiene un nombre de marca conocido
    # ej: "bbva-login" contiene "bbva", "facebook-secure" contiene "facebook"
    
    # Calcular distancia a cada variante de cada marca
    for brand_name, variants in PHISHING_TARGET_BRANDS.items():
        for variant in variants:
            dist = _levenshtein_distance(domain, variant)
            sim = _jaro_similarity(domain, variant)
            
            if dist < min_distance:
                min_distance = dist
                closest_brand = brand_name
                best_similarity = sim
    
    # Calcular score de typosquatting
    # Factor 1: distancia Levenshtein (menor = más sospechoso)
    distance_score = 1.0 - (min_distance / max(len(domain), 1))
    distance_score = max(0, min(1, distance_score))
    
    # Factor 2: similitud Jaro (mayor = más sospechoso)
    similarity_score = best_similarity
    
    # Factor 3: longitud del dominio (dominios cortos son más sospechosos)
    length_factor = 1.0 if len(domain) <= 8 else 0.5
    
    # Score compuesto
    typosquatting_score = (distance_score * 0.4 + similarity_score * 0.5 + length_factor * 0.1)
    
    # Determinar si es impersonación
    is_impersonation = 0
    closest_variant = ""
    
    # Exact match to a known phishing variant (not the official domain)
    for brand_name, variants in PHISHING_TARGET_BRANDS.items():
        if domain in variants and domain != brand_name:
            is_impersonation = 1
            closest_variant = domain
            closest_brand = brand_name
            break
    
    # Criterios clásicos de typosquatting:
    # Para marcas de 5+ caracteres: distancia <= 1 o (distancia <= 2 y longitud >= 7 y similitud > 0.82)
    # Para marcas de 3-4 caracteres: distancia DEBE ser 0 o coincidencia fonética muy estricta (> 0.92)
    if not is_impersonation and not exact_match:
        brand_len = len(closest_brand)
        if brand_len >= 5 and min_distance <= 1:
            is_impersonation = 1
        elif brand_len >= 7 and min_distance <= 2 and best_similarity > 0.85:
            is_impersonation = 1
        elif best_similarity > 0.92 and min_distance <= 1:
            is_impersonation = 1
    
    # Dominio compuesto legítimo vs malicioso:
    # e.g., "bbva-login", "facebook-secure", "santander-acceso", "login.bcp"
    # IMPORTANTE: NO hacer substring ingenuo ("live" en "delivery", "apple" en "scrapple")
    if not is_impersonation and not exact_match:
        all_brand_names = set()
        for brand_name, variants in PHISHING_TARGET_BRANDS.items():
            all_brand_names.add(brand_name)
            all_brand_names.update(variants)
            
        for brand in sorted(all_brand_names, key=len, reverse=True):
            if len(brand) < 3:
                continue
            # El nombre de la marca debe estar claramente separado por guiones o prefijos/sufijos
            pattern = rf"(^|[-_.0-9]){re.escape(brand)}([-_.0-9]|$)"
            if re.search(pattern, domain) and domain != brand:
                # Si está compuesto con keywords sospechosas o delimitado por guiones
                is_impersonation = 1
                closest_brand = brand
                break
    
    return {
        "min_brand_distance": min_distance,
        "closest_brand": closest_brand,
        "brand_similarity": best_similarity,
        "is_brand_impersonation": is_impersonation,
        "typosquatting_score": typosquatting_score,
    }


# Para testing
if __name__ == "__main__":
    test_urls = [
        "www.facebuuk.com",
        "www.facebook.com",
        "www.gogle.com",
        "www.paybal.com",
        "www.amazon.com",
        "www.mircosoft.com",
        "www.randomsite.com",
        "www.netflix-login.com",
    ]
    
    for url in test_urls:
        hostname = url.split("//")[-1].split("/")[0]
        features = extract_brand_features(hostname)
        print(f"{hostname:25} -> {features}")
