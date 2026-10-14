"""Dual Homoglyph and Unicode TR39 Confusable Normalizer for PhishPe.
Projects visual characters to their Latin visual skeleton to instantly expose homoglyph brand impersonation.
Handles IDN/Punycode decoding to prevent evasion via xn-- labels.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

# Common Unicode confusable mappings (TR39) for Cyrillic, Greek, and Lookalike characters
CONFUSABLES_MAP = {
    # Cyrillic small lookalikes
    '\u0430': 'a', # Cyrillic a
    '\u0441': 'c', # Cyrillic c
    '\u0435': 'e', # Cyrillic e
    '\u043e': 'o', # Cyrillic o
    '\u0440': 'p', # Cyrillic r (looks like p)
    '\u0445': 'x', # Cyrillic h (looks like x)
    '\u0443': 'y', # Cyrillic u (looks like y)
    '\u0456': 'i', # Cyrillic i
    '\u0458': 'j', # Cyrillic j
    '\u0455': 's', # Cyrillic s
    '\u0442': 't', # Cyrillic t
    '\u0432': 'b', # Cyrillic v
    '\u044d': 'e', # Cyrillic e
    # Greek lookalikes
    '\u03b1': 'a', # Greek alpha
    '\u03bf': 'o', # Greek omicron
    '\u03bd': 'v', # Greek nu
    '\u03c1': 'p', # Greek rho
    # Numbers/Symbols common in typosquatting
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '5': 's',
    '@': 'a',
    '$': 's',
}

POPULAR_TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "netflix",
    "amazon", "facebook", "instagram", "chase", "bankofamerica"
]

def punycode_to_unicode(hostname: str) -> str:
    """Decode Punycode (xn--) labels to Unicode for homoglyph analysis.
    
    Handles labels like 'xn--pple-43d' -> 'apple' (Cyrillic).
    Uses Python's built-in idna decoding via the encodings module.
    """
    try:
        labels = hostname.split(".")
        decoded_labels = []
        for label in labels:
            if label.lower().startswith("xn--"):
                # Decode Punycode label to Unicode using idna codec
                # Note: This may raise exceptions for malformed Punycode;
                # in that case, we fall back to the original label
                try:
                    # Use the idna codec: encode as ASCII, decode as idna
                    # This converts xn--pple-43d to the Unicode representation
                    decoded = label.encode("ascii").decode("idna")
                    decoded_labels.append(decoded)
                except (UnicodeError, UnicodeDecodeError):
                    # If IDNA decoding fails, try a manual approach
                    # xn--pple-43d -> remove xn-- prefix as a fallback
                    decoded_labels.append(label[4:])
            else:
                decoded_labels.append(label)
        return ".".join(decoded_labels)
    except Exception:
        # If decoding fails entirely, return original
        return hostname

def to_visual_skeleton(text: str) -> str:
    """Normalizes Unicode text and maps confusable glyphs to standard Latin equivalents.

    Steps:
    1. Decode any Punycode (xn--) labels to expose homoglyphs.
    2. NFD Unicode normalization.
    3. Map confusable characters to their Latin skeleton equivalents.
    4. Skip non-spacing marks (accents).
    """
    # Decode Punycode labels first. Punycode labels routinely contain hyphens
    # (e.g. 'xn--pple-43d'), so decoding is done label-by-label on '.' instead
    # of with a regex that stops at the first hyphen (regression BUG-03).
    parts: List[str] = []
    for piece in re.split(r"(\.)", text):
        if "." in piece or not piece:
            parts.append(piece)
        else:
            parts.append(punycode_to_unicode(piece))
    text = "".join(parts)

    # NFD normalization
    decomposed = unicodedata.normalize("NFD", text.lower())
    skeleton_chars = []
    for char in decomposed:
        if char in CONFUSABLES_MAP:
            skeleton_chars.append(CONFUSABLES_MAP[char])
        elif unicodedata.category(char) != "Mn": # Skip non-spacing marks/accents
            skeleton_chars.append(char)
    return "".join(skeleton_chars)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        # La fila DP debe propagarse en cada iteración; si esta asignación queda
        # fuera del bucle externo la distancia se calcula mal para cadenas cortas
        # (p. ej. lev('t','microsoft') devolvía 0 y clasificaba 't.ly'/'t.is' como
        # suplantación de Microsoft). Regresión detectada en la auditoría.
        previous_row = current_row

    return previous_row[-1]

def analyze_homoglyphs(display_host: str, registered_domain: str = "") -> Dict[str, Any]:
    """Examines a host string for homoglyph substitution targeting prominent brands.

    Returns dict with key 'is_spoofing' as primary key for compatibility with
    HybridM0Model and extension background.js. Implements proper IDN/Punycode
    decoding to prevent evasion via xn-- labels without generating false positives.

    Deteccion en dos capas:
      1. Regla principal: esqueleto visual del host completo (con etiquetas xn--
         decodificada una a una) contra marcas objetivo; ataca `xn--pple-43d.com`.
      2. Heuristica auxiliar (C-2, acotada): solo senala cuando la etiqueta xn--
         esta en el DOMINIO REGISTRADO (no en un subdominio) y el dominio
         registrado no es ya el dominio oficial de la marca. Un subdominio punycode
         bajo el dominio oficial real (xn--caf-dma.apple.com) NO es suplantacion.
    """
    # Decode Punycode first, then compute visual skeleton
    decoded_host = punycode_to_unicode(display_host)
    skeleton = to_visual_skeleton(display_host)
    has_confusables = any(c in CONFUSABLES_MAP for c in decoded_host.lower())

    # HEURISTIC (C-2, acotada tras hallazgo de la auditoria tecnica final): solo
    # senalar suplantacion por punycode cuando la propia etiqueta xn-- esta en el
    # DOMINIO REGISTRADO (no en un subdominio) y el dominio registrado NO es ya el
    # dominio oficial de la marca. Un subdominio punycode bajo el dominio oficial
    # real (p. ej. xn--caf-dma.apple.com con registrado apple.com) pertenece al
    # titular de la marca y NO es suplantacion. El caso de ataque real
    # (xn--pple-43d.com) ya lo detecta la regla principal por distancia de
    # esqueleto visual, con lo que la heuristica deja de generar ese falso positivo.
    registered_labels = registered_domain.lower().rstrip(".").split(".")
    registered_has_punycode = any(label.startswith("xn--") for label in registered_labels)
    is_known_brand_registered = punycode_to_unicode(registered_domain).lower().rstrip(".") in {
        "apple.com", "microsoft.com", "google.com", "paypal.com",
        "facebook.com", "amazon.com", "netflix.com", "instagram.com"
    }
    # el dominio registrado, en su forma cruda (sin decodificar), no debe ser ya el oficial
    registered_is_official_brand = registered_domain.lower().rstrip(".") in {
        "apple.com", "microsoft.com", "google.com", "paypal.com",
        "facebook.com", "amazon.com", "netflix.com", "instagram.com"
    }
    
    if registered_has_punycode and is_known_brand_registered and not registered_is_official_brand:
        # xn-- en el dominio registrado apuntando a una marca conocida - riesgo de homoglifo
        has_confusables = True  # Ensure confusable flag is set
    
    best_brand = "none"
    min_distance = 999

    for brand in POPULAR_TARGET_BRANDS:
        # Check if the visual skeleton contains or closely resembles the brand
        if brand in skeleton:
            dist = 0
        else:
            dist = levenshtein_distance(skeleton.split(".")[0], brand)

        if dist < min_distance:
            min_distance = dist
            best_brand = brand

    # An attack is detected if visual skeleton matches brand but registered domain is not the official brand domain
    is_spoofing = False
    decoded_registered = punycode_to_unicode(registered_domain).lower().rstrip(".")
    if min_distance <= 1:
        official_domain = f"{best_brand}.com"
        if decoded_registered != official_domain:
            is_spoofing = True
    
    # Additional (C-2 acotada): senalar solo si el punycode esta en el DOMINIO
    # REGISTRADO apuntando a una marca y el dominio registrado no es ya el oficial.
    if registered_has_punycode and is_known_brand_registered and not registered_is_official_brand and not is_spoofing:
        # Heuristic: xn-- registrable domain impersonating a known brand without proper match
        is_spoofing = True
    
    return {
        "is_spoofing": bool(is_spoofing),  # Primary key for compatibility with hybrid_model.py and background.js
        "homoglyph_brand_spoofing_detected": bool(is_spoofing),  # Kept for backward compatibility
        "visual_skeleton": skeleton,
        "closest_brand_target": best_brand if min_distance <= 2 else "none",
        "visual_edit_distance": min_distance,
        "contains_confusable_characters": float(has_confusables)
    }