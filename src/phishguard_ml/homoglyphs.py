"""
Dual Homoglyph and Unicode TR39 Confusable Normalizer for PhishGuard.
Projects visual characters to their Latin visual skeleton to instantly expose homoglyph brand impersonation.
"""

from __future__ import annotations

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

def to_visual_skeleton(text: str) -> str:
    """Normalizes Unicode text and maps confusable glyphs to standard Latin equivalents."""
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
        previous_row = current_row

    return previous_row[-1]

def analyze_homoglyphs(display_host: str, registered_domain: str = "") -> Dict[str, Any]:
    """
    Examines a host string for homoglyph substitution targeting prominent brands.
    """
    skeleton = to_visual_skeleton(display_host)
    has_confusables = any(c in CONFUSABLES_MAP for c in display_host.lower())

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
    if min_distance <= 1:
        official_domain = f"{best_brand}.com"
        if registered_domain.lower() != official_domain:
            is_spoofing = True

    return {
        "homoglyph_brand_spoofing_detected": float(is_spoofing),
        "visual_skeleton": skeleton,
        "closest_brand_target": best_brand if min_distance <= 2 else "none",
        "visual_edit_distance": min_distance,
        "contains_confusable_characters": float(has_confusables)
    }
