#!/usr/bin/env python
"""Debug script for Punycode homoglyph detection."""
import re
import unicodedata

CONFUSABLES_MAP = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u0442': 't', '\u0432': 'b', '\u044d': 'e',
    '\u03b1': 'a', '\u03bf': 'o', '\u03bd': 'v', '\u03c1': 'p',
}

def punycode_to_unicode(hostname):
    try:
        labels = hostname.split(".")
        decoded_labels = []
        for label in labels:
            if label.lower().startswith("xn--"):
                decoded = label.encode("idna").decode("utf-8")
                decoded_labels.append(decoded)
            else:
                decoded_labels.append(label)
        return ".".join(decoded_labels)
    except Exception as e:
        return hostname, str(e)

def to_visual_skeleton(text):
    def decode_label(match):
        label = match.group(0)
        return punycode_to_unicode(label)[0]
    text = re.sub(r'xn--[a-z0-9]+', decode_label, text, flags=re.IGNORECASE)
    decomposed = unicodedata.normalize("NFD", text.lower())
    skeleton_chars = []
    for char in decomposed:
        if char in CONFUSABLES_MAP:
            skeleton_chars.append(CONFUSABLES_MAP[char])
        elif unicodedata.category(char) != "Mn":
            skeleton_chars.append(char)
    return "".join(skeleton_chars)

# Test
host = "www.xn--pple-43d.com"
print(f"Original host: {host}")
decoded = punycode_to_unicode(host)
print(f"Decoded: {decoded}")
if isinstance(decoded, tuple):
    print(f"Error: {decoded[1]}")
    decoded = decoded[0]
skeleton = to_visual_skeleton(decoded)
print(f"Skeleton: {skeleton}")

# Check if Cyrillic characters are in the decoded host
has_cyrillic_lookalikes = any(c in CONFUSABLES_MAP for c in decoded.lower())
print(f"Has confusable chars: {has_cyrillic_lookalikes}")

# Test the brand check
brand = "apple"
print(f"'apple' in skeleton: {'apple' in skeleton}")
print(f"apple in decoded: {'apple' in decoded.lower()}")

# Now test with the actual analyze_homoglyphs function
sys_path = 'D:/Proyects/Seguridad_Informacion'
import os
os.chdir(sys_path)
from src.phishguard_ml.homoglyphs import analyze_homoglyphs

result = analyze_homoglyphs('www.xn--pple-43d.com', 'apple.com')
print(f"\nanalyze_homoglyphs result:")
print(f"  is_spoofing: {result['is_spoofing']}")
print(f"  homoglyph_brand_spoofing_detected: {result['homoglyph_brand_spoofing_detected']}")
print(f"  closest_brand_target: {result['closest_brand_target']}")
print(f"  visual_skeleton: {result['visual_skeleton'][:60]}...")
print(f"  contains_confusable: {result['contains_confusable_characters']}")