#!/usr/bin/env python
"""Test script for homoglyphs fixes."""
import sys
sys.path.insert(0, '.')

from src.phishguard_ml.homoglyphs import analyze_homoglyphs

# Test the IDN/Punycode case from the bug report
# https://www.xn--pple-43d.com/login (apple.com cirílico)
result = analyze_homoglyphs('www.xn--pple-43d.com', 'apple.com')
print('Punycode test (xn--pple-43d):')
print(f'  is_spoofing: {result["is_spoofing"]}')
print(f'  homoglyph_brand_spoofing_detected: {result["homoglyph_brand_spoofing_detected"]}')
print(f'  closest_brand: {result["closest_brand_target"]}')
skeleton = result["visual_skeleton"]
# Avoid repr issue by converting to string safely
skeleton_str = str(skeleton)
print(f'  visual_skeleton length: {len(skeleton_str)}')
print(f'  visual_skeleton contains "apple": {"apple" in skeleton_str.lower()}')
print(f'  visual_skeleton contains "pple": {"pple" in skeleton_str.lower()}')
print()

# Test a legitimate domain
result2 = analyze_homoglyphs('www.google.com', 'google.com')
print('Legitimate domain test:')
print(f'  is_spoofing: {result2["is_spoofing"]}')
print(f'  closest_brand: {result2["closest_brand_target"]}')
print()

# Test Cyrillic homoglyph (direct Unicode, not Punycode)
result3 = analyze_homoglyphs('www.facebuuk.com', 'facebook.com')
print('Cyrillic homoglyph test (direct Unicode):')
print(f'  is_spoofing: {result3["is_spoofing"]}')
print(f'  closest_brand: {result3["closest_brand_target"]}')
skeleton3 = str(result3["visual_skeleton"])
print(f'  visual_skeleton contains "facebook": {"facebook" in skeleton3.lower()}')
print()

# Test that legitimate domains without spoofing return is_spoofing=False
result4 = analyze_homoglyphs('www.microsoft.com', 'microsoft.com')
print('Legitimate MS test:')
print(f'  is_spoofing: {result4["is_spoofing"]}')
print(f'  closest_brand: {result4["closest_brand_target"]}')