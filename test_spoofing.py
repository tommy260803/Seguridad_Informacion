#!/usr/bin/env python
"""Test spoofing detection with mismatched registered domain."""
import sys
sys.path.insert(0, '.')

from src.phishguard_ml.homoglyphs import analyze_homoglyphs

print("=" * 60)
print("SPOOFIGHTING DETECTION TESTS (mismatched registered domain)")
print("=" * 60)

# Test A: Cyrillic homoglyph with mismatched registered domain
result = analyze_homoglyphs('www.facebuuk.com', 'google.com')
print(f"\nA. Cyrillic homoglyph with MISMATCHED registered domain:")
print(f"   Host: www.facebuuk.com, Registered: google.com")
print(f"   is_spoofing: {result['is_spoofing']} (expected: True - homoglyph but wrong brand)")
print(f"   closest_brand: {result['closest_brand_target']}")
print(f"   visual_skeleton: {result['visual_skeleton'][:60]}")

# Test B: Legitimate domain with matching registered domain
result2 = analyze_homoglyphs('www.facebuuk.com', 'facebuuk.com')
print(f"\nB. Cyrillic homoglyph with matching registered domain:")
print(f"   Host: www.facebuuk.com, Registered: facebuuk.com (not a real brand)")
print(f"   is_spoofing: {result2['is_spoofing']} (expected: False - registered domain matches)")
print(f"   closest_brand: {result2['closest_brand_target']}")

# Test C: Punycode attack with mismatched registered domain
result3 = analyze_homoglyphs('www.xn--pple-43d.com', 'microsoft.com')
print(f"\nC. Punycode attack with MISMATCHED registered domain:")
print(f"   Host: www.xn--pple-43d.com, Registered: microsoft.com")
print(f"   is_spoofing: {result3['is_spoofing']} (expected: True - xn-- with known brand mismatch)")
print(f"   closest_brand: {result3['closest_brand_target']}")

# Test D: Legitimate Microsoft with matching domain
result4 = analyze_homoglyphs('www.microsoft.com', 'microsoft.com')
print(f"\nD. Legitimate Microsoft (matching domain):")
print(f"   Host: www.microsoft.com, Registered: microsoft.com")
print(f"   is_spoofing: {result4['is_spoofing']} (expected: False)")
print(f"   closest_brand: {result4['closest_brand_target']}")

# Test E: Legitimate Google with matching domain
result5 = analyze_homoglyphs('www.google.com', 'google.com')
print(f"\nE. Legitimate Google (matching domain):")
print(f"   Host: www.google.com, Registered: google.com")
print(f"   is_spoofing: {result5['is_spoofing']} (expected: False)")
print(f"   closest_brand: {result5['closest_brand_target']}")

print("\n" + "=" * 60)
print("TESTS COMPLETED")
print("=" * 60)