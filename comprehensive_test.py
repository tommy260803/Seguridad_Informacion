#!/usr/bin/env python
"""Comprehensive homoglyph tests."""
import sys
sys.path.insert(0, '.')

from src.phishguard_ml.homoglyphs import analyze_homoglyphs

print("=" * 60)
print("COMPREHENSIVE HOMOGLYPH TESTS")
print("=" * 60)

# Test 1: Punycode attack (xn--pple-43d -> apple.com)
result = analyze_homoglyphs('www.xn--pple-43d.com', 'apple.com')
print(f"\n1. Punycode attack: www.xn--pple-43d.com (registered: apple.com)")
print(f"   is_spoofing: {result['is_spoofing']} (expected: True)")
print(f"   homoglyph_brand_spoofing_detected: {result['homoglyph_brand_spoofing_detected']}")

# Test 2: Legitimate domain without www
result2 = analyze_homoglyphs('google.com', 'google.com')
print(f"\n2. Legitimate (no www): google.com (registered: google.com)")
print(f"   is_spoofing: {result2['is_spoofing']} (expected: False)")
print(f"   closest_brand: {result2['closest_brand_target']}")

# Test 3: Legitimate domain with www
result3 = analyze_homoglyphs('www.google.com', 'google.com')
print(f"\n3. Legitimate (with www): www.google.com (registered: google.com)")
print(f"   is_spoofing: {result3['is_spoofing']} (expected: False)")
print(f"   closest_brand: {result3['closest_brand_target']}")

# Test 4: Cyrillic homoglyph (direct Unicode)
result4 = analyze_homoglyphs('www.facebuuk.com', 'facebook.com')
print(f"\n4. Cyrillic homoglyph: www.facebuuk.com (registered: facebook.com)")
print(f"   is_spoofing: {result4['is_spoofing']} (expected: True)")
print(f"   closest_brand: {result4['closest_brand_target']}")

# Test 5: Legitimate Microsoft
result5 = analyze_homoglyphs('www.microsoft.com', 'microsoft.com')
print(f"\n5. Legitimate MS: www.microsoft.com (registered: microsoft.com)")
print(f"   is_spoofing: {result5['is_spoofing']} (expected: False)")
print(f"   closest_brand: {result5['closest_brand_target']}")

# Test 6: Non-brand domain with xn--
result6 = analyze_homoglyphs('www.xn--example-abc.com', 'unknown.com')
print(f"\n6. xn-- non-brand: www.xn--example-abc.com (registered: unknown.com)")
print(f"   is_spoofing: {result6['is_spoofing']} (expected: False - not a known brand)")
print(f"   closest_brand: {result6['closest_brand_target']}")

# Test 7: Punycode non-brand
result7 = analyze_homoglyphs('www.xn--pple-43d.com', 'notapple.com')
print(f"\n7. Punycode non-brand: www.xn--pple-43d.com (registered: notapple.com)")
print(f"   is_spoofing: {result7['is_spoofing']} (expected: False - not a known brand)")
print(f"   closest_brand: {result7['closest_brand_target']}")

print("\n" + "=" * 60)
print("TESTS COMPLETED")
print("=" * 60)