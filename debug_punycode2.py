#!/usr/bin/env python
"""Debug Punycode decoding."""
import sys
sys.path.insert(0, '.')

# Test the punycode_to_unicode function directly
import re
import unicodedata

CONFUSABLES_MAP = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u0442': 't', '\u0432': 'b', '\u044d': 'e',
}

def punycode_to_unicode(hostname):
    try:
        labels = hostname.split(".")
        decoded_labels = []
        for label in labels:
            if label.lower().startswith("xn--"):
                try:
                    decoded = label.encode("ascii").decode("idna")
                    decoded_labels.append(decoded)
                except (UnicodeError, UnicodeDecodeError):
                    decoded_labels.append(label[4:])
            else:
                decoded_labels.append(label)
        return ".".join(decoded_labels)
    except Exception:
        return hostname

# Test
host = "www.xn--pple-43d.com"
print(f"Original host: {host}")
decoded = punycode_to_unicode(host)
print(f"Decoded: {decoded}")

# Check what the labels are
labels = host.split(".")
print(f"Labels: {labels}")
for i, label in enumerate(labels):
    print(f"  Label {i}: {label}, startswith xn--: {label.lower().startswith('xn--')}")
    if label.lower().startswith('xn--'):
        try:
            d = label.encode("ascii").decode("idna")
            print(f"    Decoded: {d}")
        except Exception as e:
            print(f"    Decode error: {e}")
            print(f"    Fallback (remove xn--): {label[4:]}")

# Now test the full to_visual_skeleton
def to_visual_skeleton(text):
    def decode_label(match):
        label = match.group(0)
        return punycode_to_unicode(label)
    text = re.sub(r'xn--[a-z0-9]+', decode_label, text, flags=re.IGNORECASE)
    decomposed = unicodedata.normalize("NFD", text.lower())
    skeleton_chars = []
    for char in decomposed:
        if char in CONFUSABLES_MAP:
            skeleton_chars.append(CONFUSABLES_MAP[char])
        elif unicodedata.category(char) != "Mn":
            skeleton_chars.append(char)
    return "".join(skeleton_chars)

skeleton = to_visual_skeleton(host)
print(f"\nSkeleton: {skeleton}")
print(f"Skeleton length: {len(skeleton)}")

# Check if 'apple' is in skeleton
print(f"'apple' in skeleton.lower(): {'apple' in skeleton.lower()}")
print(f"'pple' in skeleton.lower(): {'pple' in skeleton.lower()}")

# Check the confusable map
has_confusables = any(c in CONFUSABLES_MAP for c in host.lower())
print(f"Has confusable chars in host: {has_confusables}")