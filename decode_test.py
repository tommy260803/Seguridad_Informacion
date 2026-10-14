#!/usr/bin/env python
label = 'xn--pple-43d'
print(f"label: {repr(label)}")
print(f"label.isascii(): {label.isascii()}")
try:
    encoded = label.encode('ascii')
    print(f"encoded: {repr(encoded)}")
except Exception as e:
    print(f"encode error: {e}")

try:
    decoded = encoded.decode('idna')
    print(f"decoded: {repr(decoded)}")
except Exception as e:
    print(f"decode error: {e}")