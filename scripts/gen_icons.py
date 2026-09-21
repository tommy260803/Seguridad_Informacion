"""Generate PNG icons for Chrome extension."""
import struct
import zlib
from pathlib import Path

def create_png(size, bg_r, bg_g, bg_b, shield_r, shield_g, shield_b):
    """Create a simple PNG with shield shape."""
    width = height = size
    pixels = []

    cx, cy = size // 2, size // 2
    shield_w = size * 0.35
    shield_h = size * 0.45

    for y in range(height):
        row = []
        for x in range(width):
            # Background rounded rect
            margin = size * 0.05
            in_bg = (margin <= x <= size - margin and margin <= y <= size - margin)

            # Shield shape
            dx = (x - cx) / shield_w
            dy = (y - cy) / shield_h
            in_shield = (dx * dx + dy * dy * 0.6 <= 1.0 and dy >= -0.8 and dy <= 0.9)

            if in_shield:
                row.extend([shield_r, shield_g, shield_b, 255])
            elif in_bg:
                row.extend([bg_r, bg_g, bg_b, 255])
            else:
                row.extend([0, 0, 0, 0])
        pixels.append(bytes([0] + row))  # filter byte + RGBA

    raw = b"".join(pixels)

    def chunk(ctype, data):
        c = ctype + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw)

    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")

icons_dir = Path("extension/icons")
icons_dir.mkdir(parents=True, exist_ok=True)

for size in [16, 48, 128]:
    png = create_png(size, 22, 33, 62, 233, 69, 96)  # #16213e bg, #e94560 shield
    (icons_dir / f"icon{size}.png").write_bytes(png)
    print(f"Created icon{size}.png ({len(png)} bytes)")

print("All icons generated")
