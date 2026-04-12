#!/usr/bin/env python3
"""Generate APT PWA icons. Run once: python3 gen_icons.py"""
import struct, zlib, os

def png(size):
    """Generate a minimal valid PNG: dark background + blue circle crosshair."""
    w = h = size
    # Draw each pixel: dark bg (#0d1117) with a blue (#4299e1) crosshair circle
    cx, cy, r = w // 2, h // 2, int(w * 0.42)
    r2 = int(w * 0.18)
    stroke = max(1, w // 40)

    rows = []
    for y in range(h):
        row = [0]  # filter byte
        for x in range(w):
            dx, dy = x - cx, y - cy
            dist = (dx*dx + dy*dy) ** 0.5
            # Outer ring
            on_outer = abs(dist - r) <= stroke
            # Inner ring
            on_inner = abs(dist - r2) <= stroke
            # Cross lines (only within outer ring)
            on_cross = (dist <= r) and (
                (abs(dx) <= stroke and abs(dy) >= r2 + stroke) or
                (abs(dy) <= stroke and abs(dx) >= r2 + stroke)
            )
            # Center dot
            on_dot = dist <= stroke * 2

            if on_outer or on_inner or on_cross or on_dot:
                row += [0x42, 0x99, 0xe1]  # blue
            else:
                row += [0x0d, 0x11, 0x17]  # dark bg
        rows.append(bytes(row))

    raw = b''.join(rows)
    compressed = zlib.compress(raw)

    def chunk(tag, data):
        c = struct.pack('>I', len(data)) + tag + data
        return c + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)

    ihdr = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)  # 8-bit RGB
    return (
        b'\x89PNG\r\n\x1a\n' +
        chunk(b'IHDR', ihdr) +
        chunk(b'IDAT', compressed) +
        chunk(b'IEND', b'')
    )

out = os.path.join(os.path.dirname(__file__), 'icons')
os.makedirs(out, exist_ok=True)
for size in (192, 512):
    path = os.path.join(out, f'icon-{size}.png')
    with open(path, 'wb') as f:
        f.write(png(size))
    print(f'Written: {path}')
