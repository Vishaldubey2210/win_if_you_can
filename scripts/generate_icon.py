import struct
import zlib
import math

def generate_marketplace_icon(filepath="vscode-extension/media/icon.png", size=128):
    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)

    # High-resolution supersampling for crisp anti-aliasing (2x = 256x256)
    scale = 2
    w = size * scale
    h = size * scale

    # Helper: distance from point to segment
    def dist_to_segment(px, py, x1, y1, x2, y2):
        dx = x2 - x1
        dy = y2 - y1
        if dx == 0 and dy == 0:
            return math.hypot(px - x1, py - y1)
        t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
        proj_x = x1 + t * dx
        proj_y = y1 + t * dy
        return math.hypot(px - proj_x, py - proj_y)

    # Point in polygon test for shield
    # Shield shape points normalized to 0..1
    shield_pts = [
        (0.50, 0.16),  # top center tip
        (0.80, 0.22),  # top right corner
        (0.80, 0.52),  # right curve start
        (0.50, 0.88),  # bottom tip
        (0.20, 0.52),  # left curve start
        (0.20, 0.22),  # top left corner
    ]
    poly = [(p[0] * w, p[1] * h) for p in shield_pts]

    def point_in_poly(x, y):
        inside = False
        n = len(poly)
        p1x, p1y = poly[0]
        for i in range(n + 1):
            p2x, p2y = poly[i % n]
            if y > min(p1y, p2y):
                if y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        if p1x == p2x or x <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y
        return inside

    # Checkmark segments
    c1 = (0.38 * w, 0.51 * h)
    c2 = (0.47 * w, 0.62 * h)
    c3 = (0.64 * w, 0.40 * h)

    grid = []
    for y in range(h):
        row = []
        ny = y / h
        for x in range(w):
            nx = x / w
            
            # Rounded container background: smooth squircle
            cx, cy = x - w / 2, y - h / 2
            # Superellipse / rounded rect
            dist_center = math.hypot(cx, cy)
            corner_rad = 0.42 * w
            in_container = (abs(cx) < 0.44 * w and abs(cy) < 0.44 * h) or (dist_center < 0.48 * w)
            
            # Distance to container edge for anti-aliasing
            edge_dist = max(abs(cx) / (0.45 * w), abs(cy) / (0.45 * h))
            container_alpha = 1.0 if edge_dist < 0.95 else max(0.0, 1.0 - (edge_dist - 0.95) / 0.08)

            if container_alpha <= 0:
                row.append((0, 0, 0, 0))
                continue

            # Deep tech navy background gradient
            bg_r = int(11 + 10 * ny)
            bg_g = int(18 + 15 * ny)
            bg_b = int(32 + 25 * ny)

            # Check shield fill
            in_shield = point_in_poly(x, y)
            
            # Checkmark stroke
            d_check1 = dist_to_segment(x, y, c1[0], c1[1], c2[0], c2[1])
            d_check2 = dist_to_segment(x, y, c2[0], c2[1], c3[0], c3[1])
            d_check = min(d_check1, d_check2)
            check_width = 0.038 * w

            # Shield border
            min_edge_dist = 1e9
            for i in range(len(poly)):
                p_a = poly[i]
                p_b = poly[(i + 1) % len(poly)]
                d_seg = dist_to_segment(x, y, p_a[0], p_a[1], p_b[0], p_b[1])
                if d_seg < min_edge_dist:
                    min_edge_dist = d_seg

            border_width = 0.032 * w

            r, g, b = bg_r, bg_g, bg_b

            if in_shield:
                # Inside shield: glowing gradient (cyan to azure blue)
                s_ratio = (y - 0.16 * h) / (0.72 * h)
                s_ratio = max(0.0, min(1.0, s_ratio))
                r = int(14 * (1 - s_ratio) + 20 * s_ratio)
                g = int(165 * (1 - s_ratio) + 90 * s_ratio)
                b = int(233 * (1 - s_ratio) + 220 * s_ratio)

            if min_edge_dist < border_width:
                # Shield outer ring: bright cyan
                blend = min(1.0, (border_width - min_edge_dist) / 2.0)
                br, bg, bb = 56, 189, 248  # #38bdf8 Sky Cyan
                r = int(r * (1 - blend) + br * blend)
                g = int(g * (1 - blend) + bg * blend)
                b = int(b * (1 - blend) + bb * blend)

            if d_check < check_width:
                # Checkmark: Crisp pure white / bright emerald
                blend_c = min(1.0, (check_width - d_check) / 1.5)
                cr, cg, cb = 255, 255, 255
                r = int(r * (1 - blend_c) + cr * blend_c)
                g = int(g * (1 - blend_c) + cg * blend_c)
                b = int(b * (1 - blend_c) + cb * blend_c)

            a = int(container_alpha * 255)
            row.append((r, g, b, a))
        grid.append(row)

    # Downsample by 2x supersampling to get final 128x128 pixels
    final_pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            r_acc, g_acc, b_acc, a_acc = 0, 0, 0, 0
            for dy in range(scale):
                for dx in range(scale):
                    pr, pg, pb, pa = grid[y * scale + dy][x * scale + dx]
                    r_acc += pr * pa
                    g_acc += pg * pa
                    b_acc += pb * pa
                    a_acc += pa
            total_samples = scale * scale
            avg_a = a_acc / total_samples
            if avg_a > 0:
                avg_r = (r_acc / a_acc)
                avg_g = (g_acc / a_acc)
                avg_b = (b_acc / a_acc)
            else:
                avg_r, avg_g, avg_b = 0, 0, 0
            row.append((int(avg_r), int(avg_g), int(avg_b), int(avg_a)))
        final_pixels.append(row)

    # Encode PNG
    raw = bytearray()
    for row in final_pixels:
        raw.append(0)  # Filter none
        for r, g, b, a in row:
            raw.extend((r, g, b, a))

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    png += chunk(b'IEND', b'')

    with open(filepath, 'wb') as f:
        f.write(png)
    print(f"Generated {size}x{size} PNG at {filepath} ({len(png)} bytes)")

if __name__ == "__main__":
    generate_marketplace_icon()
