#!/usr/bin/env python3
"""
Crack axis encoding using the new test files where axis values don't overlap.
"""

import struct
import ezdxf
from pathlib import Path


def is_separator(b):
    return (b & 0x07) == 0x07 and b >= 0x07


def parse_all(oot_path, dxf_path):
    # DXF vertices
    doc = ezdxf.readfile(dxf_path)
    msp = doc.modelspace()
    vm, vl, fl = {}, [], []
    for e in msp:
        if e.dxftype() == '3DFACE':
            tri = []
            for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2]:
                key = (round(p[0], 4), round(p[1], 4), round(p[2], 4))
                if key not in vm:
                    vm[key] = len(vl)
                    vl.append(key)
                tri.append(vm[key])
            fl.append(tuple(tri))

    # OOT
    with open(oot_path, 'rb') as f:
        raw = f.read()

    vi = raw.find(b'Variant\x00')
    ds = vi + 8
    n_verts = raw[ds + 12]
    n_faces = raw[ds + 19]

    attr_suffix = bytes([0x00, 0x05, 0x40, 0x04, 0x00, 0x0A, 0x20, 0x08, 0x07])
    attr_pos = raw.find(attr_suffix, ds)
    if attr_pos < 0:
        attr_pos = len(raw)

    face_marker = -1
    for i in range(attr_pos - 2, ds + 30, -1):
        if raw[i] == 0x20 and raw[i + 1] == 0x00:
            face_marker = i
            break

    coord_region = raw[ds + 23:face_marker] if face_marker > 0 else raw[ds + 23:attr_pos]

    # Parse coord section into groups
    groups = []
    prev = [0] * 8
    pos = 0
    while pos < len(coord_region):
        b = coord_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(coord_region):
                break
            stored = list(coord_region[pos + 1:pos + 1 + nb])
            if stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r = stored + [0] * (8 - nb)
                kind = 'FULL'
            else:
                r = [prev[0]] + stored + list(prev[nb + 1:8])
                kind = 'DELTA'
            r = (r + [0] * 8)[:8]
            val = struct.unpack('>d', bytes(r))[0]
            prev = r
            groups.append({
                'value': val, 'kind': kind, 'n_bytes': nb,
                'tags': [], 'seps': [],
            })
            pos += 1 + nb
        elif is_separator(b):
            if groups:
                groups[-1]['seps'].append(b)
            pos += 1
        elif pos + 1 < len(coord_region):
            b2 = coord_region[pos + 1]
            hi_cls = b & 0xE0
            cls = {0x20: '20', 0x40: '40', 0x60: '60', 0x80: '80',
                   0xA0: 'A0', 0xC0: 'C0', 0xE0: 'E0'}.get(hi_cls, '{:02X}'.format(b))
            if groups:
                groups[-1]['tags'].append({
                    'cls': cls, 'byte1': b, 'byte2': b2,
                    'lo': b2 & 0x0F, 'hi': (b2 >> 4) & 0x0F,
                    'tag_str': '{}:{:02X}'.format(cls, b2),
                })
            pos += 2
        else:
            break

    return vl, fl, groups, n_verts, n_faces


def analyze(name, stem):
    oot = stem + ".00t"
    dxf = stem + ".dxf"
    if not Path(oot).exists():
        print(f"  SKIP: {oot} not found")
        return

    vl, fl, groups, nv, nf = parse_all(oot, dxf)

    print(f"\n{'=' * 78}")
    print(f"  {name}")
    print(f"  Header: {nv} verts (header), {nf} faces")
    print(f"  DXF: {len(vl)} verts, {len(fl)} faces")
    print(f"{'=' * 78}")

    # DXF vertices
    for i, v in enumerate(vl):
        print(f"  V{i}: ({v[0]:.2f}, {v[1]:.2f}, {v[2]:.2f})")

    # Axis ranges
    xs = sorted(set(round(v[0], 4) for v in vl))
    ys = sorted(set(round(v[1], 4) for v in vl))
    zs = sorted(set(round(v[2], 4) for v in vl))
    print(f"\n  X values: {xs}")
    print(f"  Y values: {ys}")
    print(f"  Z values: {zs}")

    # For each coord, determine axis from DXF
    all_vals = set(xs) | set(ys) | set(zs)
    print(f"\n  Coord groups ({len(groups)}):")

    for i, g in enumerate(groups):
        val = round(g['value'], 4)
        in_x = val in set(round(x, 4) for x in xs)
        in_y = val in set(round(y, 4) for y in ys)
        in_z = val in set(round(z, 4) for z in zs)
        axes = []
        if in_x: axes.append('X')
        if in_y: axes.append('Y')
        if in_z: axes.append('Z')
        axis_str = '/'.join(axes) if axes else '??'

        # First non-C0 tag
        first_tag = None
        for t in g['tags']:
            if t['cls'] != 'C0':
                first_tag = t
                break
        ft_str = first_tag['tag_str'] if first_tag else 'none'
        ft_cls = first_tag['cls'] if first_tag else '-'
        ft_lo = first_tag['lo'] if first_tag else -1
        ft_hi = first_tag['hi'] if first_tag else -1
        ft_b2 = first_tag['byte2'] if first_tag else -1

        # C0 tags
        c0_tags = [t for t in g['tags'] if t['cls'] == 'C0']
        c0_str = ', '.join(t['tag_str'] for t in c0_tags) if c0_tags else '-'

        # All tags
        all_tags = ', '.join(t['tag_str'] for t in g['tags'])

        print(f"    #{i}: {val:12.4f} ({g['kind']:5s})  axis={axis_str:5s}  "
              f"first={ft_str:8s} cls={ft_cls} lo={ft_lo:X} hi={ft_hi:X}  "
              f"C0=[{c0_str}]")
        if len(g['tags']) > 0:
            print(f"        all tags: [{all_tags}]")
        if g['seps']:
            print(f"        seps: {['0x{:02X}'.format(s) for s in g['seps']]}")

    return vl, fl, groups


# Run all files
files = [
    ("PRISM (non-overlapping axes)", "exampleFiles/tri-crack-prism"),
    ("GRID SLAB (many verts, 2 per axis)", "exampleFiles/tri-crack-grid-slab"),
    ("STEPPED PYRAMID (3+ Z values)", "exampleFiles/tri-crack-Stepped-pyramid"),
    # Old files for comparison
    ("TRIANGLE", "exampleFiles/tri-crack-triangle"),
    ("PLANE", "exampleFiles/tri-crack"),
    ("CUBE", "exampleFiles/tri-crack-solid"),
]

for name, stem in files:
    analyze(name, stem)
