#!/usr/bin/env python3
"""
Crack axis tracking: how do coord section tags encode X vs Y vs Z?

For each file, we know the DXF vertices. We know the coord values.
We can work backwards: each coord value IS a specific axis value for
specific vertices. The tag after it must encode which axis.

Strategy: collect (coord_value, first_tag_after, known_axis) tuples
across all files and find the pattern.
"""

import struct
import ezdxf
from pathlib import Path


def is_separator(b):
    return (b & 0x07) == 0x07 and b >= 0x07


def parse_file(oot_path, dxf_path):
    """Extract coord values, tags, and DXF ground truth."""
    # DXF
    doc = ezdxf.readfile(dxf_path)
    msp = doc.modelspace()
    vm, vl = {}, []
    for e in msp:
        if e.dxftype() == '3DFACE':
            for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2, e.dxf.vtx3]:
                key = (round(p[0], 4), round(p[1], 4), round(p[2], 4))
                if key not in vm:
                    vm[key] = len(vl)
                    vl.append(key)

    # OOT coord section
    with open(oot_path, 'rb') as f:
        raw = f.read()

    vi = raw.find(b'Variant\x00')
    ds = vi + 8

    attr_suffix = bytes([0x00, 0x05, 0x40, 0x04, 0x00, 0x0A, 0x20, 0x08, 0x07])
    attr_pos = raw.find(attr_suffix, ds)
    if attr_pos < 0:
        attr_pos = len(raw)

    face_marker = -1
    for i in range(attr_pos - 2, ds + 30, -1):
        if raw[i] == 0x20 and raw[i+1] == 0x00:
            face_marker = i
            break

    coord_region = raw[ds+23:face_marker] if face_marker > 0 else raw[ds+23:attr_pos]

    # Parse coord values and ALL following tags until next coord
    groups = []
    prev = [0]*8
    pos = 0
    while pos < len(coord_region):
        b = coord_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(coord_region):
                break
            stored = list(coord_region[pos+1:pos+1+nb])
            if stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r = stored + [0]*(8-nb)
                kind = 'FULL'
            else:
                r = [prev[0]] + stored + list(prev[nb+1:8])
                kind = 'DELTA'
            r = (r + [0]*8)[:8]
            val = struct.unpack('>d', bytes(r))[0]
            prev = r
            groups.append({
                'value': val,
                'kind': kind,
                'n_bytes': nb,
                'tags': [],
                'seps': [],
            })
            pos += 1 + nb
        elif is_separator(b):
            if groups:
                groups[-1]['seps'].append(b)
            pos += 1
        elif pos + 1 < len(coord_region):
            b2 = coord_region[pos+1]
            hi_cls = b & 0xE0
            cls = {0x20:'20', 0x40:'40', 0x60:'60', 0x80:'80',
                   0xA0:'A0', 0xC0:'C0', 0xE0:'E0'}.get(hi_cls, f'{b:02X}')
            if groups:
                groups[-1]['tags'].append({
                    'cls': cls,
                    'byte1': b,
                    'byte2': b2,
                    'lo': b2 & 0x0F,
                    'hi': (b2 >> 4) & 0x0F,
                    'tag_str': f'{cls}:{b2:02X}',
                })
            pos += 2
        else:
            break

    return vl, groups


# ======================================================================
# Collect data from all files
# ======================================================================

files = [
    ("TRIANGLE", "exampleFiles/tri-crack-triangle"),
    ("PLANE", "exampleFiles/tri-crack"),
    ("LINEAR", "exampleFiles/tri-crack-linear"),
    ("CUBE", "exampleFiles/tri-crack-solid"),
]

print("=" * 78)
print("  AXIS TRACKING: What axis does each coord value belong to?")
print("=" * 78)

all_rows = []

for name, stem in files:
    oot = stem + ".00t"
    dxf = stem + ".dxf"
    if not Path(oot).exists():
        continue

    vl, groups = parse_file(oot, dxf)

    print(f"\n--- {name} ---")
    print(f"DXF vertices: {len(vl)}")
    for i, v in enumerate(vl):
        print(f"  V{i}: ({v[0]:.1f}, {v[1]:.1f}, {v[2]:.1f})")

    # For each coord value, determine which axis it serves
    # by checking which DXF vertex-axis slots match
    all_x = set(v[0] for v in vl)
    all_y = set(v[1] for v in vl)
    all_z = set(v[2] for v in vl)

    print(f"  X values: {sorted(all_x)}")
    print(f"  Y values: {sorted(all_y)}")
    print(f"  Z values: {sorted(all_z)}")
    print()

    for i, g in enumerate(groups):
        val = g['value']
        # Which axes use this value?
        axes = []
        if val in all_x: axes.append('X')
        if val in all_y: axes.append('Y')
        if val in all_z: axes.append('Z')

        # First non-C0 tag
        first_tag = None
        first_tag_full = None
        for t in g['tags']:
            if t['cls'] != 'C0':
                first_tag = t
                first_tag_full = t['tag_str']
                break

        # First tag of any kind
        any_first = g['tags'][0] if g['tags'] else None
        any_first_str = any_first['tag_str'] if any_first else 'none'

        # Tag class of first tag
        first_cls = first_tag['cls'] if first_tag else 'none'
        first_lo = first_tag['lo'] if first_tag else -1
        first_byte2 = first_tag['byte2'] if first_tag else -1

        # Number of following tags/seps
        n_tags = len(g['tags'])
        n_seps = len(g['seps'])

        row = {
            'file': name,
            'idx': i,
            'value': val,
            'axes': axes,
            'kind': g['kind'],
            'first_tag': first_tag_full,
            'first_cls': first_cls,
            'first_lo': first_lo,
            'first_byte2': first_byte2,
            'n_tags': n_tags,
            'n_seps': n_seps,
            'any_first': any_first_str,
        }
        all_rows.append(row)

        axis_str = '/'.join(axes) if axes else '??'
        print(f"  Coord #{i}: {val:10.2f} ({g['kind']:5s})  "
              f"axis={axis_str:5s}  "
              f"first_tag={str(first_tag_full):8s}  "
              f"cls={first_cls}  lo=0x{first_lo:X}  "
              f"tags={n_tags} seps={n_seps}")


# ======================================================================
# Find the axis encoding pattern
# ======================================================================

print(f"\n{'='*78}")
print("  PATTERN ANALYSIS")
print(f"{'='*78}")

# Group by axis assignment
print("\n--- First tag CLASS by axis ---")
by_axis = {}
for r in all_rows:
    for ax in r['axes']:
        by_axis.setdefault(ax, []).append(r)

for ax in ['X', 'Y', 'Z']:
    if ax in by_axis:
        rows = by_axis[ax]
        classes = [r['first_cls'] for r in rows]
        tags = [r['first_tag'] for r in rows]
        byte2s = [r['first_byte2'] for r in rows]
        los = [r['first_lo'] for r in rows]
        print(f"\n  Axis {ax}:")
        print(f"    first_tag classes: {classes}")
        print(f"    first_tags: {tags}")
        print(f"    byte2 values: {[f'0x{b:02X}' if b >= 0 else 'none' for b in byte2s]}")
        print(f"    lo_nibs: {[f'0x{l:X}' if l >= 0 else 'none' for l in los]}")

# Some coords serve multiple axes (like 1000 in linear strip = X AND Y AND Z)
# Let's also look at coords that are UNAMBIGUOUSLY one axis
print("\n--- UNAMBIGUOUS axis assignments (value used for exactly 1 axis) ---")
for r in all_rows:
    if len(r['axes']) == 1:
        ax = r['axes'][0]
        print(f"  {r['file']:8s} coord #{r['idx']}: {r['value']:10.2f} = {ax} only  "
              f"tag={r['first_tag']}  cls={r['first_cls']}  lo=0x{r['first_lo']:X}")

# Focus on the first 3 coords (initial vertex X, Y, Z) across files
print("\n--- First 3 coords (initial vertex) ---")
print("These should always be X, Y, Z in order:\n")
for name, stem in files:
    rows = [r for r in all_rows if r['file'] == name and r['idx'] < 3]
    if len(rows) >= 3:
        for r in rows:
            print(f"  {name:8s} #{r['idx']}: {r['value']:8.1f}  "
                  f"tag={r['first_tag']}  cls={r['first_cls']}  "
                  f"byte2=0x{r['first_byte2']:02X}  lo=0x{r['first_lo']:X}")
    print()

# The key question: for coords AFTER the initial 3, what determines the axis?
print("--- Coords after initial 3 (axis must be determined from tag) ---\n")
for r in all_rows:
    if r['idx'] >= 3 and r['value'] > 10:  # skip garbage decoded values
        ax = '/'.join(r['axes'])
        print(f"  {r['file']:8s} #{r['idx']}: {r['value']:8.1f}  "
              f"axis={ax:5s}  tag={r['first_tag']}  "
              f"cls={r['first_cls']}  byte2=0x{r['first_byte2']:02X}  lo=0x{r['first_lo']:X}")

# Check specific hypothesis:
# lo_nib of first tag encodes axis counter / axis index
print(f"\n--- Hypothesis: first tag's lo_nib encodes axis cycling ---")
print("If axis cycles X(0)->Y(1)->Z(2)->X(0)->..., does lo_nib track this?\n")

for name, stem in files:
    rows = [r for r in all_rows if r['file'] == name]
    print(f"  {name}:")
    axis_cycle = 0  # 0=X, 1=Y, 2=Z
    for r in rows:
        expected_axis = ['X', 'Y', 'Z'][axis_cycle % 3]
        actual = '/'.join(r['axes'])
        match = expected_axis in r['axes']
        lo = r['first_lo']
        print(f"    #{r['idx']}: val={r['value']:8.1f}  "
              f"expected={expected_axis} actual={actual:5s}  "
              f"lo=0x{lo:X}  match={'YES' if match else 'no'}")
        axis_cycle += 1
    print()
