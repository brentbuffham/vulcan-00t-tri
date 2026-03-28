#!/usr/bin/env python3
"""
Verify axis tracking state machine against all test files.

Rules:
  - First 3 coords: always X, Y, Z (axis 0, 1, 2)
  - After that, axis cycles +1 (X->Y->Z->X...) UNLESS:
    - E0 class first tag: stay on same axis
    - lo_nib = F: go backward (axis - 1) mod 3
    - A0 class: advance but marks "last in this direction"
"""

import struct
import ezdxf
from pathlib import Path


def is_separator(b):
    return (b & 0x07) == 0x07 and b >= 0x07


def parse_file(oot_path):
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
        if raw[i] == 0x20 and raw[i + 1] == 0x00:
            face_marker = i
            break

    coord_region = raw[ds + 23:face_marker] if face_marker > 0 else raw[ds + 23:attr_pos]

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
            groups.append({'value': val, 'kind': kind, 'tags': [], 'seps': []})
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
                    'cls': cls, 'byte2': b2,
                    'lo': b2 & 0x0F, 'hi': (b2 >> 4) & 0x0F,
                })
            pos += 2
        else:
            break

    return groups


def get_first_non_c0_tag(group):
    for t in group['tags']:
        if t['cls'] != 'C0':
            return t
    return None


def predict_axes(groups):
    """Apply axis state machine to predict axis for each coord group.

    Rules:
    1. First 3 coords: always X(0), Y(1), Z(2)
    2. Direction starts at +1 (forward: X->Y->Z->X)
    3. For each subsequent coord:
       a. E0 class            -> stay on same axis
       b. lo=F AND hi=0       -> set direction to -1, move backward
       c. lo=F AND hi>0       -> stay on same axis
       d. everything else     -> move in current direction
    """
    AXIS_NAMES = ['X', 'Y', 'Z']
    results = []
    axis = 0
    direction = 1  # +1 = forward (X->Y->Z), -1 = backward (Z->Y->X)

    for i, g in enumerate(groups):
        ft = get_first_non_c0_tag(g)

        if i < 3:
            predicted = i
        else:
            if ft is None:
                # No tag - move in current direction
                predicted = (axis + direction) % 3
            elif ft['cls'] == 'E0':
                # Stay on same axis
                predicted = axis
            elif ft['lo'] == 0xF and ft['hi'] == 0:
                # Flip direction to backward, move
                direction = -1
                predicted = (axis + direction) % 3
            elif ft['lo'] == 0xF and ft['hi'] > 0:
                # Stay on same axis
                predicted = axis
            else:
                # Move in current direction (lo=7, etc.)
                predicted = (axis + direction) % 3

        results.append({
            'idx': i,
            'value': g['value'],
            'predicted_axis': predicted,
            'predicted_name': AXIS_NAMES[predicted],
            'tag': ft,
            'tag_str': '{}:{:02X}'.format(ft['cls'], ft['byte2']) if ft else 'none',
            'direction': direction,
        })
        axis = predicted

    return results


def verify(name, stem):
    oot = stem + ".00t"
    dxf = stem + ".dxf"
    if not Path(oot).exists() or not Path(dxf).exists():
        return

    # DXF ground truth
    doc = ezdxf.readfile(dxf)
    msp = doc.modelspace()
    vm, vl = {}, []
    for e in msp:
        if e.dxftype() == '3DFACE':
            for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2, e.dxf.vtx3]:
                key = (round(p[0], 4), round(p[1], 4), round(p[2], 4))
                if key not in vm:
                    vm[key] = len(vl)
                    vl.append(key)

    xs = set(round(v[0], 4) for v in vl)
    ys = set(round(v[1], 4) for v in vl)
    zs = set(round(v[2], 4) for v in vl)

    # Parse coord section
    groups = parse_file(oot)

    # Predict axes
    predictions = predict_axes(groups)

    print(f"\n{'=' * 78}")
    print(f"  {name}")
    print(f"  DXF: {len(vl)} verts, X={sorted(xs)}, Y={sorted(ys)}, Z={sorted(zs)}")
    print(f"{'=' * 78}")

    correct = 0
    wrong = 0
    ambiguous = 0
    garbage = 0

    for p in predictions:
        val = round(p['value'], 4)

        # Determine actual axis from DXF
        in_x = val in xs
        in_y = val in ys
        in_z = val in zs
        actual_axes = []
        if in_x: actual_axes.append('X')
        if in_y: actual_axes.append('Y')
        if in_z: actual_axes.append('Z')

        if not actual_axes:
            # Value doesn't match any DXF axis - likely garbage/face section data
            status = 'GARBAGE'
            garbage += 1
        elif len(actual_axes) > 1:
            # Ambiguous - value appears in multiple axes
            if p['predicted_name'] in actual_axes:
                status = 'OK(ambig)'
                correct += 1
            else:
                status = 'WRONG(ambig)'
                wrong += 1
            ambiguous += 1
        else:
            # Unambiguous
            actual = actual_axes[0]
            if p['predicted_name'] == actual:
                status = 'OK'
                correct += 1
            else:
                status = '*** WRONG ***'
                wrong += 1

        if status != 'GARBAGE' or p['idx'] < 10:
            print(f"  #{p['idx']:2d}: {val:12.4f}  predicted={p['predicted_name']}  "
                  f"actual={'/'.join(actual_axes) if actual_axes else '??':5s}  "
                  f"tag={p['tag_str']:8s}  {status}")

    total = correct + wrong
    if total > 0:
        pct = 100 * correct / total
        print(f"\n  SCORE: {correct}/{total} correct ({pct:.0f}%), "
              f"{wrong} wrong, {ambiguous} ambiguous, {garbage} garbage")
    else:
        print(f"\n  No verifiable coords")

    return correct, wrong, ambiguous, garbage


# Run all files
files = [
    ("PRISM", "exampleFiles/tri-crack-prism"),
    ("TRIANGLE", "exampleFiles/tri-crack-triangle"),
    ("PLANE", "exampleFiles/tri-crack"),
    ("LINEAR STRIP", "exampleFiles/tri-crack-linear"),
    ("CUBE", "exampleFiles/tri-crack-solid"),
]

totals = [0, 0, 0, 0]
for name, stem in files:
    result = verify(name, stem)
    if result:
        for i in range(4):
            totals[i] += result[i]

print(f"\n{'=' * 78}")
print(f"  OVERALL: {totals[0]}/{totals[0]+totals[1]} correct "
      f"({100*totals[0]/(totals[0]+totals[1]) if totals[0]+totals[1] > 0 else 0:.0f}%), "
      f"{totals[1]} wrong, {totals[2]} ambiguous, {totals[3]} garbage")
print(f"{'=' * 78}")
