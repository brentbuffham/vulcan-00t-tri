#!/usr/bin/env python3
"""
Unified cube1-5 analysis.

Cubes 1-5 are the same 50³ axis-aligned box rotated around Z by different
angles. Cube1 is axis-aligned (0°). cube2 is -25°, cube3 is -75°. cube4/5
unknown angles.

For each cube:
  1. Show the parser's emitted vertex values (and which ones look like rotated
     cube1 corners).
  2. Show expected corners from ground truth (where known).
  3. Try to back-derive cube4/cube5's rotation angle from emitted values.
  4. Print coord-region byte stream + group separators side-by-side so we can
     spot structural differences across the rotations.
"""
import sys, math
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'python'))
sys.path.insert(0, str(ROOT / 'scripts'))

import oot_parser_v2 as P
from OL_GW_ground_truth import CUBE1_CORNERS, rotate_z


def expected_for_angle(theta):
    return rotate_z(CUBE1_CORNERS, theta)


def unique_axis_values(corners):
    xs = sorted({round(c[0], 2) for c in corners})
    ys = sorted({round(c[1], 2) for c in corners})
    zs = sorted({round(c[2], 2) for c in corners})
    return xs, ys, zs


def derive_angle_from_values(emitted_values, axis_aligned_unique=(50, 25, 10, 100, 75, 60)):
    """Search 0-359 deg for angle whose rotated CUBE1_CORNERS unique values best
    match the emitted set."""
    emitted = sorted(set(round(v, 2) for v in emitted_values))
    best = None
    for theta in range(-179, 180):
        rotated = rotate_z(CUBE1_CORNERS, theta)
        rxs, rys, rzs = unique_axis_values(rotated)
        target = sorted(set(rxs + rys + rzs))
        match = 0
        for t in target:
            for e in emitted:
                if abs(t - e) < 1.5:
                    match += 1
                    break
        if best is None or match > best[0]:
            best = (match, theta, target)
    return best


def hex_dump(data, start, end, width=16):
    """Hex dump `data[start:end]` 16 bytes per line, with offset prefix."""
    lines = []
    for i in range(start, end, width):
        chunk = data[i:i + width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        lines.append(f'  +{i - start:04x}: {hex_str}')
    return '\n'.join(lines)


def analyze_one(name):
    path = ROOT / 'exampleFiles' / f'{name}.00t'
    print(f'\n{"=" * 78}')
    print(f' {name}.00t')
    print('=' * 78)

    res = P.parse_oot_v2(str(path))
    verts = res.vertices

    # Determine expected ground truth
    if name == 'cube1':
        expected = CUBE1_CORNERS
        angle = 0
    elif name == 'cube2':
        angle = -25
        expected = rotate_z(CUBE1_CORNERS, angle)
    elif name == 'cube3':
        angle = -75
        expected = rotate_z(CUBE1_CORNERS, angle)
    else:
        expected = None
        angle = None

    print(f'\nParser: {len(verts)} vertices, {len(res.faces)} faces')
    print(f'  Header: n_verts={res.n_verts_header}, n_faces={res.n_faces_header}')

    # Emitted unique axis values from parser output
    emitted_all = []
    for v in verts:
        emitted_all.extend(v)

    if expected is not None:
        ex, ey, ez = unique_axis_values(expected)
        print(f'\nExpected unique values (from rotation {angle}°):')
        print(f'  X: {ex}')
        print(f'  Y: {ey}')
        print(f'  Z: {ez}')
        all_target = sorted(set(ex + ey + ez))
        print(f'  All distinct: {all_target}')

        # How many of these target values appear in parser output?
        hits = 0
        emitted_set = set(round(v, 2) for v in emitted_all)
        for t in all_target:
            for e in emitted_set:
                if abs(t - e) < 1.5:
                    hits += 1
                    break
        print(f'\n  Distinct expected values found in parser emissions: {hits}/{len(all_target)}')

        # Coverage
        covered = 0
        for t in expected:
            for v in verts:
                if (abs(v[0] - t[0]) < 1.5 and abs(v[1] - t[1]) < 1.5
                        and abs(v[2] - t[2]) < 1.5):
                    covered += 1
                    break
        print(f'  Corners covered: {covered}/8')

    else:
        # Try to derive angle
        match, theta, target = derive_angle_from_values(emitted_all)
        print(f'\nNo ground truth; best-fit rotation: {theta}°')
        print(f'  At {theta}° unique target values: {target}')
        print(f'  Distinct values matched: {match}/{len(target)}')

    # Parser emission list
    print(f'\nParser vertices:')
    for i, v in enumerate(verts):
        print(f'  V{i}: ({v[0]:9.3f}, {v[1]:9.3f}, {v[2]:9.3f})')


if __name__ == '__main__':
    for name in ['cube1', 'cube2', 'cube3', 'cube4', 'cube5']:
        analyze_one(name)
