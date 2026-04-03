#!/usr/bin/env python3
"""
Test: Per-Axis prev tracking vs Single prev tracking for coordinate deltas.

Hypothesis: The .00t encoding may use per-axis prev values (each X delta is
relative to the last X, each Y delta to last Y, each Z delta to last Z),
rather than a single global prev.

This script:
1. Extracts the coord region bytes from .00t files
2. Parses elements using the current parser (single prev) to get axis assignments
3. Re-decodes using per-axis prev values
4. Compares results against expected DXF coordinates

Author: Test script for reverse-engineering investigation
"""

import struct
import sys
import os

# Add parent directory so we can import the parser
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oot_parser_v2 import (
    parse_coord_elements, group_coord_elements, assign_axes,
    extract_c0_assignments, read_be_double, is_separator
)


def extract_coord_region(filepath):
    """Extract the coordinate region bytes and metadata from an .00t file.

    Returns: (coord_region_bytes, is_new_format, raw_data, coord_start, coord_end)
    """
    with open(filepath, 'rb') as f:
        raw = f.read()

    vi = raw.find(b'Variant')
    if vi < 0:
        raise ValueError("No Variant marker")

    variant_len = raw[vi - 1]
    ds = vi + variant_len
    is_new_format = variant_len > 8

    anchor = raw.find(b'\x43\xE0\x0E', ds, ds + 20)
    if anchor < 0:
        raise ValueError("No header anchor pattern")

    n_verts = raw[anchor + 7]
    n_faces = raw[anchor + 14]

    # Find coord_start
    coord_start = -1
    for off in range(15, 25):
        pos = anchor + off
        if pos + 2 < len(raw) and raw[pos] == 0xE0 and raw[pos + 2] == 0x14:
            coord_start = pos + 3
            break
    if coord_start < 0:
        for off in range(15, 25):
            pos = anchor + off
            if pos < len(raw) and raw[pos] <= 0x06:
                coord_start = pos
                break
    if coord_start < 0:
        coord_start = anchor + 18

    # Find coord_end
    shaded_pos = raw.find(b'SHADED', ds)
    if shaded_pos < 0:
        shaded_pos = len(raw)

    face_marker = -1
    for i in range(shaded_pos - 2, coord_start, -1):
        if raw[i] == 0x20 and raw[i + 1] == 0x00:
            face_marker = i
            break

    coord_end = face_marker if face_marker > 0 else shaded_pos

    region = raw[coord_start:coord_end]
    return region, is_new_format, n_verts, n_faces


def parse_with_single_prev(region, new_format):
    """Current parser: single global prev. Returns list of (value, kind, n_bytes, raw_bytes)."""
    elements = parse_coord_elements(region, new_format=new_format)
    groups = group_coord_elements(elements)
    assign_axes(groups)

    results = []
    for g in groups:
        results.append({
            'value': g.value,
            'kind': g.kind,
            'n_bytes': g.n_bytes,
            'axis': g.axis,
        })
    return results


def parse_with_per_axis_prev(region, new_format, axis_assignments):
    """Re-decode coordinates using per-axis prev tracking.

    Uses the axis assignments from the single-prev parse, but maintains
    separate prev_x, prev_y, prev_z for delta computation.

    Args:
        region: raw coordinate region bytes
        new_format: whether this is a new-format file
        axis_assignments: list of axis values (0=X, 1=Y, 2=Z) from single-prev parse

    Returns: list of dicts with decoded values
    """
    prev_per_axis = [[0]*8, [0]*8, [0]*8]  # prev for X, Y, Z
    prev_global = [0]*8  # also track global for comparison

    results = []
    coord_idx = 0
    pos = 0

    while pos < len(region):
        b = region[pos]
        if b <= 0x06 or (new_format and b == 0x07):
            nb = b + 1
            raw_nb = nb
            if pos + 1 + nb > len(region):
                break
            stored = list(region[pos + 1:pos + 1 + nb])

            # Apply same escape stripping as original parser
            if new_format and len(stored) > 1:
                stripped = list(stored)
                while len(stripped) > 1 and (stripped[0] >= 0xFC or stripped[0] == 0x00):
                    candidate = stripped[1:]
                    if candidate[0] in (0x40, 0x41, 0xC0, 0xC1):
                        stored = candidate
                        nb = len(stored)
                        break
                    elif candidate[0] >= 0xFC or candidate[0] == 0x00:
                        stripped = candidate
                        continue
                    else:
                        break

            # Get axis assignment from the single-prev parse
            if coord_idx < len(axis_assignments):
                axis = axis_assignments[coord_idx]
            else:
                axis = coord_idx % 3  # fallback

            prev_axis = prev_per_axis[axis]

            # --- SINGLE PREV decode (for comparison) ---
            if stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r_single = stored + [0] * (8 - nb)
                kind = 'FULL'
            else:
                if new_format:
                    r_single = [prev_global[0]] + stored + [0] * (8 - nb - 1)
                else:
                    r_single = [prev_global[0]] + stored + list(prev_global[nb + 1:8])
                kind = 'DELTA'
            r_single = (r_single + [0]*8)[:8]
            val_single = read_be_double(bytes(r_single))

            # --- PER-AXIS PREV decode ---
            if stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r_peraxis = stored + [0] * (8 - nb)
                kind_pa = 'FULL'
            else:
                if new_format:
                    r_peraxis = [prev_axis[0]] + stored + [0] * (8 - nb - 1)
                else:
                    r_peraxis = [prev_axis[0]] + stored + list(prev_axis[nb + 1:8])
                kind_pa = 'DELTA'

                # Also apply IDELTA check for new format
                if new_format and kind_pa == 'DELTA':
                    test_r = (r_peraxis + [0]*8)[:8]
                    test_val = read_be_double(bytes(test_r))
                    if abs(test_val) > 10000:
                        prev_int = struct.unpack('>Q', bytes(prev_axis))[0]
                        delta_int = int.from_bytes(bytes(stored[:raw_nb]), 'big')
                        if stored[0] >= 0x80:
                            delta_int -= (1 << (raw_nb * 8))
                        result_int = (prev_int + delta_int) & 0xFFFFFFFFFFFFFFFF
                        r_peraxis = list(struct.pack('>Q', result_int))
                        kind_pa = 'IDELTA'

            r_peraxis = (r_peraxis + [0]*8)[:8]
            val_peraxis = read_be_double(bytes(r_peraxis))

            # Also apply IDELTA for single-prev
            if new_format and kind == 'DELTA':
                test_val_s = val_single
                if abs(test_val_s) > 10000:
                    prev_int = struct.unpack('>Q', bytes(prev_global))[0]
                    delta_int = int.from_bytes(bytes(stored[:raw_nb]), 'big')
                    if stored[0] >= 0x80:
                        delta_int -= (1 << (raw_nb * 8))
                    result_int = (prev_int + delta_int) & 0xFFFFFFFFFFFFFFFF
                    r_single_id = list(struct.pack('>Q', result_int))
                    r_single_id = (r_single_id + [0]*8)[:8]
                    val_single = read_be_double(bytes(r_single_id))
                    r_single = r_single_id
                    kind = 'IDELTA'

            results.append({
                'coord_idx': coord_idx,
                'axis': axis,
                'kind': kind,
                'kind_pa': kind_pa,
                'val_single': val_single,
                'val_peraxis': val_peraxis,
                'stored_hex': ' '.join(f'{x:02X}' for x in region[pos+1:pos+1+raw_nb]),
                'nb': nb,
                'raw_nb': raw_nb,
            })

            # Update prevs
            prev_global = list(r_single)
            prev_per_axis[axis] = list(r_peraxis)

            coord_idx += 1
            pos += 1 + raw_nb
        elif is_separator(b):
            pos += 1
        elif pos + 1 < len(region):
            pos += 2  # tag
        else:
            break

    return results


def score_against_expected(values_by_axis, expected):
    """Score how well decoded values match expected coordinate sets.

    Args:
        values_by_axis: {0: [x_vals], 1: [y_vals], 2: [z_vals]}
        expected: {0: set_of_expected_x, 1: set_of_expected_y, 2: set_of_expected_z}

    Returns: (n_matched, n_total, details)
    """
    matched = 0
    total = 0
    details = []

    for axis in range(3):
        axis_name = ['X', 'Y', 'Z'][axis]
        exp_set = expected[axis]
        vals = values_by_axis.get(axis, [])
        for v in vals:
            total += 1
            closest = min(exp_set, key=lambda e: abs(v - e)) if exp_set else None
            dist = abs(v - closest) if closest is not None else float('inf')
            is_match = dist < 1.0
            if is_match:
                matched += 1
            else:
                details.append(f"  {axis_name}: {v:.4f} (closest expected: {closest}, dist: {dist:.4f})")

    return matched, total, details


def run_test(filepath, name, expected_coords):
    """Run the per-axis vs single-prev comparison for one file."""
    print(f"\n{'='*70}")
    print(f"  {name}: {filepath}")
    print(f"{'='*70}")

    region, is_new_format, n_verts, n_faces = extract_coord_region(filepath)
    print(f"  Format: {'NEW' if is_new_format else 'OLD'}, "
          f"n_verts={n_verts}, n_faces={n_faces}, "
          f"coord_region={len(region)} bytes")
    print(f"  Region hex (first 80 bytes): {region[:80].hex(' ')}")

    # Step 1: Parse with current single-prev parser to get axis assignments
    single_results = parse_with_single_prev(region, is_new_format)
    axis_assignments = [r['axis'] for r in single_results]

    print(f"\n  Found {len(single_results)} coordinates")
    print(f"  Axis assignments: {axis_assignments}")

    # Step 2: Re-decode with per-axis prev
    comparison = parse_with_per_axis_prev(region, is_new_format, axis_assignments)

    # Step 3: Show comparison
    print(f"\n  {'Idx':>3} {'Axis':>4} {'Kind':>6} {'Single-Prev':>14} {'Per-Axis':>14} {'Diff':>10} {'Stored':>20}")
    print(f"  {'-'*3} {'-'*4} {'-'*6} {'-'*14} {'-'*14} {'-'*10} {'-'*20}")

    n_different = 0
    single_vals_by_axis = {0: [], 1: [], 2: []}
    peraxis_vals_by_axis = {0: [], 1: [], 2: []}

    for c in comparison:
        ax_name = ['X', 'Y', 'Z'][c['axis']]
        diff = c['val_peraxis'] - c['val_single']
        marker = " ***" if abs(diff) > 0.001 else ""
        if abs(diff) > 0.001:
            n_different += 1

        single_vals_by_axis[c['axis']].append(c['val_single'])
        peraxis_vals_by_axis[c['axis']].append(c['val_peraxis'])

        print(f"  {c['coord_idx']:>3} {ax_name:>4} {c['kind']:>6} {c['val_single']:>14.4f} {c['val_peraxis']:>14.4f} {diff:>10.4f} {c['stored_hex']:>20}{marker}")

    print(f"\n  Coordinates that DIFFER: {n_different}/{len(comparison)}")

    # Step 4: Score against expected DXF values
    if expected_coords:
        print(f"\n  --- Scoring against expected DXF coordinates ---")

        s_matched, s_total, s_details = score_against_expected(single_vals_by_axis, expected_coords)
        p_matched, p_total, p_details = score_against_expected(peraxis_vals_by_axis, expected_coords)

        print(f"  SINGLE-PREV: {s_matched}/{s_total} coords match expected DXF values")
        if s_details:
            print(f"  Single-prev mismatches:")
            for d in s_details[:10]:
                print(d)

        print(f"  PER-AXIS:    {p_matched}/{p_total} coords match expected DXF values")
        if p_details:
            print(f"  Per-axis mismatches:")
            for d in p_details[:10]:
                print(d)

        if p_matched > s_matched:
            print(f"\n  >>> PER-AXIS PREV is BETTER ({p_matched} vs {s_matched} matches)")
        elif s_matched > p_matched:
            print(f"\n  >>> SINGLE PREV is BETTER ({s_matched} vs {p_matched} matches)")
        else:
            print(f"\n  >>> BOTH METHODS PRODUCE SAME RESULTS ({s_matched} matches)")

    return comparison, single_vals_by_axis, peraxis_vals_by_axis


def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Hexhole expected DXF coords
    hexhole_expected = {
        0: {1000, 1100, 1200, 1300},  # X
        1: {1000, 1100, 1200, 1300},  # Y
        2: {300, 350},                 # Z
    }

    # Cube expected DXF coords
    cube_expected = {
        0: {100, 300},   # X
        1: {500, 600},   # Y
        2: {900, 950},   # Z
    }

    # Test Hexhole
    hexhole_path = os.path.join(base, "exampleFiles", "tri-crack-Hexhole.00t")
    run_test(hexhole_path, "HEXHOLE", hexhole_expected)

    # Test Cube
    cube_path = os.path.join(base, "exampleFiles", "tri-crack-solid.00t")
    run_test(cube_path, "CUBE (solid)", cube_expected)

    print(f"\n{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}")
    print(f"  If per-axis tracking shows identical results to single-prev,")
    print(f"  the first 3 coords (X,Y,Z) set distinct prev values per axis.")
    print(f"  Differences only appear when a DELTA coord for axis A uses a")
    print(f"  prev that was set by a coord from a DIFFERENT axis B.")
    print(f"")
    print(f"  Key insight: FULL values don't depend on prev at all.")
    print(f"  Only DELTA values are affected. If most coords are FULL,")
    print(f"  both methods will agree. The difference only matters when")
    print(f"  DELTA coords follow coords from a different axis.")


if __name__ == '__main__':
    main()
