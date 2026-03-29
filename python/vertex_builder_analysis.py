"""
Vertex Builder Analysis: Compare OOT parsed vertices vs DXF ground truth.

For each test file:
1. Extract DXF 3DFACE unique vertices
2. Parse .00t coord groups using the NEW parser rules
3. Run the axis state machine
4. Run the vertex builder (running state + C0 slots)
5. Compare OOT vertices vs DXF vertices
"""

import struct
import os
from collections import OrderedDict

BASE_DIR = r"C:\Users\brent\desktop\GIT\vulcan-00t-tri\exampleFiles"

# ═══════════════════════════════════════════════════════
# DXF Parser - extract unique 3DFACE vertices
# ═══════════════════════════════════════════════════════

def parse_dxf(filepath):
    """Extract unique vertices and face indices from 3DFACE entities."""
    with open(filepath, 'r') as f:
        lines = f.readlines()

    verts = []
    faces = []
    vmap = {}

    def vkey(x, y, z):
        return f"{x:.4f},{y:.4f},{z:.4f}"

    def get_vi(x, y, z):
        k = vkey(x, y, z)
        if k in vmap:
            return vmap[k]
        i = len(verts)
        verts.append((x, y, z))
        vmap[k] = i
        return i

    i = 0
    while i < len(lines):
        if lines[i].strip() == '3DFACE':
            pts = {}
            i += 1
            while i < len(lines) - 1:
                code = int(lines[i].strip())
                val = lines[i+1].strip()
                if code == 0:
                    break
                if 10 <= code <= 37:
                    pts[code] = float(val)
                i += 2
            if 10 in pts:
                v0 = get_vi(pts.get(10,0), pts.get(20,0), pts.get(30,0))
                v1 = get_vi(pts.get(11,0), pts.get(21,0), pts.get(31,0))
                v2 = get_vi(pts.get(12,0), pts.get(22,0), pts.get(32,0))
                faces.append((v0, v1, v2))
        else:
            i += 1

    return verts, faces


# ═══════════════════════════════════════════════════════
# OOT Parser - coord groups with NEW rules
# ═══════════════════════════════════════════════════════

def is_sep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

def read_be64(byte_list):
    """Read 8 bytes as big-endian float64."""
    padded = list(byte_list) + [0] * (8 - len(byte_list))
    return struct.unpack('>d', bytes(padded[:8]))[0]

def find_bytes(data, needle, start=0):
    needle = bytes(needle)
    for i in range(start, len(data) - len(needle) + 1):
        if data[i:i+len(needle)] == needle:
            return i
    return -1

def parse_oot_coords(filepath):
    """Parse .00t file and return coord groups, raw bytes info."""
    with open(filepath, 'rb') as f:
        data = f.read()

    data = bytearray(data)

    # Find Variant marker
    variant_needle = [0x56, 0x61, 0x72, 0x69, 0x61, 0x6E, 0x74]  # "Variant"
    vi = find_bytes(data, variant_needle)
    if vi < 0:
        return None, "No Variant marker"

    # Find header pattern: 43 E0 0E 2F
    header_pattern = [0x43, 0xE0, 0x0E, 0x2F]
    hdr_idx = find_bytes(data, header_pattern, vi)
    if hdr_idx < 0:
        return None, "Cannot find data header"

    ds = hdr_idx - 5

    # Read header info
    n_verts_header = data[ds + 12] if ds + 12 < len(data) else 0
    n_faces_header = data[ds + 19] if ds + 19 < len(data) else 0

    # Find attribute suffix
    attr_suffix = [0x00, 0x05, 0x40, 0x04, 0x00, 0x0A, 0x20, 0x08, 0x07]
    attr_pos = find_bytes(data, attr_suffix, ds)
    if attr_pos < 0:
        # Fallback: SHADED
        shaded = find_bytes(data, b'SHADED', ds)
        if shaded > 0:
            sep_needle = b'separator'
            sep_pos = find_bytes(data, sep_needle, ds)
            if sep_pos > 0 and sep_pos < shaded:
                attr_pos = sep_pos - 10
            else:
                attr_pos = shaded - 20
        else:
            attr_pos = len(data)

    # Find face marker: first "20 00" after coord data
    face_marker = -1
    for i in range(ds + 30, attr_pos - 1):
        if data[i] == 0x20 and data[i+1] == 0x00:
            face_marker = i
            break

    coord_start = ds + 23
    coord_end = face_marker if face_marker > 0 else attr_pos
    coord_region = data[coord_start:coord_end]

    # Parse coord groups
    prev = bytearray(8)
    pos = 0
    had_full = False
    groups = []
    raw_bytes_log = []  # For debugging

    while pos < len(coord_region):
        b = coord_region[pos]

        if b <= 0x06:
            # Count byte: next b+1 bytes are the value
            if b == 0x00 and not had_full:
                # Zero literal before first FULL
                groups.append({
                    'value': 0.0,
                    'tags': [],
                    'seps': [],
                    'raw': [b],
                    'type': 'ZERO_LITERAL',
                    'offset': coord_start + pos
                })
                raw_bytes_log.append(f"  [{pos:3d}] 0x{b:02X} -> ZERO_LITERAL = 0.0")
                pos += 1
                continue

            nb = b + 1
            if pos + 1 + nb > len(coord_region):
                break
            stored = coord_region[pos+1:pos+1+nb]
            result = bytearray(8)

            is_full = stored[0] in (0x40, 0x41, 0xC0, 0xC1)
            if is_full:
                for i in range(nb):
                    result[i] = stored[i]
                had_full = True
                vtype = 'FULL'
            else:
                result[0] = prev[0]
                for i in range(nb):
                    result[i+1] = stored[i]
                for i in range(nb+1, 8):
                    result[i] = prev[i]
                vtype = 'DELTA'

            val = struct.unpack('>d', bytes(result))[0]
            for i in range(8):
                prev[i] = result[i]

            raw = list(coord_region[pos:pos+1+nb])
            groups.append({
                'value': val,
                'tags': [],
                'seps': [],
                'raw': raw,
                'type': vtype,
                'offset': coord_start + pos,
                'stored_hex': ' '.join(f'{x:02X}' for x in stored),
                'result_hex': ' '.join(f'{x:02X}' for x in result)
            })
            raw_bytes_log.append(
                f"  [{pos:3d}] 0x{b:02X} nb={nb} stored=[{' '.join(f'{x:02X}' for x in stored)}] "
                f"-> {vtype} val={val:.4f}"
            )
            pos += 1 + nb

        elif is_sep(b):
            if groups:
                groups[-1]['seps'].append(b)
            raw_bytes_log.append(f"  [{pos:3d}] 0x{b:02X} -> SEP")
            pos += 1

        elif b >= 0x60 and pos + 1 < len(coord_region):
            # Tag pair
            b2 = coord_region[pos+1]
            cls_map = {0x60:'60', 0x80:'80', 0xA0:'A0', 0xC0:'C0', 0xE0:'E0'}
            cls = cls_map.get(b & 0xE0, '??')
            tag = {
                'cls': cls,
                'byte1': b,
                'byte2': b2,
                'lo': b2 & 0xF,
                'hi': (b2 >> 4) & 0xF
            }
            if groups:
                groups[-1]['tags'].append(tag)
            raw_bytes_log.append(
                f"  [{pos:3d}] 0x{b:02X} 0x{b2:02X} -> TAG cls={cls} hi=0x{tag['hi']:X} lo=0x{tag['lo']:X}"
            )
            pos += 2

        else:
            # Skip bytes 0x08-0x5F
            raw_bytes_log.append(f"  [{pos:3d}] 0x{b:02X} -> SKIP")
            pos += 1

    return {
        'groups': groups,
        'raw_log': raw_bytes_log,
        'coord_start': coord_start,
        'coord_end': coord_end,
        'coord_region_hex': ' '.join(f'{b:02X}' for b in coord_region),
        'face_marker': face_marker,
        'n_verts_header': n_verts_header,
        'n_faces_header': n_faces_header,
        'ds': ds,
    }, None


# ═══════════════════════════════════════════════════════
# Axis State Machine
# ═══════════════════════════════════════════════════════

def run_axis_state_machine(groups):
    """Assign axis to each coord group."""
    axis = 0
    direction = 1
    axis_map = []

    for i, g in enumerate(groups):
        # Find first non-C0 tag
        ft = None
        for t in g['tags']:
            if t['cls'] != 'C0':
                ft = t
                break

        if i < 3:
            ax = i
        elif ft is None:
            ax = ((axis + direction) % 3 + 3) % 3
        elif ft['cls'] == 'E0':
            ax = axis
        elif ft['lo'] == 0xF and ft['hi'] == 0:
            direction = -1
            ax = ((axis - 1) % 3 + 3) % 3
        elif ft['lo'] == 0xF and ft['hi'] > 0:
            ax = axis
        else:
            ax = ((axis + direction) % 3 + 3) % 3

        axis_map.append(ax)
        axis = ax

    return axis_map


# ═══════════════════════════════════════════════════════
# Coord Group End Detection
# ═══════════════════════════════════════════════════════

def detect_coord_group_end(groups):
    """Detect where coordinate groups end and face/garbage begins."""
    coord_group_end = len(groups)

    first_real_value = 0
    for g in groups:
        if abs(g['value']) > 1:
            first_real_value = abs(g['value'])
            break

    for i in range(3, len(groups)):
        v = groups[i]['value']
        av = abs(v)

        if first_real_value > 10 and av < first_real_value / 100 and av < 10:
            coord_group_end = i
            break
        if first_real_value > 1 and av > first_real_value * 50:
            coord_group_end = i
            break
        # Stop at 20:03 tags
        if any(t['cls'] == '20' and t['byte2'] == 0x03 for t in groups[i]['tags']):
            coord_group_end = i
            break
        # Stop on negative when previous positive
        if v < -0.5 and i > 3 and groups[i-1]['value'] > 0:
            coord_group_end = i
            break

    return coord_group_end


# ═══════════════════════════════════════════════════════
# Vertex Builder
# ═══════════════════════════════════════════════════════

def build_vertices(groups, axis_map, coord_group_end):
    """
    Build vertices using gap-filling model:
    1. Collect C0 slot assignments
    2. Collect primary vertices from running state
    3. C0 slots claim specific indices; primaries fill gaps then extend
    """
    # Collect base values and Z variants
    base_values = [None, None, None]
    z_values = []

    for i in range(coord_group_end):
        ax = axis_map[i]
        if 0 <= ax <= 2:
            if base_values[ax] is None:
                base_values[ax] = groups[i]['value']
            if ax == 2 and groups[i]['value'] not in z_values:
                z_values.append(groups[i]['value'])

    running = [0.0, 0.0, 0.0]
    c0_slots = {}
    c0_slot_set = set()
    primaries = []

    trace_log = []

    for i in range(coord_group_end):
        g = groups[i]
        ax = axis_map[i]
        if ax < 0 or ax > 2:
            continue
        running[ax] = g['value']

        # Collect C0 slot numbers
        for t in g['tags']:
            if t['cls'] == 'C0':
                c0_slot_set.add(t['hi'])

        if i == 2:
            # V0 from initial 3 coords
            vert = [running[0], running[1], running[2]]
            primaries.append(vert)
            trace_log.append(f"  group[{i}] ax={ax} val={g['value']:.4f} -> V0 PRIMARY = {format_vert(vert)}")

        elif i > 2:
            # Check first non-C0 tag
            ft = None
            for t in g['tags']:
                if t['cls'] != 'C0':
                    ft = t
                    break

            if len(z_values) >= 2 and ft and ft['lo'] == 0xF:
                v1 = [running[0], running[1], z_values[0]]
                v2 = [running[0], running[1], z_values[1]]
                primaries.append(v1)
                primaries.append(v2)
                trace_log.append(
                    f"  group[{i}] ax={ax} val={g['value']:.4f} lo=0xF -> TWO PRIMARIES: "
                    f"{format_vert(v1)}, {format_vert(v2)}"
                )
            else:
                vert = [running[0], running[1], running[2]]
                primaries.append(vert)
                tag_info = f"ft={ft['cls']}:0x{ft['byte2']:02X}" if ft else "no_tag"
                trace_log.append(
                    f"  group[{i}] ax={ax} val={g['value']:.4f} {tag_info} -> PRIMARY = {format_vert(vert)}"
                )

            # Process C0 assignments
            for t in g['tags']:
                if t['cls'] != 'C0':
                    continue
                slot = t['hi']
                if slot not in c0_slots:
                    c0_slots[slot] = [
                        base_values[0] or 0,
                        base_values[1] or 0,
                        base_values[2] or 0
                    ]
                c0_slots[slot][ax] = g['value']

                # Z-variant from lo_nib
                if len(z_values) >= 2:
                    if t['lo'] == 0x07:
                        c0_slots[slot][2] = z_values[0]
                    elif t['lo'] == 0x0F:
                        c0_slots[slot][2] = z_values[1]

                trace_log.append(
                    f"    C0 slot={slot} lo=0x{t['lo']:X} -> slot[{slot}] = {format_vert(c0_slots[slot])}"
                )
        else:
            trace_log.append(f"  group[{i}] ax={ax} val={g['value']:.4f} (building initial xyz)")

    # Vertex ordering: primaries first, then C0 slots
    vertices = list(primaries)
    c0_slot_nums = sorted(c0_slots.keys())
    for slot in c0_slot_nums:
        vertices.append(c0_slots[slot])

    trace_log.append(f"\n  === VERTEX SUMMARY ===")
    trace_log.append(f"  Base values: X={base_values[0]}, Y={base_values[1]}, Z={base_values[2]}")
    trace_log.append(f"  Z variants: {z_values}")
    trace_log.append(f"  Primary vertices ({len(primaries)}):")
    for j, p in enumerate(primaries):
        trace_log.append(f"    P{j}: {format_vert(p)}")
    trace_log.append(f"  C0 slots ({len(c0_slots)}):")
    for slot in c0_slot_nums:
        trace_log.append(f"    C0[{slot}]: {format_vert(c0_slots[slot])}")
    trace_log.append(f"  Total vertices: {len(vertices)}")

    return vertices, trace_log, {
        'base_values': base_values,
        'z_values': z_values,
        'primaries': primaries,
        'c0_slots': c0_slots,
        'running_final': running[:],
    }


def format_vert(v):
    return f"({v[0]:.1f}, {v[1]:.1f}, {v[2]:.1f})"


# ═══════════════════════════════════════════════════════
# Comparison
# ═══════════════════════════════════════════════════════

def compare_vertices(oot_verts, dxf_verts):
    """Compare OOT vertices vs DXF vertices. Return match analysis."""
    results = []

    # Try to match each DXF vertex to nearest OOT vertex
    matched_oot = set()
    for di, dv in enumerate(dxf_verts):
        best_dist = float('inf')
        best_oi = -1
        for oi, ov in enumerate(oot_verts):
            dist = sum((a-b)**2 for a,b in zip(dv, ov)) ** 0.5
            if dist < best_dist:
                best_dist = dist
                best_oi = oi

        if best_dist < 0.1:
            results.append(f"  DXF[{di}] {format_vert(dv)} <-> OOT[{best_oi}] {format_vert(oot_verts[best_oi])} MATCH (dist={best_dist:.4f})")
            matched_oot.add(best_oi)
        else:
            results.append(f"  DXF[{di}] {format_vert(dv)} <-> OOT[{best_oi}] {format_vert(oot_verts[best_oi])} MISMATCH (dist={best_dist:.4f})")

    # Report unmatched OOT vertices
    for oi, ov in enumerate(oot_verts):
        if oi not in matched_oot:
            results.append(f"  OOT[{oi}] {format_vert(ov)} -- NO DXF MATCH (extra vertex)")

    n_matched = len(matched_oot)
    n_dxf = len(dxf_verts)
    n_oot = len(oot_verts)

    return results, n_matched, n_dxf, n_oot


# ═══════════════════════════════════════════════════════
# Main analysis
# ═══════════════════════════════════════════════════════

TEST_FILES = [
    ("tri-crack-triangle", "4 verts, 1 face (single triangle)"),
    ("tri-crack", "5 verts, 2 faces (plane)"),
    ("tri-crack-solid", "8 verts, 12 faces (cube)"),
    ("tri-crack-prism", "5 verts, 2 faces (prism/wedge)"),
]

def analyze_file(name, description):
    oot_path = os.path.join(BASE_DIR, f"{name}.00t")
    dxf_path = os.path.join(BASE_DIR, f"{name}.dxf")

    print(f"\n{'='*80}")
    print(f" {name} -- {description}")
    print(f"{'='*80}")

    # 1. Parse DXF
    dxf_verts, dxf_faces = parse_dxf(dxf_path)
    print(f"\n--- DXF Ground Truth ---")
    print(f"  Unique vertices: {len(dxf_verts)}")
    for i, v in enumerate(dxf_verts):
        print(f"    [{i}] {format_vert(v)}")
    print(f"  Faces: {len(dxf_faces)}")
    for i, f in enumerate(dxf_faces):
        print(f"    [{i}] {f}")

    # 2. Parse OOT
    result, err = parse_oot_coords(oot_path)
    if err:
        print(f"\n  ERROR: {err}")
        return

    groups = result['groups']
    print(f"\n--- OOT Coord Region ---")
    print(f"  Header: ds=0x{result['ds']:04X}, coord_start=0x{result['coord_start']:04X}, "
          f"coord_end=0x{result['coord_end']:04X}")
    print(f"  Header verts={result['n_verts_header']}, faces={result['n_faces_header']}")
    print(f"  Coord region hex:")
    hex_str = result['coord_region_hex']
    # Print in chunks
    for j in range(0, len(hex_str), 96):
        print(f"    {hex_str[j:j+96]}")

    print(f"\n--- Coord Groups ({len(groups)}) ---")
    for i, g in enumerate(groups):
        tag_str = ""
        for t in g['tags']:
            tag_str += f" [{t['cls']}:{t['byte1']:02X}/{t['byte2']:02X} hi={t['hi']:X} lo={t['lo']:X}]"
        sep_str = ""
        if g['seps']:
            sep_str = f" seps=[{','.join(f'0x{s:02X}' for s in g['seps'])}]"
        stored = g.get('stored_hex', '')
        rtype = g.get('type', '?')
        print(f"  [{i}] val={g['value']:12.4f}  type={rtype:5s}  stored=[{stored}]{tag_str}{sep_str}")

    # 3. Raw byte log
    print(f"\n--- Raw Byte Parse Log ---")
    for line in result['raw_log']:
        print(line)

    # 4. Axis state machine
    axis_map = run_axis_state_machine(groups)
    print(f"\n--- Axis Map ---")
    for i, ax in enumerate(axis_map):
        axis_names = {0: 'X', 1: 'Y', 2: 'Z'}
        print(f"  [{i}] axis={ax} ({axis_names.get(ax, '?')})  val={groups[i]['value']:.4f}")

    # 5. Coord group end
    coord_group_end = detect_coord_group_end(groups)
    print(f"\n--- Coord Group End = {coord_group_end} (of {len(groups)} groups) ---")

    # 6. Vertex builder
    vertices, trace_log, builder_info = build_vertices(groups, axis_map, coord_group_end)
    print(f"\n--- Vertex Builder Trace ---")
    for line in trace_log:
        print(line)

    # 7. Comparison
    print(f"\n--- Vertex Comparison (OOT vs DXF) ---")
    comp_results, n_matched, n_dxf, n_oot = compare_vertices(vertices, dxf_verts)
    for line in comp_results:
        print(line)

    match_pct = (n_matched / n_dxf * 100) if n_dxf > 0 else 0
    print(f"\n  RESULT: {n_matched}/{n_dxf} DXF vertices matched ({match_pct:.0f}%), "
          f"OOT has {n_oot} vertices")

    if n_matched == n_dxf and n_oot == n_dxf:
        print("  STATUS: PERFECT MATCH")
    elif n_matched == n_dxf:
        print(f"  STATUS: ALL DXF MATCHED but OOT has {n_oot - n_dxf} extra vertices")
    else:
        print(f"  STATUS: MISMATCH - {n_dxf - n_matched} DXF vertices not found in OOT")

    return {
        'name': name,
        'dxf_verts': dxf_verts,
        'oot_verts': vertices,
        'n_matched': n_matched,
        'n_dxf': n_dxf,
        'n_oot': n_oot,
        'builder_info': builder_info,
        'groups': groups,
        'axis_map': axis_map,
        'coord_group_end': coord_group_end,
    }


def main():
    print("=" * 80)
    print(" VERTEX BUILDER ANALYSIS: OOT vs DXF Comparison")
    print("=" * 80)

    all_results = []
    for name, desc in TEST_FILES:
        r = analyze_file(name, desc)
        if r:
            all_results.append(r)

    # Final summary
    print("\n\n" + "=" * 80)
    print(" OVERALL SUMMARY")
    print("=" * 80)
    for r in all_results:
        status = "OK" if r['n_matched'] == r['n_dxf'] and r['n_oot'] == r['n_dxf'] else "FAIL"
        print(f"  {r['name']:25s}  DXF={r['n_dxf']} OOT={r['n_oot']} matched={r['n_matched']}  [{status}]")

    # Detailed analysis of failures
    print("\n\n" + "=" * 80)
    print(" DETAILED FAILURE ANALYSIS")
    print("=" * 80)

    for r in all_results:
        if r['n_matched'] != r['n_dxf'] or r['n_oot'] != r['n_dxf']:
            print(f"\n--- {r['name']} ---")
            print(f"  DXF expects {r['n_dxf']} vertices:")
            for i, v in enumerate(r['dxf_verts']):
                print(f"    [{i}] {format_vert(v)}")
            print(f"  OOT produced {r['n_oot']} vertices:")
            for i, v in enumerate(r['oot_verts']):
                print(f"    [{i}] {format_vert(v)}")

            # Identify what's missing from OOT
            oot_set = set()
            for v in r['oot_verts']:
                oot_set.add(f"{v[0]:.1f},{v[1]:.1f},{v[2]:.1f}")
            print(f"  Missing DXF vertices in OOT:")
            for i, v in enumerate(r['dxf_verts']):
                key = f"{v[0]:.1f},{v[1]:.1f},{v[2]:.1f}"
                if key not in oot_set:
                    print(f"    [{i}] {format_vert(v)} <-- MISSING")

            # Identify extra OOT vertices
            dxf_set = set()
            for v in r['dxf_verts']:
                dxf_set.add(f"{v[0]:.1f},{v[1]:.1f},{v[2]:.1f}")
            print(f"  Extra OOT vertices not in DXF:")
            for i, v in enumerate(r['oot_verts']):
                key = f"{v[0]:.1f},{v[1]:.1f},{v[2]:.1f}"
                if key not in dxf_set:
                    print(f"    [{i}] {format_vert(v)} <-- EXTRA")

            # C0 analysis
            bi = r['builder_info']
            print(f"  C0 slot analysis:")
            print(f"    Base values: {bi['base_values']}")
            print(f"    Z variants: {bi['z_values']}")
            if bi['c0_slots']:
                for slot, vals in sorted(bi['c0_slots'].items()):
                    print(f"    Slot {slot}: {format_vert(vals)}")
                    # Check: what should this slot be?
                    # Try matching to unmatched DXF vertices
                    for dv in r['dxf_verts']:
                        key = f"{dv[0]:.1f},{dv[1]:.1f},{dv[2]:.1f}"
                        if key not in oot_set:
                            print(f"      -> Should be {format_vert(dv)}?")
                            # Analyze what inheritance rule would produce it
                            print(f"         Need: X={dv[0]:.1f} (base={bi['base_values'][0]}), "
                                  f"Y={dv[1]:.1f} (base={bi['base_values'][1]}), "
                                  f"Z={dv[2]:.1f} (base={bi['base_values'][2]})")

            # Analyze C0 tag lo_nib patterns
            print(f"  C0 tag lo_nib analysis:")
            for i in range(r['coord_group_end']):
                g = r['groups'][i]
                for t in g['tags']:
                    if t['cls'] == 'C0':
                        ax = r['axis_map'][i]
                        print(f"    group[{i}] ax={ax} val={g['value']:.1f} "
                              f"C0 byte1=0x{t['byte1']:02X} byte2=0x{t['byte2']:02X} "
                              f"hi={t['hi']:X} lo=0x{t['lo']:X}")


def deep_analysis():
    """
    Deep analysis of exactly what's going wrong and what C0 should do.
    """
    print("\n\n" + "=" * 80)
    print(" DEEP ANALYSIS: What C0 tags should do differently")
    print("=" * 80)

    # ── tri-crack (plane) ──
    print("\n" + "-" * 60)
    print("1. tri-crack (plane): 4 verts, 2 faces")
    print("-" * 60)
    print("""
DXF vertices:
  [0] (100, 500, 900)   -- V0
  [1] (300, 600, 900)   -- V1
  [2] (300, 500, 900)   -- V2  <-- MISSING from OOT
  [3] (100, 600, 900)   -- V3

OOT coord groups:
  [0] X=100 FULL           axis=X
  [1] Y=500 FULL           axis=Y
  [2] Z=900 FULL  C0:17    axis=Z  <-- C0 slot 1, lo=7
  [3] Y=600 DELTA C0:17    axis=Y  <-- C0 slot 1, lo=7
  [4] X=300 DELTA           axis=X

Current behavior:
  - V0=(100,500,900) from groups 0-2 (running state)
  - V1=(100,600,900) from group 3 (running: X=100 unchanged, Y=600)
  - V2=(300,600,900) from group 4 (running: X=300)
  - C0 slot 1 initialized to base (100,500,900), then:
    group[2] ax=Z -> slot[1][Z] = 900
    group[3] ax=Y -> slot[1][Y] = 600
    Result: C0[1] = (100, 600, 900) -- DUPLICATE of V1!

What SHOULD happen: C0[1] = (300, 500, 900)
  The C0 tag on groups 2 and 3 says "build a vertex that uses
  the OTHER value for each axis". Since:
  - Group 2 provides Z=900 and C0 says "include this Z" -> Z=900
  - Group 3 provides Y=600 and C0 says "include this Y" -> Y=600? NO!

  Actually C0 slot should inherit RUNNING values AFTER all coords are processed.
  Or: C0 slot should use values NOT from the tagged coord but from the base.

  The missing vertex (300, 500, 900) needs:
  - X=300 (from group 4, the last X value)
  - Y=500 (base Y, NOT the Y=600 from group 3)
  - Z=900 (only one Z variant)

  HYPOTHESIS: C0 tags DON'T assign the tagged coord's value to the slot.
  Instead, C0 tags mean "create a vertex for this slot using base values
  for this axis (NOT the current coord's value)". In other words, C0 is
  a REFERENCE BACK to the base, not a forward assignment.

  Alternative HYPOTHESIS: C0 slot should inherit from the END of the
  coord stream (running state at the end), and the C0-tagged axes
  get the BASE value instead of the running value.
""")

    # ── tri-crack-solid (cube) ──
    print("-" * 60)
    print("2. tri-crack-solid (cube): 8 verts, 12 faces")
    print("-" * 60)
    print("""
DXF vertices (cube corners):
  [0] (100, 500, 900)
  [1] (100, 500, 950)
  [2] (100, 600, 950)
  [3] (300, 500, 900)
  [4] (100, 600, 900)
  [5] (300, 500, 950)
  [6] (300, 600, 950)
  [7] (300, 600, 900)

3 unique X: 100, 300
3 unique Y: 500, 600
3 unique Z: 900, 950

Cube = all 8 combinations of {100,300} x {500,600} x {900,950}

OOT coord groups:
  [0] X=100 FULL                axis=X
  [1] Y=500 FULL                axis=Y
  [2] Z=900 FULL  E0:07         axis=Z
  [3] Z=950 DELTA E0:05         axis=Z  (E0 same-axis repeat)
  [4] Y=600 DELTA C0:17 C0:2F   axis=Y
  [5] X=300 DELTA C0:47 C0:5F C0:2F C0:17  axis=X

Current result: 9 vertices (one duplicate: (300,600,950) appears as both P4 and C0[2])

C0 tags on group[4] (Y=600):
  C0:17 slot=1 lo=7 -> Z=900 (z_values[0])
  C0:2F slot=2 lo=F -> Z=950 (z_values[1])

C0 tags on group[5] (X=300):
  C0:47 slot=4 lo=7 -> Z=900
  C0:5F slot=5 lo=F -> Z=950
  C0:2F slot=2 lo=F -> Z=950 (OVERWRITE slot 2!)
  C0:17 slot=1 lo=7 -> Z=900

Current C0 slot behavior: copies running value for the current axis.
  group[4] ax=Y: slot[1][Y]=600, slot[2][Y]=600  -- both get Y=600
  group[5] ax=X: slot[4][X]=300, slot[5][X]=300, slot[2][X]=300, slot[1][X]=300

After group[4]: slot[1]=(100,600,900), slot[2]=(100,600,950)
After group[5]: All slots get X=300:
  slot[1]=(300,600,900), slot[2]=(300,600,950),
  slot[4]=(300,500,900), slot[5]=(300,500,950)

Expected vertices that should come from C0:
  (300,500,900), (300,500,950), (300,600,950), (300,600,900)

Actual C0 slots produce:
  slot[1]=(300,600,900), slot[2]=(300,600,950),
  slot[4]=(300,500,900), slot[5]=(300,500,950)

These ARE correct! The issue is the DUPLICATE: P4=(300,600,950) duplicates C0[2].

The duplicate comes from the lo=0xF TWO-PRIMARY rule:
  group[4] lo=F on first non-C0 tag -> creates TWO primaries
  P2=(100,600,900) and P3=(100,600,950) -- CORRECT
  Then group[5] creates P4=(300,600,950) from running state -- this is the X=300 update.
  But running still has Y=600 and Z=950 from the last update.

  The problem: group[5]'s primary vertex (300,600,950) is a duplicate of C0 slot 2.
  Either:
  a) Group[5] should NOT create a primary (it only has C0 tags for vertex creation)
  b) Or the vertex ordering needs dedup

For the CUBE, C0 slots work PERFECTLY! The issue is just the extra primary from group[5].
""")

    # ── tri-crack-prism ──
    print("-" * 60)
    print("3. tri-crack-prism (wedge): 5 verts, 2 faces")
    print("-" * 60)
    print("""
DXF vertices:
  [0] (100, 1000, 5000)
  [1] (150, 1000, 5500)
  [2] (150, 500, 5000)
  [3] (150, 1500, 6000)

OOT coord groups:
  [0] X=100  FULL           axis=X
  [1] Y=1000 FULL           axis=Y
  [2] Z=5000 FULL           axis=Z
  [3] X=150  DELTA          axis=X
  [4] Y=1500 DELTA          axis=Y
  [5] Z=6000 DELTA C0:17 C0:2F  axis=Z
  [6] Z=5500 DELTA C0:17    axis=Z (parsed but cut off by coord_group_end=5!)
  [7] Z=503.75 DELTA        axis=Z (garbage -- too many delta ops)

CRITICAL: coord_group_end = 5, but groups 5 and 6 contain essential data!
  group[5] Z=6000 has C0 tags
  group[6] Z=5500 has C0 tag

The problem: coord_group_end cuts off too early.
  After group 4, running = (150, 1500, 5000)
  group[5] Z=6000: creates primary (150, 1500, 6000) -- MATCHES DXF[3]!
  group[6] Z=5500: creates primary or C0 slot

But groups 5+ are cut at coord_group_end=5 because the detection logic
stops when values exceed a range threshold.

Actually wait -- let me re-check. 6000 vs first_real=100:
  6000 > 100 * 50 = 5000... so 6000 > 5000 triggers the "jumps dramatically" check!

FIX NEEDED: The coord_group_end detection is too aggressive. The values
5000, 6000, 5500 are legitimate Z coordinates in a mining context.

Even if we fix coord_group_end, we still need to understand C0 behavior.
  group[5] Z=6000 with C0:17 (slot 1, lo=7) and C0:2F (slot 2, lo=F):
  group[6] Z=5500 with C0:17 (slot 1, lo=7):

Expected DXF vertices from C0 logic:
  slot 1 should produce (150, 1000, 5500)
  slot 2 should produce (150, 500, 5000)

For slot 1: X=150 (running), Y=1000 (BASE Y!), Z=5500 (from group 6)
  -> The C0 on group 5 assigns Z=6000 to slot 1? NO, we need Z=5500.
  -> Maybe C0 on group 6 overwrites slot 1's Z to 5500. That works!

For slot 2: X=150 (running), Y=500 (BASE Y!?), Z=5000 (BASE Z!)
  -> But 500 is the base Y in the DXF... wait, 500 appears NOWHERE in
     the OOT coord stream as an explicit Y value. Y values are 1000 and 1500.
  -> DXF vertex (150, 500, 5000) has Y=500 which is NOT in any group.

  Actually wait -- look at group[7] val=503.75. Could this be a mis-parse of Y=500?
  The stored byte [7F] delta from Z=5500: prev was Z high bytes, inserting 7F...
  What if this is supposed to be Y=500 axis but the axis machine put it on Z?

CONCLUSION: The prism case has TWO problems:
  1. coord_group_end cuts too early (6000 > 5000 = first_val * 50)
  2. The axis machine may misassign group 7

The Y=500 value in DXF vertex (150, 500, 5000) must come from somewhere.
Possibly it's the group[7] value that should be Y=500 not Z=503.75.
""")

    # ── Key findings ──
    print("=" * 80)
    print(" KEY FINDINGS AND RECOMMENDATIONS")
    print("=" * 80)
    print("""
1. TRIANGLE (single face): PERFECT. 3 primaries from running state. No C0.

2. PLANE (tri-crack): C0 slot inherits RUNNING value for its axis.
   Problem: C0[1] gets Y=600 from group[3], making it (100,600,900) = duplicate.
   Should be: (300,500,900) -- needs X=300 (future value!) and Y=500 (base value).

   INSIGHT: C0 slot assignment is DEFERRED. The slot collects which axes
   are assigned but the final vertex is assembled AFTER all coords are
   processed, using the FINAL running state for non-tagged axes.

   Current code: c0_slots[slot][ax] = g.value (assigns immediately)
   Fix needed: C0 slots should NOT inherit the tagged axis value directly.
   Instead, C0 tags mark which axes use BASE values vs RUNNING values.

   C0 lo=7: use base Z (z_values[0]) or base value for the current axis?
   C0 lo=F: use z_values[1]?

   For the PLANE: slot 1 tagged on groups 2(Z) and 3(Y).
   If "tagged means use BASE for that axis":
     slot[1] = (running_X=300, base_Y=500, base_Z=900) = (300,500,900) CORRECT!

3. CUBE (tri-crack-solid): C0 slots produce correct vertices!
   The only issue is one extra primary vertex (duplicate).

   C0 tags on group[4] (Y=600): slots 1,2 -> these axes should NOT use base Y
   C0 tags on group[5] (X=300): slots 4,5,2,1 -> these axes should NOT use base X

   Wait, this contradicts the plane hypothesis. Let me re-examine...

   For cube C0 slot 4: tagged on group[5] ax=X with lo=7
     Current: slot[4][X] = 300, slot[4][Y] = base=500, slot[4][Z] = z[0]=900
     Result: (300, 500, 900) = DXF[3] CORRECT

   For cube C0 slot 1: tagged on group[4] ax=Y with lo=7, and group[5] ax=X with lo=7
     After group[4]: slot[1] = (base_X=100, Y=600, Z=z[0]=900) = (100,600,900)
     After group[5]: slot[1][X] = 300 -> (300, 600, 900) = DXF[7] CORRECT

   So for the cube, C0 assigns the CURRENT coord value to the slot for that axis!
   slot[1] gets Y=600 from group[4], then X=300 from group[5].
   Non-assigned axes keep base values. Z is set by lo_nib (7=z[0], F=z[1]).
   This IS what the current code does, and it works for the cube!

4. So WHY does it fail for the plane?
   Plane C0 slot 1: tagged on group[2] ax=Z, group[3] ax=Y
     After group[2]: slot[1] = (base=100, base=500, Z=900) -- lo=7 -> Z=z[0]=900
     After group[3]: slot[1][Y] = 600 -> (100, 600, 900) = DXF[3]?

   DXF[3] = (100, 600, 900) -- YES this IS in DXF!
   But the MISSING vertex is DXF[2] = (300, 500, 900).

   So C0 slot 1 correctly produces (100, 600, 900) = DXF[3].
   The problem is that (300, 500, 900) is NOT produced at all!

   In the current code, primaries are:
     P0 = (100, 500, 900) from groups 0-2
     P1 = (100, 600, 900) from group 3 (Y=600, running X still 100)
     P2 = (300, 600, 900) from group 4 (X=300, running Y still 600)
   C0: slot[1] = (100, 600, 900) = P1 (DUPLICATE!)

   The vertex (300, 500, 900) needs to come from somewhere. It requires:
     X=300 (from group 4), Y=500 (base), Z=900 (only Z value)

   This is an "implicit" vertex -- all axes at their non-primary values except X.
   The axis state machine puts group[3] on Y (correct) and group[4] on X (correct).

   The lo=F tag on groups 3 and 4 triggers the axis direction reversal.
   group[3]: ft.lo=0xF, ft.hi=0 -> direction=-1, axis = (Y-1)%3 = Y? NO.

   Wait, let me re-check axis state machine for the plane:
   group[3]: ft=80:0F -> lo=0xF, hi=0 -> direction=-1, ax = ((1-1)%3+3)%3 = 0 = X!?

   But the output shows group[3] axis=Y! Let me recheck...

   Actually in the output: group[3] axis=1 (Y). Let me trace manually:
   i=3, prev axis=2 (Z), direction=1
   ft = 80:0F, cls=80, lo=0xF, hi=0
   -> lo==0xF and hi==0: direction=-1, ax = ((2-1)%3+3)%3 = 1 = Y. Correct!

   i=4, prev axis=1 (Y), direction=-1
   ft = A0:0F, cls=A0, lo=0xF, hi=0
   -> lo==0xF and hi==0: direction=-1 (already), ax = ((1-1)%3+3)%3 = 0 = X. Correct!

   So axes are correct. The problem is purely in vertex construction.

   REAL ISSUE FOR PLANE: There are only 5 coord groups for 4 unique vertices.
   3 groups make the initial vertex. 2 more groups = 2 new axis values.
   But we need to build 3 MORE unique vertices from just 2 new values.

   The 4 vertices are: all combinations of {100,300} x {500,600} x {900}
   That's 2x2x1 = 4 vertices. We have X={100,300}, Y={500,600}, Z={900}.

   V0 = (100, 500, 900) -- from initial 3 groups
   V1 = (100, 600, 900) -- Y changes to 600
   V2 = (300, 600, 900) -- X changes to 300 (Y stays 600 from running)
   V3 = (300, 500, 900) -- NEEDS Y to go back to 500

   C0 tag on group[3] (Y=600): "also create a vertex with the OPPOSITE Y"?
   C0 tag on group[2] (Z=900): "also mark Z for this slot"?

   If C0 means "this slot gets the BASE value for this axis":
     slot 1 tagged on Z (group 2): slot[1].Z = base_Z = 900 (lo=7 -> z[0])
     slot 1 tagged on Y (group 3): slot[1].Y = base_Y = 500
     Non-tagged axes use FINAL running state:
       slot[1].X = final_running_X = 300
     Result: (300, 500, 900) = DXF[2] CORRECT!

   But this CONTRADICTS the cube behavior where C0 assigns the CURRENT value!

   OR: For the CUBE, C0 tags assign current value AND it works because
   there are separate slots for each combination. Let me verify with the
   "C0 = base value" hypothesis for the cube:

   Cube group[4] Y=600, C0:17 (slot 1), C0:2F (slot 2):
     "slot 1 use base Y": slot[1].Y = base_Y = 500
     "slot 2 use base Y": slot[2].Y = base_Y = 500
   Cube group[5] X=300, C0:47 (slot 4), C0:5F (slot 5), C0:2F (slot 2), C0:17 (slot 1):
     "slot 4 use base X": slot[4].X = base_X = 100
     "slot 5 use base X": slot[5].X = base_X = 100
     "slot 2 use base X": slot[2].X = base_X = 100
     "slot 1 use base X": slot[1].X = base_X = 100

   Then non-tagged axes use final running: X=300, Y=600, Z depends on lo_nib

   slot[1]: tagged on Y and X -> use base: X=100, Y=500, Z by lo_nib
     On group 4: lo=7 -> Z=900
     On group 5: lo=7 -> Z=900
     Result: (100, 500, 900) = DXF[0] -- BUT this is already V0!

   That doesn't work for the cube. The "base value" hypothesis fails for cube.

   LET ME TRY ANOTHER HYPOTHESIS: C0 tagged axis gets the CURRENT value,
   non-tagged axes get BASE values (not running). Z comes from lo_nib.

   Plane slot 1:
     tagged on Z (group 2): Z = current = 900
     tagged on Y (group 3): Y = current = 600
     non-tagged X: base_X = 100
     Z overridden by lo=7: Z = z[0] = 900
     Result: (100, 600, 900) = DXF[3] -- but still missing (300, 500, 900)!

   This doesn't help either. We're back to the same problem.

   HYPOTHESIS 3: C0 creates a SNAPSHOT of running state at that point,
   and lo_nib only affects Z. No base value inheritance.

   Plane slot 1:
     group[2] ax=Z: running=(100,500,900), slot[1] = (100,500,900), Z by lo=7 -> 900
     group[3] ax=Y: running=(100,600,900), slot[1].Y = 600 -> (100,600,900)
     Result: (100,600,900) -- still duplicates primary!

   NONE of these simple hypotheses produce (300, 500, 900) for the plane.
   The only way to get X=300 is from group[4], which has NO C0 tag.

   CONCLUSION: The vertex (300, 500, 900) must be produced by a DIFFERENT
   mechanism -- perhaps the lo=0xF on groups 3 and 4 means "split":
   when lo=0xF, it creates TWO vertices - one with the NEW value and one
   with the BASE value for that axis.

   Currently lo=0xF only triggers the two-primary rule when z_values >= 2.
   For the plane (only one Z), the two-primary rule doesn't trigger.

   REVISED HYPOTHESIS: lo=0xF means "create two primaries - one with current
   value, one with base value for this axis" REGARDLESS of z_values count.

   group[3] ax=Y, lo=0xF:
     Primary A: running = (100, 600, 900) -- Y=600 (new value)
     Primary B: (100, 500, 900) -- Y=base=500? No, that's V0 again.

   group[4] ax=X, lo=0xF:
     Primary A: running = (300, 600, 900) -- X=300
     Primary B: (100, 600, 900) -- X=base=100? Duplicate of V1.

   Still doesn't produce (300, 500, 900).

   PERHAPS: C0 slot 1 doesn't inherit the tagged value. Instead:
   - C0:17 on group[2] (Z=900): "slot 1 will eventually need Z=base(lo=7)=900"
   - C0:17 on group[3] (Y=600): "slot 1 will eventually need Y... from final running??"

   The only way X=300 ends up in slot 1 is if non-tagged axes use FINAL running,
   AND tagged axes DON'T use the current value but something else.

   What if C0 means: "for this slot, this axis should use the OTHER value"?
   "Other" meaning: if the current value is the SECOND unique value for this
   axis, use the FIRST (base), and vice versa.

   Plane: X has values {100, 300}. Y has values {500, 600}. Z has {900}.

   C0:17 on group[2] Z=900: "slot 1, Z = other Z". Only one Z, so Z=900.
   C0:17 on group[3] Y=600: "slot 1, Y = other Y" = 500 (base)!
   Non-tagged X: uses FINAL running X = 300.
   Result: (300, 500, 900) = DXF[2] CORRECT!

   Let me verify this with the cube:

   Cube unique values: X={100,300}, Y={500,600}, Z={900,950}

   C0:17 on group[4] Y=600 slot=1 lo=7: "slot 1, Y=other Y=500, Z by lo=7"
   C0:2F on group[4] Y=600 slot=2 lo=F: "slot 2, Y=other Y=500, Z by lo=F"
   C0:47 on group[5] X=300 slot=4 lo=7: "slot 4, X=other X=100, Z by lo=7"
   C0:5F on group[5] X=300 slot=5 lo=F: "slot 5, X=other X=100, Z by lo=F"
   C0:2F on group[5] X=300 slot=2 lo=F: "slot 2, X=other X=100, Z by lo=F"
   C0:17 on group[5] X=300 slot=1 lo=7: "slot 1, X=other X=100, Z by lo=7"

   Non-tagged axes use FINAL running: X=300, Y=600, Z=950

   slot 1: tagged on Y(other=500) and X(other=100).
     X=100, Y=500, Z by lo=7 -> Z=900
     Result: (100, 500, 900) = DXF[0] -- THAT'S V0 AGAIN!

   Hmm, that gives the wrong result for the cube. V0 is already a primary.

   Let me reconsider. For the cube the CURRENT code works:
   slot 1: (300, 600, 900) = DXF[7] CORRECT

   So "other value" hypothesis works for plane but not cube.

   KEY OBSERVATION: In the cube, C0 slots get the CURRENT value (not "other").
   In the plane, we NEED the slot to NOT get the current value.

   The difference: in the cube, C0 tag appears on the SECOND unique axis value.
   In the plane, C0 tags appear on... also the second unique values.

   Wait, for the plane, group[2] Z=900 has C0:17. Z=900 is the FIRST (and only)
   Z value. group[3] Y=600 has C0:17. Y=600 is the SECOND Y value (base=500).

   For the cube: group[4] Y=600 has C0 tags. Y=600 is SECOND Y (base=500).
   group[5] X=300 has C0 tags. X=300 is SECOND X (base=100).

   Cube slot 1: C0:17 on Y=600 -> slot.Y = 600 (current, NOT other)
                C0:17 on X=300 -> slot.X = 300 (current, NOT other)
                Z by lo=7 -> 900
                Result: (300, 600, 900) = DXF[7] CORRECT

   Cube slot 4: C0:47 on X=300 -> slot.X = 300 (current)
                No Y tag -> Y = base = 500
                Z by lo=7 -> 900
                Result: (300, 500, 900) = DXF[3] CORRECT

   So for cube: C0 = current value WORKS.
   For plane: C0 = current value gives (100, 600, 900) which IS DXF[3].
   The MISSING vertex (300, 500, 900) is NOT built by C0 at all!

   So where does (300, 500, 900) come from? It has X=300 and Y=500.
   X=300 comes from group[4]. Y=500 is the base Y.

   GROUP[4] has lo=0xF on its first tag. Maybe lo=0xF should create
   TWO primaries even without multiple Z values:
     Primary 1: running = (300, 600, 900) -- normal
     Primary 2: (300, base_Y, 900) = (300, 500, 900) -- base for the changed axis

   YES! That's it! lo=0xF means "split vertex: create one with new value,
   one with base value for the axis that just changed."

   Let me verify for the cube:
   group[4] Y=600, lo=0xF:
     Primary 1: (100, 600, z[0]) = (100, 600, 900) -- using z_values
     Primary 2: (100, 600, z[1]) = (100, 600, 950)
     Current code already does this because z_values >= 2.

   For the plane (single Z):
     Currently: single primary (100, 600, 900)
     Should be: Primary 1: (100, 600, 900) and Primary 2: (100, 500, 900)?

     That gives us (100, 500, 900) which is V0 again -- duplicate!

   group[4] X=300, lo=0xF:
     Currently: single primary (300, 600, 900)
     Should be: Primary 1: (300, 600, 900) and Primary 2: (300, 500, 900)?

     YES! (300, 500, 900) is the missing vertex!

   But we'd also duplicate V0 from group[3].

   REVISED RULE for lo=0xF:
   - If z_values >= 2: create two primaries with z[0] and z[1] (current behavior)
   - If z_values < 2: create two primaries -- one with current axis value,
     one with BASE value for that axis. Essentially "also snapshot base for this axis."

   WAIT -- or maybe it's simpler. lo=0xF always means "also create a vertex
   with the BASE value for the axis that just changed."

   For cube group[4] Y=600:
     P1: (100, 600, 900) -- already done via z-split
     P2: (100, 600, 950) -- already done via z-split
     Also: (100, 500, 900) = base_Y? (100, 500, 950) = base_Y with z[1]?
     But that would create 4 vertices from one group, which seems too many.

   The cube already works with the z-split, so maybe lo=0xF means:
   "If multiple Z: split on Z. Otherwise: split on this axis's base value."

   That's the simplest explanation that fits both cases!
""")

    # ── Concrete fix proposal ──
    print("=" * 80)
    print(" PROPOSED FIX")
    print("=" * 80)
    print("""
For the lo=0xF primary vertex creation rule:

CURRENT:
  if z_values >= 2 and ft.lo == 0xF:
    create two primaries with z[0] and z[1]
  else:
    create one primary from running state

PROPOSED:
  if ft.lo == 0xF:
    if z_values >= 2:
      create two primaries with z[0] and z[1]  (split on Z)
    else:
      create two primaries:
        P1: running state (current axis value)
        P2: running state but with BASE value for current axis
      (split on the current axis)

This would:
- Triangle: no lo=F tags -> unchanged, still PERFECT
- Plane: group[4] lo=F creates (300,600,900) + (300,500,900) -> adds missing vertex
  group[3] lo=F creates (100,600,900) + (100,500,900) -> V0 duplicate (dedup needed)
- Cube: unchanged (z_values>=2 path)
- Prism: need to fix coord_group_end first, then test

ALSO NEEDED:
- Fix coord_group_end detection for prism (6000 is valid, not garbage)
  The check `av > firstRealValue * 50` is too aggressive when coords span
  different scales (X~100, Y~1000, Z~5000).
- Dedup vertices after building (or don't create duplicate primaries)
- The extra primary in the cube (group[5] creates P4 that duplicates C0[2])
  should be suppressed when a group's primary is purely from C0 assignments
""")


if __name__ == '__main__':
    main()
    deep_analysis()
