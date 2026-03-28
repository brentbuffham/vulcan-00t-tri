#!/usr/bin/env python3
"""
Fix the vertex table builder. Test against all DXF ground truth.

The model:
- Coord section stores UNIQUE axis values (not per-vertex XYZ triples)
- First 3 values = X, Y, Z of V0
- Subsequent values update the "running" X/Y/Z state based on axis tracking
- Each new coord value creates a NEW vertex from the current running state
  (with the new value overriding one axis)
- C0 tags create ADDITIONAL vertices that copy the running state but
  may use a different Z variant (lo=7 vs lo=F)
- The running state carries forward: each new coord value updates it,
  and the updated state becomes the basis for the next vertex
"""

import struct
import ezdxf
from pathlib import Path


def is_separator(b):
    return (b & 0x07) == 0x07 and b >= 0x07


def read_be_double(buf):
    return struct.unpack('>d', bytes((list(buf) + [0]*8)[:8]))[0]


def parse_coord_section(filepath):
    with open(filepath, 'rb') as f:
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
        if raw[i] == 0x20 and raw[i+1] == 0x00:
            face_marker = i
            break

    coord_region = raw[ds+23:face_marker] if face_marker > 0 else raw[ds+23:attr_pos]

    # Parse into groups: each coord value + following tags
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
            val = read_be_double(bytes(r))
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
            b2 = coord_region[pos+1]
            hi_cls = b & 0xE0
            cls = {0x20:'20', 0x40:'40', 0x60:'60', 0x80:'80',
                   0xA0:'A0', 0xC0:'C0', 0xE0:'E0'}.get(hi_cls, '{:02X}'.format(b))
            if groups:
                groups[-1]['tags'].append({
                    'cls': cls, 'byte2': b2,
                    'lo': b2 & 0x0F, 'hi': (b2 >> 4) & 0x0F,
                })
            pos += 2
        else:
            break

    return groups, n_verts, n_faces


def build_vertices(groups):
    """Build vertex table from coord groups.

    Model:
    - running_state = [X, Y, Z] starts as [None, None, None]
    - First 3 coords set V0's X, Y, Z and initialize running_state
    - After that, each coord updates one axis of running_state (per axis rules)
    - The PRIMARY vertex for each coord = snapshot of running_state after update
    - C0 tags create ADDITIONAL vertex copies from running_state
      with Z overridden by the lo_nib variant
    """

    # ── Axis tracking ──
    axis_assignments = []
    axis = 0
    direction = 1

    for i, g in enumerate(groups):
        ft = None
        for t in g['tags']:
            if t['cls'] != 'C0':
                ft = t
                break

        if i < 3:
            ax = i
        else:
            if ft is None:
                ax = (axis + direction) % 3
            elif ft['cls'] == 'E0':
                ax = axis
            elif ft['lo'] == 0xF and ft['hi'] == 0:
                direction = -1
                ax = (axis + direction) % 3
            elif ft['lo'] == 0xF and ft['hi'] > 0:
                ax = axis
            else:
                ax = (axis + direction) % 3

        axis_assignments.append(ax)
        axis = ax

    # ── Collect Z variants ──
    z_values = []
    for i, g in enumerate(groups):
        if i < len(axis_assignments) and axis_assignments[i] == 2:
            v = round(g['value'], 6)
            if abs(v) > 0.01 and v not in z_values:  # skip garbage
                z_values.append(v)

    # ── Build vertices ──
    running = [None, None, None]
    vertices = []  # list of (x, y, z)
    vertex_created_at = []  # which coord group created each vertex

    # V0 from first 3 coords
    for i in range(min(3, len(groups))):
        ax = axis_assignments[i]
        running[ax] = groups[i]['value']

    if running[0] is not None and running[1] is not None and running[2] is not None:
        vertices.append(tuple(running))
        vertex_created_at.append(0)

    # Process remaining coord groups
    for i in range(3, len(groups)):
        g = groups[i]
        ax = axis_assignments[i] if i < len(axis_assignments) else 0
        val = g['value']

        # Sanity check: stop if values look like garbage (face section data)
        if abs(val) < 0.01 and ax != 2:  # small non-Z values are suspicious
            # Check if this is still a valid coord
            has_20_tag = any(t['cls'] == '20' for t in g['tags'])
            if has_20_tag:
                break  # Entered face section

        # Update running state
        running[ax] = val

        # Create primary vertex from running state
        # (only if this coord introduces a genuinely new vertex)
        # Heuristic: a new vertex is created when the coord has
        # non-C0 tags (80, A0, etc.) indicating a primary assignment
        ft = None
        for t in g['tags']:
            if t['cls'] != 'C0':
                ft = t
                break

        # Check: does this group have C0 tags? If so, C0 tags create the vertices.
        # If not, the primary coord creates a new vertex.
        c0_tags = [t for t in g['tags'] if t['cls'] == 'C0']

        if not c0_tags:
            # No C0 tags: this coord creates ONE new vertex
            vertices.append(tuple(running))
            vertex_created_at.append(i)

        # C0 tags: each creates an additional vertex slot
        for t in c0_tags:
            vi = t['hi']
            lo = t['lo']

            # Build vertex from running state
            v = list(running)

            # Override Z based on lo_nib
            if len(z_values) >= 2:
                if lo == 0x7:
                    v[2] = z_values[0]
                elif lo == 0xF:
                    v[2] = z_values[1]
            elif len(z_values) == 1:
                v[2] = z_values[0]

            # Place at the C0-specified index
            while vi >= len(vertices):
                vertices.append(tuple(running))
            vertices[vi] = tuple(v)

    return vertices


def load_dxf(path):
    doc = ezdxf.readfile(path)
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
    return vl, fl


def check_verts(oot_verts, dxf_verts, tol=1.0):
    matched = 0
    mapping = {}
    used_dxf = set()
    for oi, ov in enumerate(oot_verts):
        for di, dv in enumerate(dxf_verts):
            if di in used_dxf:
                continue
            if (abs(ov[0] - dv[0]) < tol and
                abs(ov[1] - dv[1]) < tol and
                abs(ov[2] - dv[2]) < tol):
                mapping[oi] = di
                used_dxf.add(di)
                matched += 1
                break
    return matched, mapping


files = [
    ("TRIANGLE", "exampleFiles/tri-crack-triangle"),
    ("PLANE", "exampleFiles/tri-crack"),
    ("LINEAR STRIP", "exampleFiles/tri-crack-linear"),
    ("CUBE", "exampleFiles/tri-crack-solid"),
    ("PRISM", "exampleFiles/tri-crack-prism"),
]

total_matched = 0
total_dxf = 0

for name, stem in files:
    oot = stem + ".00t"
    dxf = stem + ".dxf"
    if not Path(oot).exists():
        continue

    groups, nv, nf = parse_coord_section(oot)
    verts = build_vertices(groups)
    dxf_verts, dxf_faces = load_dxf(dxf)

    matched, mapping = check_verts(verts, dxf_verts)

    print(f"\n{'=' * 60}")
    print(f"  {name}: {matched}/{len(dxf_verts)} DXF vertices matched")
    print(f"  OOT produced {len(verts)} vertices, DXF has {len(dxf_verts)}")
    print(f"{'=' * 60}")

    for i, v in enumerate(verts):
        dxf_match = ""
        if i in mapping:
            di = mapping[i]
            dxf_match = f" = DXF V{di} ({dxf_verts[di][0]:.1f}, {dxf_verts[di][1]:.1f}, {dxf_verts[di][2]:.1f})"
        else:
            # Check what's wrong
            dxf_match = " NO MATCH"
        print(f"  OOT V{i}: ({v[0]:.2f}, {v[1]:.2f}, {v[2]:.2f}){dxf_match}")

    # Show unmatched DXF verts
    unmatched_dxf = [i for i in range(len(dxf_verts)) if i not in mapping.values()]
    if unmatched_dxf:
        print(f"  Missing DXF verts: {[f'V{i}({dxf_verts[i][0]:.1f},{dxf_verts[i][1]:.1f},{dxf_verts[i][2]:.1f})' for i in unmatched_dxf]}")

    total_matched += matched
    total_dxf += len(dxf_verts)

print(f"\n{'=' * 60}")
print(f"  OVERALL: {total_matched}/{total_dxf} vertices matched "
      f"({100*total_matched/total_dxf:.0f}%)")
print(f"{'=' * 60}")
