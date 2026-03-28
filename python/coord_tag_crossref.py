#!/usr/bin/env python3
"""
Cross-reference: for each vertex, what coordinate data exists in the coord
section AND what tag byte appears in the face section?

Parse the coord section element-by-element, tracking which coord values and
tags belong to which vertex. Then compare with face section tags.
"""

import struct
from pathlib import Path


def is_separator(b):
    return (b & 0x07) == 0x07 and b >= 0x07


def read_be_double(buf):
    return struct.unpack('>d', bytes((list(buf) + [0]*8)[:8]))[0]


def parse_coord_section(filepath):
    """Parse the coordinate section, returning every element with full context."""
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

    coord_start = ds + 23
    coord_end = face_marker if face_marker > 0 else attr_pos
    face_end = attr_pos

    coord_region = raw[coord_start:coord_end]
    face_region = raw[face_marker:face_end] if face_marker > 0 else b''

    # Parse coord section
    coord_elements = []
    prev = [0]*8
    pos = 0
    while pos < len(coord_region):
        b = coord_region[pos]
        if b <= 0x06:
            count = b
            nb = count + 1
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
            coord_elements.append({
                'type': 'COORD',
                'offset': pos,
                'count': count,
                'n_bytes': nb,
                'kind': kind,
                'value': val,
                'raw': coord_region[pos:pos+1+nb],
            })
            prev = r
            pos += 1 + nb
        elif is_separator(b):
            coord_elements.append({
                'type': 'SEP',
                'offset': pos,
                'byte': b,
            })
            pos += 1
        elif pos + 1 < len(coord_region):
            b2 = coord_region[pos+1]
            hi_byte = b & 0xE0
            cls = {0x20:'20', 0x40:'40', 0x60:'60', 0x80:'80',
                   0xA0:'A0', 0xC0:'C0', 0xE0:'E0'}.get(hi_byte, f'{b:02X}')
            lo = b2 & 0x0F
            hi = (b2 >> 4) & 0x0F
            coord_elements.append({
                'type': 'TAG',
                'offset': pos,
                'cls': cls,
                'byte1': b,
                'byte2': b2,
                'lo_nib': lo,
                'hi_nib': hi,
            })
            pos += 2
        else:
            break

    # Parse face section
    face_elements = []
    pos = 0
    while pos < len(face_region):
        b = face_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(face_region):
                break
            dv = face_region[pos+1] if nb == 1 else int.from_bytes(face_region[pos+1:pos+1+nb], 'big')
            face_elements.append({
                'type': 'DATA',
                'offset': pos,
                'value': dv,
                'raw': face_region[pos:pos+1+nb],
            })
            pos += 1 + nb
        elif is_separator(b):
            face_elements.append({'type': 'SEP', 'offset': pos, 'byte': b})
            pos += 1
        elif pos + 1 < len(face_region):
            b2 = face_region[pos+1]
            hi_byte = b & 0xE0
            cls = {0x20:'20', 0x40:'40', 0x60:'60', 0x80:'80',
                   0xA0:'A0', 0xC0:'C0', 0xE0:'E0'}.get(hi_byte, f'{b:02X}')
            if b == 0xE1: cls = 'E1'
            lo = b2 & 0x0F
            hi = (b2 >> 4) & 0x0F
            face_elements.append({
                'type': 'TAG',
                'offset': pos,
                'cls': cls,
                'byte1': b,
                'byte2': b2,
                'lo_nib': lo,
                'hi_nib': hi,
            })
            pos += 2
        else:
            break

    return {
        'n_verts': n_verts,
        'n_faces': n_faces,
        'coord_elements': coord_elements,
        'face_elements': face_elements,
    }


def analyze_file(name, filepath):
    print(f"\n{'='*78}")
    print(f"  {name}")
    print(f"{'='*78}")

    data = parse_coord_section(filepath)
    ce = data['coord_elements']
    fe = data['face_elements']

    print(f"  Header: {data['n_verts']} verts, {data['n_faces']} faces")

    # ── Coord section: group elements by vertex ──
    # Strategy: coordinate values build vertices. The tags between coords
    # tell us about vertex construction. Let's segment by looking at
    # the pattern: [COORD] [TAG]* [COORD] [TAG]* ...
    # and group the tags that follow each COORD value.

    print(f"\n  COORD SECTION ELEMENTS ({len(ce)} elements):")
    coord_idx = 0
    for el in ce:
        if el['type'] == 'COORD':
            print(f"    [{el['offset']:3d}] COORD #{coord_idx}: count={el['count']} "
                  f"({el['kind']}) {el['n_bytes']}B stored -> {el['value']:.6f}")
            coord_idx += 1
        elif el['type'] == 'TAG':
            print(f"    [{el['offset']:3d}] TAG   {el['cls']}:{el['byte2']:02X} "
                  f"(lo={el['lo_nib']:X} hi={el['hi_nib']:X})")
        elif el['type'] == 'SEP':
            print(f"    [{el['offset']:3d}] SEP   0x{el['byte']:02X}")

    # ── Group coords with following tags ──
    # Each group = one coord value + the tags/seps that follow before next coord
    print(f"\n  COORD GROUPS (coord + following tags):")
    groups = []
    current = None
    for el in ce:
        if el['type'] == 'COORD':
            if current is not None:
                groups.append(current)
            current = {
                'coord': el,
                'tags': [],
                'seps': [],
            }
        elif current is not None:
            if el['type'] == 'TAG':
                current['tags'].append(el)
            elif el['type'] == 'SEP':
                current['seps'].append(el)
    if current is not None:
        groups.append(current)

    for i, g in enumerate(groups):
        c = g['coord']
        tags_str = ', '.join(f"{t['cls']}:{t['byte2']:02X}" for t in g['tags'])
        seps_str = ', '.join(f"0x{s['byte']:02X}" for s in g['seps'])
        n_tags = len(g['tags'])
        n_seps = len(g['seps'])
        total_following = n_tags * 2 + n_seps  # bytes of non-coord data following

        print(f"    Coord #{i}: {c['value']:12.4f}  "
              f"stored={c['n_bytes']}B ({c['kind']})  "
              f"followed by {n_tags} tags + {n_seps} seps = {total_following}B")
        if tags_str:
            print(f"      Tags: [{tags_str}]")
        if seps_str:
            print(f"      Seps: [{seps_str}]")

    # ── Face section topology tags ──
    print(f"\n  FACE SECTION TOPOLOGY TAGS:")
    face_topology_tags = []
    for el in fe:
        if el['type'] == 'TAG' and el['cls'] in ('40', 'C0', 'E1'):
            face_topology_tags.append(el)
            print(f"    [{el['offset']:3d}] {el['cls']}:{el['byte2']:02X} "
                  f"(lo={el['lo_nib']:X} hi={el['hi_nib']:X})")

    # ── Cross reference ──
    # For each C operation (topology tag), what coord group does the
    # corresponding vertex come from?
    # We know: vertex 0,1,2 = initial triangle (coord groups 0,1,2 for X,Y,Z)
    # Vertex 3 = first C op creates it, uses coord groups 3+
    # etc.

    print(f"\n  CROSS REFERENCE:")
    print(f"    Coord groups: {len(groups)}")
    print(f"    Face topology tags: {len(face_topology_tags)}")

    # Count how many coord values exist (= number of unique axis values)
    n_coords = len(groups)
    # Count tags between coordinates
    tag_counts_after_coord = []
    for g in groups:
        tag_counts_after_coord.append(len(g['tags']))

    print(f"    Tags-after-coord pattern: {tag_counts_after_coord}")

    # The first 3 coords build the initial vertex (X, Y, Z)
    # Each subsequent coord changes one axis and may create new vertices
    # The TAGS between coords encode which vertex gets the new value

    # For each coord group, extract the tag CLASS pattern
    print(f"\n  TAG CLASS PATTERNS after each coord:")
    for i, g in enumerate(groups):
        c = g['coord']
        tag_classes = [t['cls'] for t in g['tags']]
        tag_byte2s = [t['byte2'] for t in g['tags']]
        sep_count = len(g['seps'])
        print(f"    Coord #{i} ({c['value']:10.2f}, {c['n_bytes']}B {c['kind']}): "
              f"tags={tag_classes}  byte2s={[f'0x{b:02X}' for b in tag_byte2s]}  "
              f"seps={sep_count}")

    return data, groups, face_topology_tags


# ══════════════════════════════════════════════════════════════
# Analyze all test files
# ══════════════════════════════════════════════════════════════

files = [
    ("TRIANGLE", "exampleFiles/tri-crack-triangle.00t"),
    ("PLANE", "exampleFiles/tri-crack.00t"),
    ("LINEAR STRIP", "exampleFiles/tri-crack-linear.00t"),
    ("CUBE", "exampleFiles/tri-crack-solid.00t"),
]

all_data = {}
for name, path in files:
    if Path(path).exists():
        all_data[name] = analyze_file(name, path)

# ══════════════════════════════════════════════════════════════
# Summary cross-reference table
# ══════════════════════════════════════════════════════════════

print(f"\n{'='*78}")
print(f"  SUMMARY: Coord section tag counts vs Face section hi_nib")
print(f"{'='*78}")

for name in ["TRIANGLE", "PLANE", "LINEAR STRIP", "CUBE"]:
    if name not in all_data:
        continue
    data, groups, face_tags = all_data[name]
    print(f"\n  {name}:")
    print(f"    Coord groups: {len(groups)}")
    print(f"    Face topology tags: {len(face_tags)}")

    # Show tag-after-coord counts
    for i, g in enumerate(groups):
        n_tags = len(g['tags'])
        n_seps = len(g['seps'])
        c = g['coord']
        print(f"    Coord #{i}: {c['value']:10.2f} ({c['kind']}, {c['n_bytes']}B) "
              f"-> {n_tags} tags, {n_seps} seps after")

    # Show face tag hi_nibs
    face_hi_nibs = [t['hi_nib'] for t in face_tags]
    print(f"    Face tag hi_nibs: {face_hi_nibs}")
    face_byte2s = ['0x{:02X}'.format(t['byte2']) for t in face_tags]
    print(f"    Face tag byte2s:  {face_byte2s}")

    # Coord tag count pattern
    coord_tag_counts = [len(g['tags']) for g in groups]
    print(f"    Coord tag-count pattern: {coord_tag_counts}")
    print(f"    Sum of coord tags: {sum(coord_tag_counts)}")

    # Look for correlation: do face hi_nibs match coord tag counts?
    print(f"    --- Correlation check ---")
    for i, ft in enumerate(face_tags):
        # Does hi_nib match anything about the coord groups?
        hi = ft['hi_nib']
        if i < len(coord_tag_counts):
            ct = coord_tag_counts[i]
            match_ct = "YES" if hi == ct else f"no ({hi} vs {ct})"
        else:
            match_ct = "n/a"
        print(f"    Face tag {i}: hi={hi}, coord_tags[{i}]={match_ct}")
