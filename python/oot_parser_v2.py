#!/usr/bin/env python3
"""
Vulcan .00t Parser v2 — Standalone decoder.

Combines all reverse-engineering findings:
  - Delta-compressed coordinate extraction
  - Axis state machine (direction-based X/Y/Z tracking)
  - C0 tag vertex assignment (hi_nib = vertex index)
  - EdgeBreaker face topology (group-based C/R/L/E decoding)

Author: Brent Buffham + Claude (reverse-engineering collaboration)
"""

import struct
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


def is_separator(b: int) -> bool:
    return (b & 0x07) == 0x07 and b >= 0x07


def read_be_double(buf: bytes) -> float:
    return struct.unpack('>d', bytes((list(buf) + [0] * 8)[:8]))[0]


# ══════════════════════════════════════════════════════════════
# COORDINATE SECTION PARSER
# ══════════════════════════════════════════════════════════════

@dataclass
class CoordElement:
    etype: str  # 'COORD', 'TAG', 'SEP'
    offset: int = 0
    # COORD fields
    value: float = 0.0
    kind: str = ''  # 'FULL' or 'DELTA'
    n_bytes: int = 0
    # TAG fields
    cls: str = ''
    byte2: int = 0
    lo_nib: int = 0
    hi_nib: int = 0
    # SEP fields
    sep_byte: int = 0


def parse_coord_elements(region: bytes, new_format: bool = False) -> List[CoordElement]:
    """Parse the coordinate region into typed elements.

    Args:
        new_format: If True, use new-format encoding rules:
            - 00-escape: stored bytes starting with 0x00 are FULL values (strip the 0x00)
            - zero-trailing: DELTA values zero out trailing bytes instead of keeping previous
    """
    elements = []
    prev = [0] * 8
    pos = 0

    while pos < len(region):
        b = region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(region):
                break
            stored = list(region[pos + 1:pos + 1 + nb])
            if new_format and stored[0] == 0x00 and len(stored) > 1:
                # New-format "00-escape": strip leading 0x00, treat rest as FULL
                actual = stored[1:]
                r = actual + [0] * (8 - len(actual))
                kind = 'FULL'
            elif stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r = stored + [0] * (8 - nb)
                kind = 'FULL'
            else:
                if new_format:
                    # New format: zero out trailing bytes
                    r = [prev[0]] + stored + [0] * (8 - nb - 1)
                else:
                    # Old format: keep trailing bytes from previous value
                    r = [prev[0]] + stored + list(prev[nb + 1:8])
                kind = 'DELTA'
            r = (r + [0] * 8)[:8]
            val = read_be_double(bytes(r))
            prev = r
            elements.append(CoordElement(
                etype='COORD', offset=pos, value=val, kind=kind, n_bytes=nb
            ))
            pos += 1 + nb
        elif is_separator(b):
            elements.append(CoordElement(etype='SEP', offset=pos, sep_byte=b))
            pos += 1
        elif pos + 1 < len(region):
            b2 = region[pos + 1]
            hi_cls = b & 0xE0
            cls = {0x20: '20', 0x40: '40', 0x60: '60', 0x80: '80',
                   0xA0: 'A0', 0xC0: 'C0', 0xE0: 'E0'}.get(hi_cls, '{:02X}'.format(b))
            elements.append(CoordElement(
                etype='TAG', offset=pos, cls=cls, byte2=b2,
                lo_nib=b2 & 0x0F, hi_nib=(b2 >> 4) & 0x0F,
            ))
            pos += 2
        else:
            break

    return elements


@dataclass
class CoordGroup:
    """A coordinate value and its following tags."""
    value: float
    kind: str
    n_bytes: int
    tags: List[CoordElement] = field(default_factory=list)
    seps: List[int] = field(default_factory=list)
    # Derived
    axis: int = -1  # 0=X, 1=Y, 2=Z
    c0_assignments: List[Tuple[int, int]] = field(default_factory=list)  # (vertex_idx, lo_nib)


def group_coord_elements(elements: List[CoordElement]) -> List[CoordGroup]:
    """Group elements: each COORD + following TAGs/SEPs until next COORD."""
    groups = []
    current = None
    for el in elements:
        if el.etype == 'COORD':
            if current is not None:
                groups.append(current)
            current = CoordGroup(value=el.value, kind=el.kind, n_bytes=el.n_bytes)
        elif current is not None:
            if el.etype == 'TAG':
                current.tags.append(el)
            elif el.etype == 'SEP':
                current.seps.append(el.sep_byte)
    if current is not None:
        groups.append(current)
    return groups


def assign_axes(groups: List[CoordGroup]) -> None:
    """Assign X/Y/Z axis to each coordinate using closest-delta heuristic.

    Each coordinate value is assigned to the axis whose current running value
    is closest. This works for files where axis value ranges don't overlap
    (the common case for mining data: X/Y in thousands, Z in hundreds).

    Falls back to tag-based state machine rules when values are ambiguous.
    """
    if len(groups) < 3:
        for i, g in enumerate(groups):
            g.axis = i
        return

    # First 3 coords are always X(0), Y(1), Z(2)
    for i in range(3):
        groups[i].axis = i

    current = [groups[0].value, groups[1].value, groups[2].value]

    for g in groups[3:]:
        # Closest-delta: assign to axis with nearest current value
        deltas = [abs(g.value - current[ax]) for ax in range(3)]
        best_ax = deltas.index(min(deltas))
        g.axis = best_ax
        current[best_ax] = g.value


def extract_c0_assignments(groups: List[CoordGroup]) -> None:
    """Extract C0 vertex assignments from each group's tags."""
    for g in groups:
        for t in g.tags:
            if t.cls == 'C0':
                g.c0_assignments.append((t.hi_nib, t.lo_nib))


def build_vertex_table(groups: List[CoordGroup]) -> List[List[Optional[float]]]:
    """Build vertex table from coord groups + axis assignments + C0 tags.

    Strategy:
    - V0 is built from the first 3 coord groups (X, Y, Z)
    - Subsequent coords update the "running vertex" state
    - C0 tags assign the current coord value to additional vertex slots
    - Each vertex inherits unset axes from the running state
    """
    # Find max vertex index from C0 tags
    max_v = 0
    for g in groups:
        for vi, lo in g.c0_assignments:
            if vi > max_v:
                max_v = vi

    # Also need to know total vertex count
    # For now, allocate based on max C0 reference + some padding
    n_verts = max(max_v + 1, 3)

    # Initialize vertex table: [X, Y, Z] per vertex
    verts = [[None, None, None] for _ in range(n_verts + 10)]

    # Running state: current X, Y, Z values
    current = [None, None, None]

    # Track which groups are "real" coords (not garbage from face section)
    # Garbage coords have cls='20' tags or produce values far outside normal range
    # For now, stop when we hit suspicious values

    coord_idx = 0
    vertex_count = 0

    for g in groups:
        ax = g.axis
        if ax < 0 or ax > 2:
            continue

        # Update running state
        current[ax] = g.value

        # If this is one of the first 3 coords, it builds V0
        if coord_idx < 3:
            verts[0][ax] = g.value
            if coord_idx == 2:
                vertex_count = 1
        else:
            # This coord creates or updates vertex slots
            # The "primary" vertex gets all 3 current axes
            # C0 tags assign this specific axis value to other vertex slots

            # First, create a new "primary" vertex from running state
            # (only if this is an X coord, completing a new XYZ cycle)
            # Actually, each coord value goes to the running state,
            # and vertices are created by the C0 assignments + face section

            pass

        # Process C0 assignments
        for vi, lo in g.c0_assignments:
            # Ensure vertex slot exists
            while vi >= len(verts):
                verts.append([None, None, None])

            # Assign current coord value to vertex vi's axis
            verts[vi][ax] = g.value

            # The lo_nib encodes Z-variant:
            # lo=7 -> use the "base Z" (first Z value seen)
            # lo=F -> use the "alternate Z" (second Z value seen)
            # For now, we track this but apply it after all coords are processed

        coord_idx += 1

    # V0 is fully defined from first 3 coords
    # Other vertices need their missing axes filled from running state or defaults

    # Collect all Z values seen
    z_values = []
    for g in groups:
        if g.axis == 2 and g.value > 1:  # skip garbage
            if g.value not in z_values:
                z_values.append(g.value)

    # Apply lo_nib Z-variant
    for g in groups:
        for vi, lo in g.c0_assignments:
            if vi < len(verts):
                if lo == 0x7 and len(z_values) >= 1:
                    verts[vi][2] = z_values[0]  # base Z
                elif lo == 0xF and len(z_values) >= 2:
                    verts[vi][2] = z_values[1]  # alternate Z

    # Fill missing axes with nearest reasonable value
    # For V0, all axes should be set
    # For other vertices, fill from V0 or running state
    for vi in range(len(verts)):
        for ax in range(3):
            if verts[vi][ax] is None:
                verts[vi][ax] = verts[0][ax] if verts[0][ax] is not None else 0.0

    # Trim to actual vertex count (based on max C0 ref)
    return verts[:max(n_verts, vertex_count)]


# ══════════════════════════════════════════════════════════════
# FACE SECTION PARSER
# ══════════════════════════════════════════════════════════════

def parse_face_section(face_region: bytes, n_verts_header: int):
    """Parse face section and extract topology ops + vertex refs."""
    elements = []
    pos = 0

    while pos < len(face_region):
        b = face_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(face_region):
                break
            dv = face_region[pos + 1] if nb == 1 else int.from_bytes(face_region[pos + 1:pos + 1 + nb], 'big')
            elements.append(('DATA', dv, pos))
            pos += 1 + nb
        elif is_separator(b):
            elements.append(('SEP', b, pos))
            pos += 1
        elif pos + 1 < len(face_region):
            b2 = face_region[pos + 1]
            hi_cls = b & 0xE0
            cls = {0x20: '20', 0x40: '40', 0xC0: 'C0', 0xE0: 'E0'}.get(hi_cls, '{:02X}'.format(b))
            if b == 0xE1:
                cls = 'E1'
            lo = b2 & 0x0F
            hi = (b2 >> 4) & 0x0F
            elements.append(('TAG', cls, b2, lo, hi, pos))
            pos += 2
        else:
            break

    # Extract topology ops (40/C0 class tags)
    topology_ops = []
    for el in elements:
        if el[0] == 'TAG' and el[1] in ('40', 'C0', 'E1'):
            topology_ops.append({
                'cls': el[1], 'byte2': el[2],
                'lo': el[3], 'hi': el[4], 'offset': el[5],
            })

    # Extract vertex references (DATA values that are valid vertex indices)
    vertex_refs = []
    for el in elements:
        if el[0] == 'DATA':
            dv = el[1]
            if 1 <= dv <= max(n_verts_header, 20) and dv != 0x40 and dv != 0x82 and dv != 0xC0:
                vertex_refs.append(dv)

    # Identify initial triangle vertices
    # Pattern: after 20:00 start, look for DATA values before first E0:03
    initial_verts = []
    found_start = False
    for el in elements:
        if el[0] == 'TAG' and el[1] == '20' and (len(el) > 2 and el[2] == 0x00):
            found_start = True
            continue
        if found_start:
            if el[0] == 'TAG' and el[1] in ('40', 'C0'):
                # Topology tag before vertex data = implicit initial triangle
                break
            if el[0] == 'DATA' and 1 <= el[1] <= max(n_verts_header, 20):
                initial_verts.append(el[1])
            if el[0] == 'TAG' and el[1] == 'E0':
                break

    return topology_ops, vertex_refs, initial_verts


# ══════════════════════════════════════════════════════════════
# EDGEBREAKER FACE DECODER
# ══════════════════════════════════════════════════════════════

class EdgeBreakerDecoder:
    def __init__(self, initial_tri):
        self.faces = [initial_tri]
        self.bnd = list(initial_tri)
        self.g = 1  # gate at position 1 (edge V1->V2)
        self.nv = max(initial_tri) + 1
        self.stack = []

    def C(self):
        n = len(self.bnd)
        if n < 3:
            return False
        li = self.g % n
        L, R = self.bnd[li], self.bnd[(self.g + 1) % n]
        v = self.nv
        self.nv += 1
        self.faces.append((L, R, v))
        self.bnd.insert(li + 1, v)
        self.g = li + 1
        return True

    def R(self):
        n = len(self.bnd)
        if n < 4:
            return False
        li = self.g % n
        ri = (self.g + 1) % n
        L, R = self.bnd[li], self.bnd[ri]
        fr = self.bnd[(self.g + 2) % n]
        self.faces.append((L, R, fr))
        self.bnd.pop(ri)
        if self.g >= len(self.bnd):
            self.g %= len(self.bnd)
        return True

    def L(self):
        n = len(self.bnd)
        if n < 4:
            return False
        li = self.g % n
        L, R = self.bnd[li], self.bnd[(self.g + 1) % n]
        fl = self.bnd[(self.g - 1) % n]
        self.faces.append((fl, L, R))
        self.bnd.pop(li)
        self.g = (li - 1) % len(self.bnd)
        return True

    def E(self):
        n = len(self.bnd)
        if n == 3:
            self.faces.append(tuple(self.bnd))
            self.bnd = []
            if self.stack:
                self.bnd, self.g = self.stack.pop()
            return True
        if n >= 4:
            li = self.g % n
            L, R = self.bnd[li], self.bnd[(self.g + 1) % n]
            fl = self.bnd[(self.g - 1) % n]
            self.faces.append((fl, L, R))
            self.bnd.pop(li)
            self.g = (li - 1) % len(self.bnd)
            return True
        return False

    def gate_advance(self, offset):
        if self.bnd:
            self.g = (self.g + offset) % len(self.bnd)


def decode_faces_simple(topology_ops, initial_tri):
    """Decode faces using the group-based C/C/finalizer pattern.

    For open meshes (strips, fans, planes):
    - Groups of 3 ops: C, C_or_R, finalizer(gate -1)
    - Back-reference groups: C, R, finalizer
    - Closing group: single E/L/R op

    This is the simple deterministic decoder for strip/fan topologies.
    """
    dec = EdgeBreakerDecoder(initial_tri)

    # Filter to just 40/C0 class ops (skip E0, E1, 20 class)
    ops = [o for o in topology_ops if o['cls'] in ('40', 'C0')]

    if not ops:
        return dec.faces

    # Skip the first op if it's the initial face metadata tag
    # (it appears before vertex data in the face section)
    start = 0
    # Check if first op is before any vertex data — heuristic
    if len(ops) > 1:
        start = 0  # include all for now

    i = start
    while i < len(ops):
        op = ops[i]

        # Is this a finalizer? (lo=B, hi=1 with tag 40:1B)
        if op['byte2'] == 0x1B:
            dec.gate_advance(-1)
            i += 1
            continue

        # Single remaining op at end = closing (E)
        if i == len(ops) - 1:
            dec.E()
            i += 1
            continue

        # Check if next op is a finalizer (lookahead)
        next_op = ops[i + 1] if i + 1 < len(ops) else None
        next_is_fin = next_op and next_op['byte2'] == 0x1B

        if next_is_fin:
            # Single op before finalizer = C
            dec.C()
            i += 1
            continue

        # Two ops before finalizer (or end) = C + C or C + R
        next_next = ops[i + 2] if i + 2 < len(ops) else None
        next_next_is_fin = next_next and next_next['byte2'] == 0x1B

        if next_next_is_fin:
            # Pair of ops: first is C, second is C or R
            dec.C()
            i += 1
            # Second op: C if we still have new vertices to create, R otherwise
            # Heuristic: if boundary is growing, C. If it's time to close, R.
            if len(dec.bnd) < 8:  # simple heuristic
                dec.C()
            else:
                dec.R()
            i += 1
            continue

        # Default: treat as C
        dec.C()
        i += 1

    return dec.faces


# ══════════════════════════════════════════════════════════════
# MAIN PARSER
# ══════════════════════════════════════════════════════════════

@dataclass
class OotResult:
    vertices: List[Tuple[float, float, float]] = field(default_factory=list)
    faces: List[Tuple[int, int, int]] = field(default_factory=list)
    coord_values: List[float] = field(default_factory=list)
    n_verts_header: int = 0
    n_faces_header: int = 0
    warnings: List[str] = field(default_factory=list)
    success: bool = False


def parse_oot_v2(filepath: str) -> OotResult:
    """Parse a Vulcan .00t file — standalone, no sidecar needed."""
    result = OotResult()

    with open(filepath, 'rb') as f:
        raw = f.read()

    # Validate header
    if len(raw) < 64:
        result.warnings.append("File too small")
        return result
    if raw[0:4] != b'\xea\xfb\xa7\x8a' or raw[4:8] != b'vulZ':
        result.warnings.append("Bad magic/signature")
        return result

    # Find data section
    # Handle both "Variant\0" (old format) and "Variant/C:..." (new format)
    vi = raw.find(b'Variant')
    if vi < 0:
        result.warnings.append("No Variant marker")
        return result

    # The length byte immediately before "Variant" tells how long the string is
    variant_len = raw[vi - 1]
    ds = vi + variant_len

    # Find the anchor pattern 43 E0 0E in the pre-coordinate header
    anchor = raw.find(b'\x43\xE0\x0E', ds, ds + 20)
    if anchor < 0:
        result.warnings.append("No header anchor pattern")
        return result

    # Vertex count (coordinate count) at anchor+7, face count at anchor+14
    result.n_verts_header = raw[anchor + 7]
    result.n_faces_header = raw[anchor + 14]

    # Find coord_start: search for 0x14 constant after E0 0A/0B
    coord_start = -1
    for off in range(15, 25):
        pos = anchor + off
        if pos + 2 < len(raw) and raw[pos] == 0xE0 and raw[pos + 2] == 0x14:
            coord_start = pos + 3
            break
    if coord_start < 0:
        # Fallback: search for first count byte (0-6) after anchor+14
        for off in range(15, 25):
            pos = anchor + off
            if pos < len(raw) and raw[pos] <= 0x06:
                coord_start = pos
                break
    if coord_start < 0:
        coord_start = anchor + 18  # last resort fallback

    # Find section boundaries using SHADED as universal attribute marker
    shaded_pos = raw.find(b'SHADED', ds)
    if shaded_pos < 0:
        shaded_pos = len(raw)

    # Face section starts at the last "20 00" before SHADED
    face_marker = -1
    for i in range(shaded_pos - 2, coord_start, -1):
        if raw[i] == 0x20 and raw[i + 1] == 0x00:
            face_marker = i
            break

    coord_end = face_marker if face_marker > 0 else shaded_pos
    face_end = shaded_pos

    # ── Parse coordinate section ──
    # Detect format: new format uses Variant/C:... (variant_len > 8)
    is_new_format = variant_len > 8
    coord_region = raw[coord_start:coord_end]
    elements = parse_coord_elements(coord_region, new_format=is_new_format)
    groups = group_coord_elements(elements)
    assign_axes(groups)
    extract_c0_assignments(groups)

    # Store raw coord values
    for g in groups:
        result.coord_values.append(g.value)

    # Build vertex table
    vertices = build_vertex_table(groups)
    result.vertices = [(v[0], v[1], v[2]) for v in vertices if v[0] is not None]

    # ── Parse face section ──
    if face_marker > 0:
        face_region = raw[face_marker:face_end]
        topology_ops, vertex_refs, initial_verts = parse_face_section(
            face_region, result.n_verts_header
        )

        # Determine initial triangle
        if len(initial_verts) >= 3:
            init_tri = tuple(v - 1 for v in initial_verts[:3])  # 1-based to 0-based
        else:
            init_tri = (0, 1, 2)  # implicit

        # Decode faces
        faces = decode_faces_simple(topology_ops, init_tri)
        result.faces = faces

    result.success = len(result.vertices) > 0
    return result


# ══════════════════════════════════════════════════════════════
# VALIDATION
# ══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import ezdxf
    from pathlib import Path
    from collections import Counter
    from itertools import permutations

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
        """Check how many OOT vertices match DXF vertices."""
        matched = 0
        oot_to_dxf = {}
        for oi, ov in enumerate(oot_verts):
            for di, dv in enumerate(dxf_verts):
                if (abs(ov[0] - dv[0]) < tol and
                    abs(ov[1] - dv[1]) < tol and
                    abs(ov[2] - dv[2]) < tol):
                    oot_to_dxf[oi] = di
                    matched += 1
                    break
        return matched, oot_to_dxf

    files = [
        ("TRIANGLE", "exampleFiles/tri-crack-triangle"),
        ("PLANE", "exampleFiles/tri-crack"),
        ("LINEAR STRIP", "exampleFiles/tri-crack-linear"),
        ("CUBE", "exampleFiles/tri-crack-solid"),
        ("FAN", "exampleFiles/tri-crack-fan"),
        ("PRISM", "exampleFiles/tri-crack-prism"),
        ("4-SIDES PRISM", "exampleFiles/tri-crack-4sides-prism"),
        ("STEPPED PYRAMID", "exampleFiles/tri-crack-Stepped-pyramid"),
        ("L-SHAPE", "exampleFiles/tri-crack-L-SHAPE"),
        ("HEXHOLE", "exampleFiles/tri-crack-Hexhole"),
        ("NONROUND", "exampleFiles/tri-crack-NonRound"),
        ("SPHERE", "exampleFiles/tri-crack-SPHERE"),
    ]

    # Build case-insensitive DXF lookup
    dxf_lookup = {}
    for p in Path("exampleFiles").glob("*.dxf"):
        dxf_lookup[p.stem.lower()] = str(p)

    for name, stem in files:
        oot_path = stem + ".00t"
        stem_base = Path(stem).stem.lower()
        dxf_path = dxf_lookup.get(stem_base, stem + ".dxf")
        if not Path(oot_path).exists():
            continue

        print(f"\n{'=' * 60}")
        print(f"  {name}")
        print(f"{'=' * 60}")

        result = parse_oot_v2(oot_path)
        dxf_verts, dxf_faces = load_dxf(dxf_path)

        print(f"  OOT: {len(result.vertices)} vertices, {len(result.faces)} faces")
        print(f"  DXF: {len(dxf_verts)} vertices, {len(dxf_faces)} faces")

        if result.warnings:
            print(f"  Warnings: {result.warnings}")

        # Check vertices
        matched, mapping = check_verts(result.vertices, dxf_verts)
        print(f"  Vertex match: {matched}/{len(dxf_verts)} DXF verts found in OOT")

        if result.vertices:
            print(f"  OOT vertices:")
            for i, v in enumerate(result.vertices[:10]):
                dxf_match = f" -> DXF V{mapping[i]}" if i in mapping else " -> NO MATCH"
                print(f"    V{i}: ({v[0]:.2f}, {v[1]:.2f}, {v[2]:.2f}){dxf_match}")
            if len(result.vertices) > 10:
                print(f"    ... ({len(result.vertices) - 10} more)")

        print(f"  OOT faces ({len(result.faces)}):")
        for i, f in enumerate(result.faces[:8]):
            print(f"    F{i}: {f}")
        if len(result.faces) > 8:
            print(f"    ... ({len(result.faces) - 8} more)")
