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
    # Dynamic IDELTA threshold: after seeing first 3 FULL values, set to 3× max
    full_values = []
    idelta_threshold = 10000  # default until we have base values

    while pos < len(region):
        b = region[pos]
        if b <= 0x06 or (new_format and b == 0x07):
            nb = b + 1
            raw_nb = nb  # preserve original byte count for position advancement
            if pos + 1 + nb > len(region):
                break
            stored = list(region[pos + 1:pos + 1 + nb])
            if new_format and len(stored) > 1:
                # New-format escape stripping: bytes >= 0xFC or 0x00 are escape prefixes.
                # Strip them until we reach a FULL indicator (0x40, 0x41, 0xC0, 0xC1).
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
            if stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r = stored + [0] * (8 - nb)
                kind = 'FULL'
                # Track FULL values for dynamic threshold
                fv = read_be_double(bytes((r + [0] * 8)[:8]))
                if abs(fv) > 1:
                    full_values.append(abs(fv))
                    if len(full_values) == 3:
                        idelta_threshold = max(full_values) * 3
            else:
                if new_format:
                    # New format: zero out trailing bytes
                    r = [prev[0]] + stored + [0] * (8 - nb - 1)
                else:
                    # Old format: keep trailing bytes from previous value
                    r = [prev[0]] + stored + list(prev[nb + 1:8])
                kind = 'DELTA'
                if new_format and kind == 'DELTA':
                    # Check if standard DELTA produced an unreasonable value.
                    # Use dynamic threshold based on first 3 FULL values (base coords).
                    test_r = (r + [0] * 8)[:8]
                    test_val = read_be_double(bytes(test_r))
                    if abs(test_val) > idelta_threshold:
                        # Signed integer delta: treat stored as signed big-endian
                        # offset applied to prev's IEEE 754 integer representation
                        prev_int = struct.unpack('>Q', bytes(prev))[0]
                        delta_int = int.from_bytes(bytes(stored[:raw_nb]), 'big')
                        if stored[0] >= 0x80:
                            delta_int -= (1 << (raw_nb * 8))
                        result_int = (prev_int + delta_int) & 0xFFFFFFFFFFFFFFFF
                        r = list(struct.pack('>Q', result_int))
                        kind = 'IDELTA'
            r = (r + [0] * 8)[:8]
            val = read_be_double(bytes(r))
            prev = r
            elements.append(CoordElement(
                etype='COORD', offset=pos, value=val, kind=kind, n_bytes=nb
            ))
            pos += 1 + raw_nb  # advance by original byte count, not stripped
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
    """Extract vertex slot assignments from coord section tags.

    Multiple tag classes create slot assignments, not just C0:
    - C0: primary assigner (proven for cube)
    - 40: also assigns in coord section (proven for plane — 40:A7 creates missing vertex)
    - 80, 60, A0, 20: may also assign (hi_nib>0 = slot index, lo_nib = Z select)
    E0 tags (hi_nib always 0) are state markers, not assigners.
    """
    assigner_classes = {'C0', '40', '80', '60', 'A0', '20'}
    for g in groups:
        for t in g.tags:
            if t.cls in assigner_classes and t.hi_nib > 0:
                g.c0_assignments.append((t.hi_nib, t.lo_nib))


def trim_coord_groups(groups: List[CoordGroup]) -> List[CoordGroup]:
    """Trim groups to exclude face section data that leaked into the coord region.

    The coord section transitions to the face section when coordinate values
    become negative (while base coords are positive) — a reliable marker since
    mining coordinates are always positive.
    """
    if len(groups) < 3:
        return groups

    base_positive = all(groups[i].value >= 0 for i in range(min(3, len(groups))))
    if not base_positive:
        return groups  # can't use sign-based trimming

    for i in range(3, len(groups)):
        if groups[i].value < 0:
            return groups[:i]

    return groups


def build_vertex_table(groups: List[CoordGroup], n_faces: int = 0) -> List[List[Optional[float]]]:
    """Build vertex table: PRIMARIES FIRST, then C0 SLOTS APPENDED.

    Proven model from commit 868ec49 ("THE CUBE IS SOLVED"):
    1. Primaries: running state snapshot from each coord group.
       - V0 at group 2 (base XYZ)
       - For groups where first non-C0 tag has lo=F AND 2+ Z values:
         create TWO primaries (one per Z variant)
       - Otherwise: one primary from running state
    2. C0 slots: accumulate axis values, appended in slot number order.
       - lo=7 → base_Z, lo=F → alt_Z
    """
    if len(groups) < 3:
        return [[g.value if g.axis == ax else 0.0 for ax in range(3)]
                for g in groups]

    # Trim face section data
    groups = trim_coord_groups(groups)

    # Base values
    base = [groups[0].value, groups[1].value, groups[2].value]

    # Collect Z values for base/alt
    z_values = []
    for g in groups:
        if g.axis == 2 and abs(g.value) > 1:
            if g.value not in z_values:
                z_values.append(g.value)
    base_z = z_values[0] if z_values else base[2]
    alt_z = z_values[1] if len(z_values) > 1 else base_z

    # Phase 1: Build primaries from running state
    running = [0.0, 0.0, 0.0]
    primaries = []
    c0_slots = {}  # slot_idx -> [x, y, z]

    for i, g in enumerate(groups):
        ax = g.axis
        if ax < 0 or ax > 2:
            continue
        running[ax] = g.value

        # Collect slot assignments from assigner tag classes
        # C0 is primary, 40/80/60/A0/20 with hi_nib>0 also assign
        assigner_classes = {'C0', '40', '80', '60', 'A0', '20'}
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            slot = t.hi_nib
            if slot not in c0_slots:
                c0_slots[slot] = list(base)
            c0_slots[slot][ax] = g.value
            if t.lo_nib == 0x7:
                c0_slots[slot][2] = base_z
            elif t.lo_nib == 0xF:
                c0_slots[slot][2] = alt_z

        # Build primaries
        if i == 2:
            # V0 from base
            primaries.append([running[0], running[1], running[2]])
        elif i > 2:
            # Check first non-C0 tag for lo_nib
            ft = None
            for t in g.tags:
                if t.cls != 'C0':
                    ft = t
                    break

            if ft and ft.lo_nib == 0xF:
                # lo=F: create TWO primaries.
                # Primary 1: running state as-is.
                # Primary 2: running state with PREVIOUS group's axis reverted to base.
                # (For 2+ Z variants, this creates both Z variants.
                #  For 1 Z variant, this creates a vertex where the prev axis = base.)
                primaries.append([running[0], running[1], running[2]])
                base_v = [running[0], running[1], running[2]]
                prev_ax = groups[i - 1].axis if i > 0 and 0 <= groups[i - 1].axis <= 2 else -1
                if prev_ax >= 0:
                    base_v[prev_ax] = base[prev_ax]
                # Only add if different from first primary
                if base_v != [running[0], running[1], running[2]]:
                    primaries.append(base_v)
                elif len(z_values) >= 2:
                    # Fallback: create both Z variants
                    primaries[-1] = [running[0], running[1], z_values[0]]
                    primaries.append([running[0], running[1], z_values[1]])
            else:
                # One primary from running state
                primaries.append([running[0], running[1], running[2]])

    # Phase 2: Vertex list = primaries first, then C0 slots in slot number order
    vertices = list(primaries)
    for slot in sorted(c0_slots.keys()):
        vertices.append(c0_slots[slot])

    return vertices


# ══════════════════════════════════════════════════════════════
# FACE SECTION PARSER
# ══════════════════════════════════════════════════════════════

def parse_face_section(face_region: bytes, n_verts_header: int):
    """Parse face section and extract topology ops + vertex refs.

    """
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


def decode_faces_separator(face_elements, topology_ops, initial_tri, n_verts):
    """Decode faces using separator-based operation detection.

    The separator byte BEFORE each topology op determines the operation:
    - SEP 0x2F, 0x17, 0x3F, 0x27, 0x0F, 0xDF → C (create new vertex)
    - SEP 0x5F, 0x87 → R (reuse right neighbor)
    - No separator → context-dependent:
      - After C → R
      - After R → L
      - After L → E (if boundary=3) or L
      - First no-sep op → C
    - 0x1B byte2 → finalizer (gate advance -1)
    """
    dec = EdgeBreakerDecoder(initial_tri)

    # Build separator context for each topology op
    # Track last separator AND last E0 tag before each topo op
    last_sep = None
    last_e0 = None
    ops_with_sep = []
    for el in face_elements:
        if el[0] == 'SEP':
            last_sep = el[1]
        elif el[0] == 'TAG' and el[1] == 'E0':
            last_e0 = el[2]  # E0 byte2
        elif el[0] == 'TAG' and el[1] in ('40', 'C0', 'E1'):
            ops_with_sep.append({
                'cls': el[1], 'byte2': el[2],
                'lo': el[3], 'hi': el[4],
                'sep': last_sep,
                'e0_before': last_e0,
            })
            last_sep = None
            last_e0 = None

    if not ops_with_sep:
        return dec.faces

    # Expected number of C operations
    c_ops_remaining = max(n_verts - len(initial_tri), 0)
    last_op = None

    for oi, op in enumerate(ops_with_sep):
        if not dec.bnd:
            break

        # Finalizer: gate advance -1
        if op['byte2'] == 0x1B:
            dec.gate_advance(-1)
            continue

        sep = op['sep']
        e0_before = op.get('e0_before')
        n = len(dec.bnd)

        if sep is not None:
            # Separator determines operation
            if sep in (0x5F, 0x87):
                # Large separators → R
                if n >= 4:
                    dec.R()
                    last_op = 'R'
            else:
                # Other separators (0x2F, 0x3F, 0x27, etc.) → C
                if c_ops_remaining > 0:
                    dec.C()
                    c_ops_remaining -= 1
                    last_op = 'C'
                elif n >= 4:
                    dec.R()
                    last_op = 'R'
                else:
                    dec.E()
                    last_op = 'E'
        else:
            # No separator: context-dependent
            if last_op is None or last_op == 'E':
                # First op or after E → C
                if c_ops_remaining > 0:
                    dec.C()
                    c_ops_remaining -= 1
                    last_op = 'C'
                else:
                    dec.E()
                    last_op = 'E'
            elif last_op == 'C':
                if n >= 4:
                    dec.R()
                    last_op = 'R'
                else:
                    dec.E()
                    last_op = 'E'
            elif last_op == 'R':
                if n >= 4:
                    dec.L()
                    last_op = 'L'
                elif n == 3:
                    dec.E()
                    last_op = 'E'
            elif last_op == 'L':
                if n == 3:
                    dec.E()
                    last_op = 'E'
                elif n >= 4:
                    dec.L()
                    last_op = 'L'

    return dec.faces


def decode_faces_and_vertices(face_elements, initial_tri, n_verts, coord_values, base_coords):
    """Decode faces AND build vertices simultaneously using EdgeBreaker coupling.

    Each C operation creates a new vertex. The vertex coordinates come from:
    - A boundary vertex (L from the gate) as reference
    - The next coordinate value from the stream replaces ONE axis of L
    - The axis is chosen by: which axis of L is closest to the coord value

    This solves the axis-overlap problem because vertex coordinates are
    derived from boundary topology, not from independent axis assignment.
    """
    vertices = []
    if len(base_coords) < 3:
        return [], []

    # V0 = base
    vertices.append(list(base_coords[0:3]))

    # V1, V2 from next coord values using closest-delta on running state
    running = list(base_coords[0:3])
    coord_idx = 3

    for vi in range(1, min(3, n_verts)):
        if coord_idx < len(coord_values):
            val = coord_values[coord_idx]
            coord_idx += 1
            deltas = [abs(val - running[ax]) for ax in range(3)]
            best_ax = deltas.index(min(deltas))
            running[best_ax] = val
            vertices.append(list(running))

    # Build separator context for face ops
    last_sep = None
    ops_with_sep = []
    for el in face_elements:
        if el[0] == 'SEP':
            last_sep = el[1]
        elif el[0] == 'TAG' and el[1] in ('40', 'C0', 'E1'):
            ops_with_sep.append({
                'byte2': el[2], 'lo': el[3], 'hi': el[4], 'sep': last_sep,
            })
            last_sep = None

    if not ops_with_sep:
        return vertices, [tuple(initial_tri)]

    # EdgeBreaker state
    faces = [tuple(initial_tri)]
    bnd = list(initial_tri)
    gate = 1
    nv = len(vertices)
    c_ops_remaining = max(n_verts - len(vertices), 0)
    last_op = None

    for op in ops_with_sep:
        if not bnd:
            break
        if op['byte2'] == 0x1B:
            if bnd:
                gate = (gate - 1) % len(bnd)
            continue

        n = len(bnd)
        if n < 3:
            break

        li = gate % n
        ri = (gate + 1) % n
        L, R = bnd[li], bnd[ri]
        sep = op['sep']

        # Determine operation
        if sep is not None:
            if sep in (0x5F, 0x87):
                op_type = 'R'
            else:
                op_type = 'C' if c_ops_remaining > 0 else ('R' if n >= 4 else 'E')
        else:
            if last_op is None or last_op == 'E':
                op_type = 'C' if c_ops_remaining > 0 else 'E'
            elif last_op == 'C':
                op_type = 'R' if n >= 4 else 'E'
            elif last_op == 'R':
                op_type = 'L' if n >= 4 else 'E'
            elif last_op == 'L':
                op_type = 'E' if n == 3 else 'L'
            else:
                op_type = 'E'

        if op_type == 'C' and c_ops_remaining > 0:
            # BUILD VERTEX from boundary vertex + coord value
            # Try both L and R as reference — pick the one where the coord
            # value replaces exactly one axis with the smallest change
            if coord_idx < len(coord_values):
                val = coord_values[coord_idx]
                coord_idx += 1

                # Try both L and R as reference, try all 3 axes for each
                # Score: for each (ref, axis) combo, the OTHER 2 axes should
                # be CLOSE to the reference (they're copied). The replaced axis
                # can differ by any amount. So pick the combo where the replaced
                # axis accounts for the MOST difference.
                best_score = -1
                v_coords = list(vertices[L] if L < len(vertices) else running)
                for ref_idx in (L, R):
                    ref = vertices[ref_idx] if ref_idx < len(vertices) else running
                    for ax in range(3):
                        v = list(ref)
                        v[ax] = val
                        # Score: how close is val to ref[ax]? Smaller = better
                        # (means this axis had a small change = likely correct)
                        score = abs(val - ref[ax])
                        if best_score < 0 or score < best_score:
                            best_score = score
                            v_coords = v
            else:
                # No coord value: build vertex from boundary vertex + Z-select
                # The tag lo_nib bit3 encodes Z: 0→base_Z, 1→alt_Z
                # Try Prev (gate-1), R, and L as reference
                prev_idx = bnd[(gate - 1 + n) % n]
                # Collect Z values for base/alt
                z_vals = sorted(set(v[2] for v in vertices if len(v) > 2))
                base_z = z_vals[0] if z_vals else base_coords[2]
                alt_z = z_vals[1] if len(z_vals) > 1 else base_z
                use_alt_z = bool(op.get('lo', 0) & 0x8)  # bit3 of lo_nib
                target_z = alt_z if use_alt_z else base_z

                # Try each reference: pick one that produces a UNIQUE vertex
                best_ref = L
                for ref_idx in (prev_idx, R, L):
                    ref = vertices[ref_idx] if ref_idx < len(vertices) else running
                    candidate = [ref[0], ref[1], target_z]
                    # Prefer reference that produces a vertex NOT already in the list
                    is_dup = any(abs(v[0]-candidate[0])<0.1 and abs(v[1]-candidate[1])<0.1 and abs(v[2]-candidate[2])<0.1 for v in vertices)
                    if not is_dup:
                        best_ref = ref_idx
                        break

                ref = vertices[best_ref] if best_ref < len(vertices) else running
                v_coords = [ref[0], ref[1], target_z]

            v_idx = nv
            nv += 1
            c_ops_remaining -= 1
            vertices.append(v_coords)
            running = list(v_coords)

            faces.append((L, R, v_idx))
            bnd.insert(li + 1, v_idx)
            gate = li + 1
            last_op = 'C'

        elif op_type == 'R' and n >= 4:
            fr = bnd[(gate + 2) % n]
            faces.append((L, R, fr))
            bnd.pop(ri)
            if gate >= len(bnd):
                gate = gate % len(bnd)
            last_op = 'R'

        elif op_type == 'L' and n >= 4:
            fl = bnd[(gate - 1 + n) % n]
            faces.append((fl, L, R))
            bnd.pop(li)
            gate = (li - 1) % len(bnd)
            last_op = 'L'

        elif op_type == 'E':
            if n == 3:
                faces.append(tuple(bnd))
                bnd = []
            elif n >= 4:
                fl = bnd[(gate - 1 + n) % n]
                faces.append((fl, L, R))
                bnd.pop(li)
                gate = (li - 1) % len(bnd)
            last_op = 'E'

    return vertices, faces


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

    # Find section boundaries
    is_new_format = variant_len > 8

    # Find section boundaries
    shaded_pos = raw.find(b'SHADED', ds)
    if shaded_pos < 0:
        shaded_pos = len(raw)

    if is_new_format:
        # New format: use separator_line or SHADED as face_end
        sep_line_pos = raw.find(b'separator_line', ds)
        face_end = sep_line_pos - 2 if sep_line_pos > 0 else shaded_pos

        # E0:03 terminator + first "20 00 40:xx" after it
        face_marker = -1
        first_e003 = -1
        for i in range(coord_start + 10, face_end - 1):
            if raw[i] == 0xE0 and raw[i + 1] == 0x03:
                first_e003 = i
                break
        if first_e003 > 0:
            for i in range(first_e003, face_end - 1):
                if raw[i] == 0x20 and raw[i + 1] == 0x00:
                    if i + 2 < face_end and (raw[i + 2] & 0xE0) == 0x40:
                        face_marker = i
                        break
        if face_marker < 0:
            for i in range(face_end - 2, coord_start, -1):
                if raw[i] == 0x20 and raw[i + 1] == 0x00:
                    face_marker = i
                    break
    else:
        # Old format: use attrSuffix pattern as boundary, forward search for face marker
        attr_suffix = b'\x00\x05\x40\x04\x00\x0A\x20\x08\x07'
        attr_pos = raw.find(attr_suffix, ds)
        face_end = attr_pos if attr_pos > 0 else shaded_pos

        face_marker = -1
        for i in range(coord_start + 20, face_end - 1):
            if raw[i] == 0x20 and raw[i + 1] == 0x00:
                face_marker = i
                break

    coord_end = face_marker if face_marker > 0 else face_end

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

    # ── Parse face section and build vertices simultaneously ──
    if face_marker > 0:
        face_region = raw[face_marker:face_end]
        topology_ops, vertex_refs, initial_verts = parse_face_section(
            face_region, result.n_verts_header
        )

        # Parse face elements for separator context
        face_elements = []
        fpos = 0
        while fpos < len(face_region):
            fb = face_region[fpos]
            if fb <= 0x06:
                fnb = fb + 1
                if fpos + 1 + fnb > len(face_region):
                    break
                dv = face_region[fpos + 1] if fnb == 1 else int.from_bytes(
                    face_region[fpos + 1:fpos + 1 + fnb], 'big')
                face_elements.append(('DATA', dv, fpos))
                fpos += 1 + fnb
            elif is_separator(fb):
                face_elements.append(('SEP', fb, fpos))
                fpos += 1
            elif fpos + 1 < len(face_region):
                fb2 = face_region[fpos + 1]
                hi_cls = fb & 0xE0
                cls = {0x20: '20', 0x40: '40', 0xC0: 'C0', 0xE0: 'E0'}.get(
                    hi_cls, '{:02X}'.format(fb))
                if fb == 0xE1:
                    cls = 'E1'
                lo = fb2 & 0x0F
                hi = (fb2 >> 4) & 0x0F
                face_elements.append(('TAG', cls, fb2, lo, hi, fpos))
                fpos += 2
            else:
                break

        # ── Build vertex table FIRST (primaries + C0 slots) ──
        # This must happen before face decode so the vertex queue can
        # reference vertex coordinates for dedup.
        vertices = build_vertex_table(groups, n_faces=result.n_faces_header)

        # ── Determine initial triangle ──
        if len(initial_verts) >= 3:
            init_tri = list(v - 1 for v in initial_verts[:3])  # 1-based to 0-based
        else:
            init_tri = [0, 1, 2]

        # ── Build vertex queue for C operations ──
        # (Proven model from commit 868ec49 "THE CUBE IS SOLVED")
        #
        # The face section DATA values are 1-based vertex REFERENCES.
        # They tell the face decoder which vertex to use for specific C operations.
        # Split refs into pre-topology (before first 40/C0 tag) and post-topology.
        # Post-topology refs are consumed in REVERSE order.
        # "Implicit" vertices (not in initial tri, not in refs, not coord-dupes)
        # fill remaining C-op slots.
        #
        # Queue order: implicit[0], pre-topo, implicit[1], post-topo(rev), implicits...

        # Collect vertex refs from face section, split by topology tag position
        pre_topo_verts = []
        post_topo_verts = []
        past_init = False
        seen_topo = False
        for el in face_elements:
            if not past_init:
                if el[0] == 'TAG' and el[1] == 'E0':
                    past_init = True
                continue
            if el[0] == 'TAG' and el[1] in ('40', 'C0', 'E1'):
                seen_topo = True
            if el[0] == 'DATA':
                dv = el[1]
                raw_idx = dv - 1  # 1-based to 0-based
                if dv >= 1 and raw_idx < len(vertices) and dv != 0x40 and dv != 0x82 and dv != 0xC0:
                    # Skip coordinate-duplicates of already-referenced vertices
                    v_coord = vertices[raw_idx]
                    all_used = list(init_tri) + pre_topo_verts + post_topo_verts
                    is_dup = any(
                        oi < len(vertices) and
                        abs(vertices[oi][0] - v_coord[0]) < 0.1 and
                        abs(vertices[oi][1] - v_coord[1]) < 0.1 and
                        abs(vertices[oi][2] - v_coord[2]) < 0.1
                        for oi in all_used
                    )
                    if not is_dup:
                        if not seen_topo:
                            pre_topo_verts.append(raw_idx)
                        else:
                            post_topo_verts.append(raw_idx)

        post_topo_verts.reverse()  # consumed in reverse order

        # Find implicit vertices: not in initial tri, not in refs, not coord-dupes
        used_verts = set(init_tri) | set(pre_topo_verts) | set(post_topo_verts)
        used_coords = set()
        for vi in used_verts:
            if vi < len(vertices):
                v = vertices[vi]
                used_coords.add((round(v[0], 1), round(v[1], 1), round(v[2], 1)))

        implicit_verts = []
        for vi in range(len(vertices)):
            if vi in used_verts:
                continue
            v = vertices[vi]
            key = (round(v[0], 1), round(v[1], 1), round(v[2], 1))
            if key in used_coords:
                continue  # skip coordinate duplicates
            used_coords.add(key)
            implicit_verts.append(vi)
        implicit_verts.reverse()

        # Build C-vertex order: implicit[0], pre-topo, implicit[1], post-topo(rev), implicits...
        c_vertex_order = []
        ii = 0
        if implicit_verts:
            c_vertex_order.append(implicit_verts[ii]); ii += 1
        for v in pre_topo_verts:
            c_vertex_order.append(v)
        if ii < len(implicit_verts):
            c_vertex_order.append(implicit_verts[ii]); ii += 1
        for v in post_topo_verts:
            c_vertex_order.append(v)
        while ii < len(implicit_verts):
            c_vertex_order.append(implicit_verts[ii]); ii += 1

        # ── Decode faces with vertex queue ──
        # The separator-based decoder uses the vertex queue for C operations.
        # Instead of creating new vertex indices, C operations consume from the queue.
        dec = EdgeBreakerDecoder(init_tri)
        cv_idx = [0]  # mutable counter for closure

        def next_c_vertex():
            if cv_idx[0] < len(c_vertex_order):
                v = c_vertex_order[cv_idx[0]]
                cv_idx[0] += 1
                return v
            return -1

        # Build separator context
        last_sep = None
        ops_with_sep = []
        for el in face_elements:
            if el[0] == 'SEP':
                last_sep = el[1]
            elif el[0] == 'TAG' and el[1] in ('40', 'C0', 'E1'):
                ops_with_sep.append({
                    'cls': el[1], 'byte2': el[2],
                    'lo': el[3], 'hi': el[4],
                    'sep': last_sep,
                })
                last_sep = None

        c_ops_remaining = max(result.n_verts_header - len(init_tri), 0)
        last_op = None

        for op in ops_with_sep:
            if not dec.bnd:
                break
            if op['byte2'] == 0x1B:
                dec.gate_advance(-1)
                continue

            sep = op['sep']
            n = len(dec.bnd)

            if sep is not None:
                if sep in (0x5F, 0x87):
                    if n >= 4:
                        dec.R()
                        last_op = 'R'
                else:
                    if c_ops_remaining > 0:
                        # C operation: use vertex from queue instead of new index
                        v = next_c_vertex()
                        if v >= 0:
                            li = dec.g % n
                            L, R = dec.bnd[li], dec.bnd[(dec.g + 1) % n]
                            dec.faces.append((L, R, v))
                            dec.bnd.insert(li + 1, v)
                            dec.g = li + 1
                            c_ops_remaining -= 1
                            last_op = 'C'
                    elif n >= 4:
                        dec.R()
                        last_op = 'R'
                    else:
                        dec.E()
                        last_op = 'E'
            else:
                if last_op is None or last_op == 'E':
                    if c_ops_remaining > 0:
                        v = next_c_vertex()
                        if v >= 0:
                            li = dec.g % n
                            L, R = dec.bnd[li], dec.bnd[(dec.g + 1) % n]
                            dec.faces.append((L, R, v))
                            dec.bnd.insert(li + 1, v)
                            dec.g = li + 1
                            c_ops_remaining -= 1
                            last_op = 'C'
                elif last_op == 'C':
                    if n >= 4:
                        dec.R()
                        last_op = 'R'
                    else:
                        dec.E()
                        last_op = 'E'
                elif last_op == 'R':
                    if n >= 4:
                        dec.L()
                        last_op = 'L'
                    elif n == 3:
                        dec.E()
                        last_op = 'E'
                elif last_op == 'L':
                    if n == 3:
                        dec.E()
                        last_op = 'E'
                    elif n >= 4:
                        dec.L()
                        last_op = 'L'

        result.faces = dec.faces
        result.vertices = [(v[0], v[1], v[2]) for v in vertices if v[0] is not None]

    else:
        # No face section
        vertices = build_vertex_table(groups, n_faces=result.n_faces_header)
        result.vertices = [(v[0], v[1], v[2]) for v in vertices if v[0] is not None]

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
