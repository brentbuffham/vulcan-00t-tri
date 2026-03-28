#!/usr/bin/env python3
"""
EdgeBreaker hypothesis decoder for Vulcan .00t face sections.

Extracts the face section from each test file, parses the tag stream,
tries all permutations of operation mappings, and compares against
DXF ground truth.

Author: Brent Buffham + Claude (reverse-engineering collaboration)
"""

import struct
import itertools
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Set

# ── Helpers ──────────────────────────────────────────────────────────

def is_separator(b: int) -> bool:
    return (b & 0x07) == 0x07 and b >= 0x07


def read_be_double(buf: bytes) -> float:
    return struct.unpack('>d', bytes((buf + b'\x00' * 8)[:8]))[0]


# ── Face Section Parser ─────────────────────────────────────────────

@dataclass
class FaceElement:
    """A single parsed element from the face section byte stream."""
    offset: int
    etype: str          # 'tag', 'data', 'sep', 'marker'
    raw: bytes
    # For tags:
    tag_class: str = '' # '20','40','C0','E0','E1','other'
    tag_byte2: int = 0
    low_nibble: int = 0
    high_nibble: int = 0
    # For data:
    data_value: int = 0


@dataclass
class FaceSection:
    """Parsed face section with structured elements."""
    raw: bytes
    elements: List[FaceElement] = field(default_factory=list)
    initial_vertices: List[int] = field(default_factory=list)  # 1-based
    topology_ops: List[FaceElement] = field(default_factory=list)
    new_vertex_indices: List[int] = field(default_factory=list)  # 1-based
    groups: List[dict] = field(default_factory=list)


def parse_face_section(raw: bytes, n_verts: int) -> FaceSection:
    """Parse the face section byte stream into structured elements."""
    fs = FaceSection(raw=raw)
    pos = 0

    while pos < len(raw):
        b = raw[pos]

        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(raw):
                break
            data_bytes = raw[pos + 1:pos + 1 + nb]
            el = FaceElement(
                offset=pos, etype='data', raw=raw[pos:pos + 1 + nb],
                data_value=data_bytes[0] if nb == 1 else int.from_bytes(data_bytes, 'big')
            )
            fs.elements.append(el)
            pos += 1 + nb

        elif is_separator(b):
            el = FaceElement(offset=pos, etype='sep', raw=raw[pos:pos + 1])
            fs.elements.append(el)
            pos += 1

        elif pos + 1 < len(raw):
            b2 = raw[pos + 1]
            hi = b & 0xE0

            if b == 0xE1:
                tag_class = 'E1'
            elif hi == 0x20:
                tag_class = '20'
            elif hi == 0x40:
                tag_class = '40'
            elif hi == 0xC0:
                tag_class = 'C0'
            elif hi == 0xE0:
                tag_class = 'E0'
            else:
                tag_class = f'{b:02X}'

            el = FaceElement(
                offset=pos, etype='tag', raw=raw[pos:pos + 2],
                tag_class=tag_class, tag_byte2=b2,
                low_nibble=b2 & 0x0F, high_nibble=(b2 >> 4) & 0x0F
            )
            fs.elements.append(el)
            pos += 2
        else:
            break

    # ── Identify structure ──
    # Two patterns observed:
    #   A) Linear strip style: 20 00, [00 VV 20 03]*, E0 03, topology...
    #      The initial triangle vertices are explicitly listed
    #   B) Fan/Plane/Cube style: 20 00, 40 XX, [topology ops], E0 03, ...
    #      The initial triangle is implicit (first 3 from coord stream)
    #      The 40 XX right after 20 00 is already a topology op

    # Detect which pattern: look at what follows 20 00
    first_after_start = None
    for el in fs.elements:
        if el.etype == 'tag' and el.tag_class == '20' and el.tag_byte2 == 0x00:
            continue  # skip the 20 00 start marker
        first_after_start = el
        break

    explicit_initial = (first_after_start and first_after_start.etype == 'data')

    phase = 'pre'
    first_e0_03_seen = False
    for el in fs.elements:
        if phase == 'pre':
            if el.etype == 'tag' and el.tag_class == '20' and el.tag_byte2 == 0x00:
                phase = 'initial' if explicit_initial else 'topology'
        elif phase == 'initial':
            if el.etype == 'data' and 1 <= el.data_value <= 255:
                fs.initial_vertices.append(el.data_value)
            elif el.etype == 'tag' and el.tag_class == 'E0':
                phase = 'topology'
                first_e0_03_seen = True
            elif el.etype == 'tag' and el.tag_class in ('40', 'C0'):
                # Unexpected tag in initial section — could be part of initial encoding
                pass  # skip structural tags like 20 03, 20 07 between vertices
        elif phase == 'topology':
            if el.etype == 'tag' and el.tag_class in ('40', 'C0'):
                fs.topology_ops.append(el)
            elif el.etype == 'data':
                dv = el.data_value
                # Distinguish vertex indices from flags (0x40, 0x82, etc.)
                # Real vertex indices should be small (1..n_verts if header is accurate,
                # but header can be wrong, so use a reasonable upper bound)
                max_v = max(n_verts, 20)
                if 1 <= dv <= max_v and dv != 0x40 and dv != 0x82:
                    fs.new_vertex_indices.append(dv)

    # ── Group topology ops by E0 delimiters ──
    current_group = {'vertex': None, 'ops': [], 'end_tag': None}
    phase = 'pre'
    for el in fs.elements:
        if phase == 'pre':
            if el.etype == 'tag' and el.tag_class == 'E0' and el.tag_byte2 == 0x03:
                phase = 'groups'
                continue
        elif phase == 'groups':
            if el.etype == 'data' and 1 <= el.data_value <= n_verts:
                if current_group['ops']:
                    fs.groups.append(current_group)
                    current_group = {'vertex': None, 'ops': [], 'end_tag': None}
                current_group['vertex'] = el.data_value
            elif el.etype == 'tag' and el.tag_class in ('40', 'C0'):
                current_group['ops'].append(el)
            elif el.etype == 'tag' and el.tag_class in ('E0', 'E1'):
                current_group['end_tag'] = el
                if el.tag_byte2 == 0x00:  # E0 00 = section end
                    fs.groups.append(current_group)
                    break
                elif el.tag_byte2 in (0x03, 0x04):
                    fs.groups.append(current_group)
                    current_group = {'vertex': None, 'ops': [], 'end_tag': None}

    return fs


# ── .00t File Reader ─────────────────────────────────────────────────

def extract_face_section(filepath: str) -> Tuple[bytes, int, int]:
    """Extract the face section bytes, vertex count, and face count from a .00t file."""
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
        if raw[i] == 0x20 and raw[i + 1] == 0x00:
            face_marker = i
            break

    face_bytes = raw[face_marker:attr_pos] if face_marker > 0 else b''
    return face_bytes, n_verts, n_faces


# ── DXF Ground Truth ─────────────────────────────────────────────────

def load_dxf_faces(filepath: str) -> Tuple[List[Tuple], List[Tuple]]:
    """Load vertices and faces from a DXF file. Returns (vertices, faces) with 0-based indices."""
    import ezdxf
    doc = ezdxf.readfile(filepath)
    msp = doc.modelspace()
    vm = {}
    vl = []
    fl = []
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


# ── EdgeBreaker Decoder ─────────────────────────────────────────────

class EdgeBreakerDecoder:
    """
    EdgeBreaker mesh decompressor.

    Maintains a boundary loop and applies CLERS operations to reconstruct
    the triangle mesh from a traversal sequence.

    Boundary convention:
    - The boundary is a list of vertex indices forming a loop
    - The 'gate' is an edge on the boundary, defined by position in the loop
    - gate_pos points to the LEFT vertex of the gate edge
    - gate_pos+1 (mod len) points to the RIGHT vertex
    - The triangle being processed is OUTSIDE the boundary (not yet added)
    """

    def __init__(self, initial_tri: Tuple[int, int, int], n_verts: int):
        v0, v1, v2 = initial_tri
        self.faces = [(v0, v1, v2)]
        self.n_verts = n_verts
        self.next_vertex = max(initial_tri) + 1

        # Boundary: ordered loop. Gate edge is between boundary[gate_pos] and boundary[gate_pos+1]
        # After the initial triangle, boundary = [v0, v1, v2] with gate at edge (v1, v2)
        # Convention: gate is the most recently created edge
        self.boundary = [v0, v1, v2]
        self.gate_pos = 1  # gate edge = boundary[1]->boundary[2] = v1->v2

        self.stack = []  # for S (split) operations
        self.errors = []

    def _boundary_ok(self, min_size=3):
        if len(self.boundary) < min_size:
            return False
        if self.gate_pos >= len(self.boundary):
            return False
        return True

    def _left(self):
        """Vertex to the left of the gate (previous in boundary)."""
        return self.boundary[self.gate_pos % len(self.boundary)]

    def _right(self):
        """Vertex to the right of the gate (next in boundary)."""
        return self.boundary[(self.gate_pos + 1) % len(self.boundary)]

    def _far_left(self):
        """Vertex one further left from the gate."""
        return self.boundary[(self.gate_pos - 1) % len(self.boundary)]

    def _far_right(self):
        """Vertex one further right from the gate."""
        return self.boundary[(self.gate_pos + 2) % len(self.boundary)]

    def op_C(self, new_vertex: Optional[int] = None):
        """
        C (Create): New vertex. Triangle = (left, right, new_vertex).
        The new vertex is inserted into the boundary between left and right.
        Gate advances to (new_vertex, right).
        """
        if not self._boundary_ok(3):
            self.errors.append(f"C op with bad boundary (size={len(self.boundary)}, gate={self.gate_pos})")
            return

        left = self._left()
        right = self._right()

        if new_vertex is None:
            new_vertex = self.next_vertex
            self.next_vertex += 1

        self.faces.append((left, right, new_vertex))

        # Insert new vertex into boundary after gate_pos
        insert_pos = (self.gate_pos + 1) % len(self.boundary)
        self.boundary.insert(insert_pos, new_vertex)

        # Gate advances to (new_vertex, right)
        self.gate_pos = insert_pos

    def op_L(self):
        """
        L (Left): Connect to far-left vertex. Triangle = (far_left, left, right).
        Remove left from boundary. Gate stays at (far_left, right).
        """
        if not self._boundary_ok(4):
            self.errors.append(f"L op with boundary size {len(self.boundary)}")
            return

        left = self._left()
        right = self._right()
        far_left = self._far_left()

        self.faces.append((far_left, left, right))

        # Remove left vertex from boundary
        self.boundary.pop(self.gate_pos)
        # Gate is now at (far_left, right)
        self.gate_pos = (self.gate_pos - 1) % len(self.boundary)

    def op_R(self):
        """
        R (Right): Connect to far-right vertex. Triangle = (left, right, far_right).
        Remove right from boundary. Gate stays at (left, far_right).
        """
        if not self._boundary_ok(4):
            self.errors.append(f"R op with boundary size {len(self.boundary)}")
            return

        left = self._left()
        right = self._right()
        far_right = self._far_right()

        self.faces.append((left, right, far_right))

        # Remove right vertex from boundary
        right_pos = (self.gate_pos + 1) % len(self.boundary)
        self.boundary.pop(right_pos)
        # Adjust gate_pos if needed
        if self.gate_pos >= len(self.boundary):
            self.gate_pos = self.gate_pos % len(self.boundary)

    def op_E(self):
        """
        E (End): Close the last triangle. Triangle = the remaining 3 boundary vertices,
        or connect far_left-left-right if boundary > 3.
        """
        if len(self.boundary) == 3:
            self.faces.append(tuple(self.boundary))
            self.boundary = []
        elif len(self.boundary) > 3:
            if not self._boundary_ok(3):
                self.errors.append(f"E op bad gate")
                return
            left = self._left()
            right = self._right()
            far_left = self._far_left()
            self.faces.append((far_left, left, right))
            self.boundary.pop(self.gate_pos)
            self.gate_pos = (self.gate_pos - 1) % len(self.boundary)
        else:
            self.errors.append(f"E op with boundary size {len(self.boundary)}")

    def op_S(self, offset: int = 0):
        """
        S (Split): Connect to a non-adjacent boundary vertex, splitting the boundary
        into two loops. Push one loop onto the stack.
        """
        if len(self.boundary) < 5:
            self.errors.append(f"S op with boundary size {len(self.boundary)}")
            return

        left = self._left()
        right = self._right()

        # The offset tells us which boundary vertex to connect to
        # Convention: offset=0 means far_left (same as L), offset=1 means one further, etc.
        target_pos = (self.gate_pos - 2 - offset) % len(self.boundary)
        target = self.boundary[target_pos]

        self.faces.append((target, left, right))

        # Split boundary into two loops
        # Loop 1: from target to right (through gate)
        # Loop 2: from right to target (the other way)
        # We keep loop 1 active and push loop 2

        # Build the two loops
        n = len(self.boundary)
        # Loop 1: target_pos -> ... -> gate_pos (inclusive of left) -> gate_pos+1 (right)
        # But we remove left from loop 1 as it's consumed
        loop1 = []
        loop2 = []

        # Extract positions
        right_pos = (self.gate_pos + 1) % n

        # Loop 1: right -> ... -> target
        i = right_pos
        while i != target_pos:
            loop1.append(self.boundary[i])
            i = (i + 1) % n
        loop1.append(self.boundary[target_pos])

        # Loop 2: target -> ... -> left -> right (but without left since triangle consumed it)
        # Actually this needs more thought — skip for now
        self.errors.append("S op not fully implemented")

    def get_face_sets(self) -> Set[frozenset]:
        """Return faces as a set of frozensets for order-independent comparison."""
        return {frozenset(f) for f in self.faces}

    def state_str(self) -> str:
        return f"boundary={self.boundary}, gate={self.gate_pos}, faces={len(self.faces)}"


# ── Brute-force Operation Mapping ────────────────────────────────────

def try_mapping_with_gate(initial_tri, gate_init, ops_sequence, mapping, n_verts, new_vertices):
    """Like try_mapping but with configurable initial gate position."""
    dec = EdgeBreakerDecoder(initial_tri, n_verts)
    dec.gate_pos = gate_init  # override default gate
    new_vert_iter = iter(new_vertices)

    for tag_class, low_nib, high_nib in ops_sequence:
        if dec.errors:
            break

        if tag_class == 'C0':
            dec.op_S(high_nib)
            continue

        op = mapping.get(low_nib)
        if op is None:
            dec.errors.append(f"Unknown low nibble 0x{low_nib:X}")
            break

        try:
            if op == 'C':
                try:
                    v = next(new_vert_iter) - 1
                except StopIteration:
                    v = None
                dec.op_C(v)
            elif op == 'L':
                dec.op_L()
            elif op == 'R':
                dec.op_R()
            elif op == 'E':
                dec.op_E()
        except (IndexError, ValueError) as e:
            dec.errors.append(f"Exception in {op}: {e}")
            break

    return len(dec.errors) == 0, dec.faces, dec.errors


def try_mapping(initial_tri, ops_sequence, mapping, n_verts, new_vertices):
    """
    Try a specific mapping of low-nibble values to EdgeBreaker operations.

    mapping: dict {low_nibble_value: 'C'|'L'|'R'|'E'}
    ops_sequence: list of (tag_class, low_nibble, high_nibble) tuples
    new_vertices: list of explicitly provided vertex indices (1-based)

    Returns: (success, faces, errors)
    """
    dec = EdgeBreakerDecoder(initial_tri, n_verts)
    new_vert_iter = iter(new_vertices)

    for tag_class, low_nib, high_nib in ops_sequence:
        if dec.errors:
            break

        if tag_class == 'C0':
            # C0 = Split operation hypothesis
            dec.op_S(high_nib)
            continue

        op = mapping.get(low_nib)
        if op is None:
            dec.errors.append(f"Unknown low nibble 0x{low_nib:X}")
            break

        try:
            if op == 'C':
                # Try to get explicit vertex, otherwise auto-assign
                try:
                    v = next(new_vert_iter) - 1  # convert to 0-based
                except StopIteration:
                    v = None
                dec.op_C(v)
            elif op == 'L':
                dec.op_L()
            elif op == 'R':
                dec.op_R()
            elif op == 'E':
                dec.op_E()
        except (IndexError, ValueError) as e:
            dec.errors.append(f"Exception in {op}: {e}")
            break

    return len(dec.errors) == 0, dec.faces, dec.errors


def faces_match(decoded_faces, truth_faces) -> bool:
    """Compare decoded faces against ground truth (order-independent, winding-independent)."""
    decoded_sets = {frozenset(f) for f in decoded_faces}
    truth_sets = {frozenset(f) for f in truth_faces}
    return decoded_sets == truth_sets


def faces_overlap(decoded_faces, truth_faces) -> Tuple[int, int, int]:
    """Return (matching, decoded_total, truth_total)."""
    decoded_sets = {frozenset(f) for f in decoded_faces}
    truth_sets = {frozenset(f) for f in truth_faces}
    matching = len(decoded_sets & truth_sets)
    return matching, len(decoded_sets), len(truth_sets)


# ── Main Analysis ────────────────────────────────────────────────────

def analyze_file(name: str, oot_path: str, dxf_path: str):
    """Full analysis of one test file."""
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"{'='*70}")

    # Load ground truth
    truth_verts, truth_faces = load_dxf_faces(dxf_path)
    print(f"\nDXF ground truth: {len(truth_verts)} verts, {len(truth_faces)} faces")
    for i, f in enumerate(truth_faces):
        print(f"  F{i}: {f}")

    # Extract and parse face section
    face_bytes, n_verts, n_faces = extract_face_section(oot_path)
    print(f"\n00t header: {n_verts} verts, {n_faces} faces")
    print(f"Face section: {len(face_bytes)} bytes")
    print(f"Raw hex: {' '.join(f'{b:02X}' for b in face_bytes)}")

    fs = parse_face_section(face_bytes, n_verts)

    # Determine initial triangle
    if len(fs.initial_vertices) >= 3:
        initial_0based = tuple(v - 1 for v in fs.initial_vertices[:3])
        print(f"\nInitial triangle vertices (1-based, explicit): {fs.initial_vertices}")
    else:
        # Implicit: use first 3 vertices (0, 1, 2)
        initial_0based = (0, 1, 2)
        print(f"\nInitial triangle: IMPLICIT (0, 1, 2) — face section starts with topology ops")
        if fs.initial_vertices:
            print(f"  (partial vertex list found: {fs.initial_vertices})")

    print(f"Initial triangle (0-based): {initial_0based}")

    print(f"\nNew vertex indices in face section (1-based): {fs.new_vertex_indices}")

    print(f"\nTopology ops ({len(fs.topology_ops)}):")
    for op in fs.topology_ops:
        print(f"  {op.tag_class} {op.tag_byte2:02X}  "
              f"(low_nib=0x{op.low_nibble:X}, high_nib=0x{op.high_nibble:X})")

    print(f"\nGroups ({len(fs.groups)}):")
    for i, g in enumerate(fs.groups):
        ops_str = ', '.join(f"{o.tag_class}:{o.tag_byte2:02X}" for o in g['ops'])
        end_str = f"{g['end_tag'].tag_class}:{g['end_tag'].tag_byte2:02X}" if g['end_tag'] else 'none'
        print(f"  G{i}: vertex={g['vertex']}, ops=[{ops_str}], end={end_str}")

    # Build ops sequence for decoder
    ops_sequence = []
    for op in fs.topology_ops:
        ops_sequence.append((op.tag_class, op.low_nibble, op.high_nibble))

    # Identify unique low nibbles in 40-class tags
    low_nibs_40 = sorted(set(op.low_nibble for op in fs.topology_ops if op.tag_class == '40'))
    print(f"\nUnique low nibbles in 40-class ops: {['0x%X' % n for n in low_nibs_40]}")

    # Skip files with too few faces for meaningful analysis
    if len(truth_faces) <= 1:
        print("\n  (Only 1 face — no topology ops to decode)")
        return None

    # ── Try all permutations of CLRE mappings ──
    # Also try different initial triangle orderings and gate positions
    operations = ['C', 'L', 'R', 'E']
    best_results = []

    print(f"\n--- Trying all operation mappings ---")
    print(f"Mapping {len(low_nibs_40)} low nibbles to {len(operations)} operations")
    print(f"Also trying 6 initial triangle permutations × 3 gate positions")

    # Try all permutations of the initial triangle and all gate positions
    tri_perms = list(itertools.permutations(initial_0based))
    gate_positions = [0, 1, 2]

    for tri_perm in tri_perms:
        for gate_init in gate_positions:
            for assignment in itertools.product(operations, repeat=len(low_nibs_40)):
                mapping = dict(zip(low_nibs_40, assignment))

                success, decoded_faces, errors = try_mapping_with_gate(
                    tri_perm, gate_init, ops_sequence, mapping, n_verts,
                    list(fs.new_vertex_indices)
                )

                match_count, dec_total, truth_total = faces_overlap(decoded_faces, truth_faces)

                if match_count > 1:  # At least initial face + 1 correct
                    best_results.append({
                        'mapping': mapping.copy(),
                        'initial_tri': tri_perm,
                        'gate_init': gate_init,
                        'match_count': match_count,
                        'dec_total': dec_total,
                        'truth_total': truth_total,
                        'faces': decoded_faces[:],
                        'errors': errors[:],
                        'perfect': faces_match(decoded_faces, truth_faces),
                    })

    # Sort by match count descending
    best_results.sort(key=lambda r: (r['perfect'], r['match_count'], -len(r['errors'])), reverse=True)

    if best_results:
        print(f"\nTop results ({len(best_results)} mappings matched >1 face):\n")
        for r in best_results[:15]:
            flag = " *** PERFECT MATCH ***" if r['perfect'] else ""
            mapping_str = ', '.join(f"0x{k:X}={v}" for k, v in sorted(r['mapping'].items()))
            tri_str = f"tri={r.get('initial_tri', initial_0based)}"
            gate_str = f"gate={r.get('gate_init', '?')}"
            print(f"  [{r['match_count']}/{r['truth_total']} faces] {{{mapping_str}}}"
                  f"  {tri_str} {gate_str}"
                  f"  decoded={r['dec_total']} faces"
                  f"  errors={len(r['errors'])}{flag}")
            if r['perfect'] or r['match_count'] >= r['truth_total'] - 1:
                print(f"    Decoded faces: {r['faces']}")
                if r['errors']:
                    print(f"    Errors: {r['errors'][:3]}")
    else:
        print("\n  No mapping matched more than 1 face.")
        print("  This may mean:")
        print("  - The initial triangle identification is wrong")
        print("  - The topology ops are grouped differently than assumed")
        print("  - The encoding is not standard EdgeBreaker CLERS")

    # ── Also try: ops as triplets (3 tags = 1 face) ──
    print(f"\n--- Alternative: trying ops as triplets (3 tags per face) ---")
    if len(fs.topology_ops) >= 3:
        triplets = []
        for i in range(0, len(fs.topology_ops) - 2, 3):
            triplets.append(fs.topology_ops[i:i + 3])

        print(f"  {len(triplets)} triplets from {len(fs.topology_ops)} ops")
        for i, trip in enumerate(triplets):
            ops_str = ', '.join(f"{o.tag_class}:{o.tag_byte2:02X}(nib={o.low_nibble:X})" for o in trip)
            print(f"  Triplet {i}: [{ops_str}]")

    return best_results


# ── Also try with different gate/boundary conventions ────────────────

def try_alternative_conventions(name, initial_tri, ops_sequence, n_verts, new_vertices, truth_faces):
    """Try EdgeBreaker with different initial gate positions and winding orders."""
    operations = ['C', 'L', 'R', 'E']

    # Get unique low nibbles
    low_nibs = sorted(set(ln for _, ln, _ in ops_sequence if True))

    results = []

    # Try different initial triangle vertex orderings
    perms = list(itertools.permutations(initial_tri))

    for tri_perm in perms:
        for assignment in itertools.product(operations, repeat=len(low_nibs)):
            mapping = dict(zip(low_nibs, assignment))
            success, decoded_faces, errors = try_mapping(
                tri_perm, ops_sequence, mapping, n_verts, list(new_vertices)
            )

            if faces_match(decoded_faces, truth_faces):
                results.append({
                    'initial_tri': tri_perm,
                    'mapping': mapping.copy(),
                    'faces': decoded_faces,
                })

    return results


def main():
    base = Path(__file__).parent.parent / 'exampleFiles'

    test_files = [
        ('Triangle (1 face)', 'tri-crack-triangle', 3, 1),
        ('Plane (2 faces)', 'tri-crack', 4, 2),
        ('Fan (6 faces)', 'tri-crack-fan', 6, 6),
        ('Linear Strip (5 faces)', 'tri-crack-linear', 7, 5),
        ('Cube (12 faces)', 'tri-crack-solid', 8, 12),
    ]

    all_results = {}

    for name, stem, expected_v, expected_f in test_files:
        oot_path = str(base / f'{stem}.00t')
        dxf_path = str(base / f'{stem}.dxf')

        if not Path(oot_path).exists() or not Path(dxf_path).exists():
            print(f"\n  SKIP: {name} — files not found")
            continue

        results = analyze_file(name, oot_path, dxf_path)
        all_results[name] = results

    # ── Cross-file analysis ──
    print(f"\n{'='*70}")
    print(f"  CROSS-FILE ANALYSIS")
    print(f"{'='*70}")

    # Find mappings that work across multiple files
    print("\nLooking for consistent mappings across files...")

    # Collect all perfect-match mappings per file
    perfect_per_file = {}
    for name, results in all_results.items():
        if results:
            perfects = [r for r in results if r['perfect']]
            if perfects:
                perfect_per_file[name] = perfects
                print(f"\n  {name}: {len(perfects)} perfect mappings")
                # Show first few
                for r in perfects[:5]:
                    mapping_str = ', '.join(f"0x{k:X}={v}" for k, v in sorted(r['mapping'].items()))
                    print(f"    {{{mapping_str}}}")

    # Find intersection of mapping patterns
    if len(perfect_per_file) >= 2:
        print("\n  Checking for consistent low-nibble→operation mapping across files...")
        # Extract all (low_nib, op) pairs from each file's perfect mappings
        for name, perfects in perfect_per_file.items():
            print(f"\n  {name} — all perfect mappings use these assignments:")
            all_assignments = set()
            for r in perfects:
                for nib, op in r['mapping'].items():
                    all_assignments.add((nib, op))
            for nib, op in sorted(all_assignments):
                count = sum(1 for r in perfects if r['mapping'].get(nib) == op)
                print(f"    0x{nib:X} → {op}  ({count}/{len(perfects)} mappings)")

    print("\n" + "=" * 70)
    print("  DONE")
    print("=" * 70)


if __name__ == '__main__':
    main()
