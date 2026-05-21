"""
Standalone dispatcher: (sep, lo, cls, byte2) tuples → CLERS sequence.

Mirrors the per-op dispatch logic of the existing inline EdgeBreaker decoder
in oot_parser_v2.py (~lines 1820-1893) without touching dec/boundary state.
Used by the Mode C isolated branch and by analysis scripts.

Inputs:
  op_tuples:             list of (sep_byte_or_None, lo_nib, cls_str, byte2)
  initial_boundary_size: usually len(initial_verts) — typically 3
  n_verts_header:        from file header (drives c_ops_remaining budget)
  leading_40_header:     if True, drop the first op (init winding marker)

Output:
  list of opcode chars: 'C', 'L', 'R', 'E', 'X' (finalizer), 'SKIP' (leading drop)
"""
from typing import List, Sequence, Tuple, Optional


def is_separator(b: int) -> bool:
    return (b & 0x07) == 0x07 and b >= 0x07


def dispatch_clers(op_tuples: Sequence[Tuple[Optional[int], int, str, int]],
                   initial_boundary_size: int,
                   n_verts_header: int,
                   leading_40_header: bool = False,
                   shared_base_decode: bool = False) -> List[str]:
    bnd_size = initial_boundary_size
    c_ops_remaining = max(n_verts_header - initial_boundary_size, 0)
    last_op = None
    clers: List[str] = []
    ops = list(op_tuples)
    if leading_40_header and ops:
        clers.append('SKIP')
        ops = ops[1:]
    for sep, lo, cls, b2 in ops:
        if bnd_size <= 0:
            clers.append('?')
            continue
        if b2 == 0x1B:
            clers.append('X')
            continue
        n = bnd_size
        if shared_base_decode:
            if c_ops_remaining > 0:
                clers.append('C')
                c_ops_remaining -= 1
                bnd_size += 1
                last_op = 'C'
            else:
                clers.append('X')
            continue
        if sep is not None:
            if sep in (0x5F, 0x87):
                if n >= 4:
                    clers.append('R'); bnd_size -= 1; last_op = 'R'
                else:
                    clers.append('?')
            else:
                if c_ops_remaining > 0:
                    clers.append('C'); c_ops_remaining -= 1; bnd_size += 1; last_op = 'C'
                elif n >= 4:
                    clers.append('R'); bnd_size -= 1; last_op = 'R'
                else:
                    clers.append('E'); bnd_size -= 3; last_op = 'E'
        else:
            if last_op is None or last_op == 'E':
                if c_ops_remaining > 0:
                    clers.append('C'); c_ops_remaining -= 1; bnd_size += 1; last_op = 'C'
                else:
                    clers.append('E'); bnd_size -= 3; last_op = 'E'
            elif last_op == 'C':
                if n >= 4:
                    clers.append('R'); bnd_size -= 1; last_op = 'R'
                else:
                    clers.append('E'); bnd_size -= 3; last_op = 'E'
            elif last_op == 'R':
                if n >= 4:
                    clers.append('L'); bnd_size -= 1; last_op = 'L'
                elif n == 3:
                    clers.append('E'); bnd_size -= 3; last_op = 'E'
                else:
                    clers.append('?')
            elif last_op == 'L':
                if n == 3:
                    clers.append('E'); bnd_size -= 3; last_op = 'E'
                elif n >= 4:
                    clers.append('L'); bnd_size -= 1; last_op = 'L'
                else:
                    clers.append('?')
            else:
                clers.append('?')
    return clers


def extract_op_tuples_from_face_region(face_region: bytes) -> List[Tuple[Optional[int], int, str, int]]:
    """Re-parse face_region bytes into (sep, lo, cls, byte2) op tuples."""
    pos = 0
    elements = []
    while pos < len(face_region):
        b = face_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(face_region):
                break
            elements.append(('DATA',))
            pos += 1 + nb
        elif is_separator(b):
            elements.append(('SEP', b))
            pos += 1
        elif pos + 1 < len(face_region):
            b2 = face_region[pos + 1]
            hi3 = b & 0xE0
            cls_map = {0x20: '20', 0x40: '40', 0xC0: 'C0', 0xE0: 'E0'}
            cls = cls_map.get(hi3, format(b, '02x'))
            if b == 0xE1:
                cls = 'E1'
            elements.append(('TAG', cls, b2))
            pos += 2
        else:
            break

    last_sep = None
    op_tuples: List[Tuple[Optional[int], int, str, int]] = []
    for el in elements:
        if el[0] == 'SEP':
            last_sep = el[1]
        elif el[0] == 'TAG' and el[1] in ('40', 'C0', 'E1'):
            cls, b2 = el[1], el[2]
            lo = b2 & 0xF
            op_tuples.append((last_sep, lo, cls, b2))
            last_sep = None
    return op_tuples


def coord_groups_to_verts(groups, base_z=None) -> List[Tuple[float, float, float]]:
    """Pair-completion vertex extraction (works for fan; may undercount others).

    Apex from G0..G2, then for each (X, Y) pair in remaining groups emit one
    vertex with (most_recent_X, current_Y, base_Z). For Y-only groups
    (Y axis without preceding X), reuse the MAX X seen in pairs so far
    (empirical rule that places fan's V4 at (300, 467.40, 900) correctly).
    """
    if len(groups) < 3:
        return []
    if base_z is None:
        base_z = groups[2].value
    base_x = groups[0].value
    base_y = groups[1].value
    verts: List[Tuple[float, float, float]] = [(base_x, base_y, base_z)]
    most_recent_x = base_x
    pair_xs: List[float] = []
    prev_axis = -1
    i = 3
    while i < len(groups):
        g = groups[i]
        ax = g.axis
        if i + 1 < len(groups) and ax == 0 and groups[i + 1].axis == 1:
            # (X, Y) pair → emit one vertex
            most_recent_x = g.value
            pair_xs.append(g.value)
            verts.append((g.value, groups[i + 1].value, base_z))
            prev_axis = 1
            i += 2
        elif ax == 1:
            # Y-only — reuse max X from pairs (V4 in fan)
            reuse_x = max(pair_xs) if pair_xs else most_recent_x
            verts.append((reuse_x, g.value, base_z))
            prev_axis = 1
            i += 1
        else:
            if ax == 0:
                most_recent_x = g.value
            if 0 <= ax <= 2:
                prev_axis = ax
            i += 1
    return verts
