"""
Forward EdgeBreaker decoder.

Takes a CLERS string + seed triangle, replays the forward algorithm to
produce faces with abstract vertex IDs. Simpler and bug-free compared to
Spirale Reversi's L/R loop surgery.

Vertex IDs:
  - Seed loop uses IDs given (e.g., [0, 1, 2])
  - C op creates next fresh ID (max(seed)+1, then +1 per C)
  - L/R reuse existing IDs from boundary

Boundary representation: a list where the gate is the edge between
boundary[gate_idx] and boundary[(gate_idx + 1) % n]. C inserts vNew
between them; R removes loop[gate+1]; L removes loop[gate].
"""
from typing import List, Tuple, Sequence


def decode_forward(clers: str, seed_loop: Sequence[int]) -> dict:
    """Forward EdgeBreaker decode.

    Args:
      clers:     CLERS string (only C, L, R, E supported; X = skip, S not impl)
      seed_loop: initial boundary loop of 3 vertex IDs (seed triangle)

    Returns dict with:
      faces:        list of (v0, v1, v2) — first is seed triangle
      vertex_count: total vertex IDs used (seed + C-created)
      open_loops:   1 if boundary still nonempty at end, 0 if cleanly ended
    """
    if len(seed_loop) < 3:
        raise ValueError(f'seed_loop must have 3 verts, got {len(seed_loop)}')
    boundary = list(seed_loop)
    gate = 1  # Gate at edge (boundary[1], boundary[2]) by default — matches
              # the encoder convention.
    next_v = max(seed_loop) + 1
    faces = [tuple(seed_loop[:3])]

    for i, op in enumerate(clers):
        if op == 'X':
            continue
        n = len(boundary)
        if n < 3:
            return {'faces': faces, 'vertex_count': next_v,
                    'open_loops': 1, 'error': f'boundary < 3 at op {i} ({op})'}
        gA = boundary[gate % n]
        gB = boundary[(gate + 1) % n]
        if op == 'C':
            v = next_v
            next_v += 1
            faces.append((gA, gB, v))
            boundary.insert((gate % n) + 1, v)
            # gate stays at same index (now points to gA -> v)
        elif op == 'R':
            right_n = boundary[(gate + 2) % n]
            faces.append((gA, gB, right_n))
            del boundary[(gate + 1) % n]
            if gate >= len(boundary):
                gate %= len(boundary)
        elif op == 'L':
            left_n = boundary[(gate - 1) % n]
            faces.append((gA, gB, left_n))
            del boundary[gate % n]
            gate = (gate - 1) % len(boundary) if boundary else 0
        elif op == 'E':
            # End of strip — boundary should reduce to 0 (closing triangle)
            # In closed-manifold canonical EB, E removes all 3 remaining verts.
            # For open meshes, E just marks end; boundary may have unhandled verts.
            faces.append((gA, gB, boundary[(gate + 2) % n] if n >= 3 else 0))
            boundary = []
            break
        elif op == 'S':
            raise NotImplementedError('S op not yet supported')
        else:
            raise ValueError(f'Unknown op {op!r} at index {i}')

    return {'faces': faces, 'vertex_count': next_v,
            'open_loops': 1 if boundary else 0}
