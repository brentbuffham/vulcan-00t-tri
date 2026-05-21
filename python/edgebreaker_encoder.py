"""
Forward EdgeBreaker encoder — canonical CLERS generator.

Given a triangle mesh (vertices + triangle face list), produces the canonical
CLERS sequence by walking the mesh from a chosen seed triangle.

Pairs with spirale_reversi.py: encode(mesh) -> CLERS -> decode(CLERS) should
round-trip back to the same topology (modulo vertex ID renumbering).

This is the OTHER half we needed for the Vulcan investigation: feed a known
DXF triangulation in, get the CLERS the encoder would have produced, compare
to what Vulcan's byte stream actually encodes. Any mismatch reveals either
(a) Vulcan uses a different triangulation than DXF for the same surface, or
(b) the seed/winding convention differs.

The implementation handles C/L/R/E. S (split) is NOT implemented — Vulcan's
corpus appears not to use splits (no S ops needed for any solved file). If S
is ever required, add a stack push/pop matching spirale_reversi's reverse-pass.

Author convention: edges are unordered pairs (frozenset); winding is preserved
in the triangle tuple. The gate is the edge between boundary[gate_idx] and
boundary[gate_idx + 1], traversed in boundary order.
"""
from typing import List, Tuple, Optional, Sequence


def encode(faces: Sequence[Tuple[int, int, int]],
           seed_face_idx: int = 0,
           verbose: bool = False) -> dict:
    """Forward EdgeBreaker encode.

    Args:
      faces:         list of (v0, v1, v2) triangle tuples (consistent winding)
      seed_face_idx: which face starts the strip (default 0)
      verbose:       if True, return per-op trace

    Returns dict with:
      clers:    CLERS string
      seed_tri: the seed triangle's vertex IDs
      trace:    per-op log (only if verbose)
      success:  True if all faces visited
    """
    if not faces:
        return {'clers': '', 'seed_tri': None, 'trace': [], 'success': True}

    # Build edge → triangle adjacency (each edge in at most 2 triangles)
    edge_to_tris: dict = {}
    for fi, f in enumerate(faces):
        for a, b in [(f[0], f[1]), (f[1], f[2]), (f[2], f[0])]:
            key = frozenset((a, b))
            edge_to_tris.setdefault(key, []).append(fi)

    visited = {seed_face_idx}
    seed = faces[seed_face_idx]
    # Boundary loop starts as the seed triangle's 3 vertices.
    # Convention: gate is the edge (boundary[g], boundary[(g+1) % n]).
    # Start gate at index 1 → edge (seed[1], seed[2]) — this matches the
    # spirale_reversi convention where C inserts vNew between gate's two ends.
    boundary = list(seed)
    gate = 1

    clers = []
    trace = []

    while len(visited) < len(faces):
        n = len(boundary)
        if n < 3:
            # Boundary degenerate — shouldn't happen for valid mesh
            break
        gA = boundary[gate % n]
        gB = boundary[(gate + 1) % n]
        edge_key = frozenset((gA, gB))
        tris = edge_to_tris.get(edge_key, [])
        candidate = None
        for fi in tris:
            if fi not in visited:
                candidate = fi
                break
        if candidate is None:
            # Gate edge has no unvisited triangle. In a single-strip mesh,
            # this means we've hit a dead-end and need to backtrack (S op).
            # For now: error out — Vulcan corpus is expected to be single-strip.
            return {
                'clers': ''.join(clers), 'seed_tri': seed, 'trace': trace,
                'success': False,
                'error': f'dead end at gate ({gA}, {gB}); {len(faces) - len(visited)} faces unvisited',
            }
        visited.add(candidate)
        f = faces[candidate]
        # Third vertex (not on the gate edge)
        v_third = next(v for v in f if v != gA and v != gB)

        right_idx = (gate + 2) % n
        left_idx = (gate - 1) % n
        right_v = boundary[right_idx]
        left_v = boundary[left_idx]

        op = None
        if v_third not in boundary:
            op = 'C'
            # Insert v_third between gA and gB in boundary.
            boundary.insert((gate % n) + 1, v_third)
            # New gate is (gA, v_third) — same gate index, but now points to
            # the newly inserted vertex.
            # gate stays where it was (still references boundary[gate], boundary[gate+1])
        elif v_third == right_v:
            op = 'R'
            # Triangle closes via right neighbor. Remove gB from boundary.
            del boundary[(gate + 1) % n]
            # Gate stays at (gA, v_third = right_v).
            if gate >= len(boundary):
                gate %= len(boundary)
        elif v_third == left_v:
            op = 'L'
            # Triangle closes via left neighbor. Remove gA from boundary.
            del boundary[gate % n]
            # New gate at (left_v, gB) — gate index shifts back by 1.
            gate = (gate - 1) % len(boundary)
        else:
            op = 'S'
            # Split — would need stack. Not implemented.
            return {
                'clers': ''.join(clers + [op]), 'seed_tri': seed, 'trace': trace,
                'success': False,
                'error': f'S op encountered at face {candidate}; not implemented',
            }

        # Detect E (end-of-strip): boundary down to 3 vertices and all faces
        # involving those 3 vertices are already visited.
        if len(boundary) == 3:
            edge_key = frozenset((boundary[0], boundary[1]))
            edge_key_b = frozenset((boundary[1], boundary[2]))
            edge_key_c = frozenset((boundary[2], boundary[0]))
            all_visited = all(
                all(fi in visited for fi in edge_to_tris.get(k, []))
                for k in (edge_key, edge_key_b, edge_key_c)
            )
            if all_visited or len(visited) == len(faces):
                # Convert the last op into 'E' (closes the strip).
                # Actually E follows the closing op; some conventions append E
                # after the last face. For Vulcan, we'll append E here.
                clers.append(op)
                if verbose:
                    trace.append({'face': candidate, 'op': op, 'v_third': v_third,
                                  'boundary_after': list(boundary)})
                clers.append('E')
                if verbose:
                    trace.append({'face': None, 'op': 'E', 'boundary_after': []})
                boundary = []
                break

        clers.append(op)
        if verbose:
            trace.append({'face': candidate, 'op': op, 'v_third': v_third,
                          'boundary_after': list(boundary)})

    return {
        'clers': ''.join(clers),
        'seed_tri': seed,
        'trace': trace,
        'success': len(visited) == len(faces),
        'visited_count': len(visited),
        'total_faces': len(faces),
    }


def encode_with_seed_choices(faces: Sequence[Tuple[int, int, int]]) -> List[dict]:
    """Try every face as seed; return all successful encodings, sorted by CLERS length."""
    results = []
    for si in range(len(faces)):
        r = encode(faces, seed_face_idx=si)
        if r.get('success'):
            results.append((si, r))
    return results
