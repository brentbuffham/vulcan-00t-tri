"""
Spirale Reversi — single-pass REVERSE EdgeBreaker decoder for CLERS streams.

Python port of js/spirale-reversi-sketch.js (Isenburg & Snoeyink, 2001).

Walk a CLERS stream backwards, rebuilding faces with ABSTRACT vertex IDs
(0, 1, 2, …) where each C creates a fresh ID. This decouples topology from
vertex identity — perfect for reverse-engineering an unknown encoder where
we already know the coord values but not which coord goes where.

Used by scripts/OL_GW_spirale_harness.py to test against Vulcan .00t files.
"""
from typing import List, Sequence, Union


VALID_OPS = ('C', 'L', 'E', 'R', 'S', 'X')  # X = skip (no face emitted, no loop change)


def normalise_stream(stream: Union[str, Sequence]) -> List[str]:
    if isinstance(stream, str):
        return list(stream)
    if isinstance(stream, (list, tuple)):
        if len(stream) == 0:
            return []
        if isinstance(stream[0], int):
            names = ['C', 'L', 'E', 'R', 'S']
            return [names[n] for n in stream]
        return list(stream)
    raise TypeError(f'Stream must be a string or list, got {type(stream)}')


def validate_counts(stream) -> dict:
    """Counting invariants. Run this FIRST on any suspected CLERS stream.
    If C+2 != expected vertex count, the stream isn't a textbook CLERS encoding."""
    s = normalise_stream(stream)
    c = {op: 0 for op in VALID_OPS}
    for i, op in enumerate(s):
        if op not in c:
            raise ValueError(f'Unknown opcode {op!r} at index {i}')
        c[op] += 1
    total = sum(c.values())
    return {
        'counts': c,
        'triangles': total,
        # Closed manifold, single strip: expected verts = C + 2.
        'expected_vertices': c['C'] + 2,
        # E - S = handles + 1 for the seed triangle. Sphere topology: 1.
        'e_minus_s': c['E'] - c['S'],
        # C should dominate (45–55% typical).
        'c_fraction': c['C'] / total if total > 0 else 0.0,
    }


def decode(stream, seed_loop=None, seed_face=True):
    """Reverse-pass CLERS decoder.

    Args:
      stream:    CLERS string or list (without the implicit seed E).
      seed_loop: pre-initialized boundary loop, list of vertex IDs. If None,
                 the loop_stack starts empty and the LAST forward op must be E.
                 For Vulcan: seed_loop = list(initial_verts) (the 3 seed IDs).
      seed_face: if True and seed_loop is given, emit the seed triangle as a face.

    Returns dict with:
      faces:        list of (v0, v1, v2) tuples — abstract vertex IDs
      vertex_count: nextV (total fresh IDs created — counts seed + C-created)
      open_loops:   number of unclosed boundary loops at end (0 for clean mesh)
      trace:        per-op log {i, op, face, ...}
    """
    s = normalise_stream(stream)

    faces = []
    next_v = 0
    loop_stack = []
    trace = []

    if seed_loop is not None:
        loop_stack.append(list(seed_loop))
        next_v = max(seed_loop) + 1 if seed_loop else 0
        if seed_face and len(seed_loop) >= 3:
            faces.append(tuple(seed_loop[:3]))
            trace.append({'i': -1, 'op': 'SEED', 'face': len(faces) - 1})

    for i in range(len(s) - 1, -1, -1):
        op = s[i]

        if op == 'E':
            # Open a fresh single-triangle loop with three new vertices.
            v0, v1, v2 = next_v, next_v + 1, next_v + 2
            next_v += 3
            faces.append((v0, v1, v2))
            loop_stack.append([v0, v1, v2])
            trace.append({'i': i, 'op': 'E', 'face': len(faces) - 1})

        elif op == 'C':
            # Glue a triangle that introduces ONE new vertex onto the gate.
            if not loop_stack:
                raise RuntimeError(f'C at index {i} but no active loop')
            loop = loop_stack[-1]
            g_a, g_b = loop[0], loop[1]
            v_new = next_v
            next_v += 1
            faces.append((g_a, g_b, v_new))
            # New gate is (gA, vNew). Insert vNew between gA and gB.
            loop.insert(1, v_new)
            trace.append({'i': i, 'op': 'C', 'face': len(faces) - 1, 'new_vertex': v_new})

        elif op == 'L':
            # Triangle uses the gate edge plus the LEFT boundary neighbour.
            if not loop_stack:
                raise RuntimeError(f'L at index {i} but no active loop')
            loop = loop_stack[-1]
            l_a, l_b = loop[0], loop[1]
            if len(loop) < 3:
                raise RuntimeError(f'L at index {i} but loop has < 3 vertices')
            left_n = loop[-1]
            faces.append((l_a, l_b, left_n))
            # Remove lA, new gate is (leftN, lB). Rotate so leftN sits at index 0.
            loop.pop(0)
            loop.insert(0, left_n)
            trace.append({'i': i, 'op': 'L', 'face': len(faces) - 1})

        elif op == 'R':
            # Mirror of L: third vertex is the RIGHT boundary neighbour (loop[2]).
            if not loop_stack:
                raise RuntimeError(f'R at index {i} but no active loop')
            loop = loop_stack[-1]
            if len(loop) < 3:
                raise RuntimeError(f'R at index {i} but loop has < 3 vertices')
            r_a, r_b = loop[0], loop[1]
            right_n = loop[2]
            faces.append((r_a, r_b, right_n))
            # Remove rB, new gate is (rA, rightN).
            del loop[1]
            trace.append({'i': i, 'op': 'R', 'face': len(faces) - 1})

        elif op == 'X':
            # Skip / no-op marker (e.g. Vulcan finalizer byte2=0x1B).
            trace.append({'i': i, 'op': 'X'})
            continue

        elif op == 'S':
            # Merge the TOP TWO loops via one bridging triangle.
            if len(loop_stack) < 2:
                raise RuntimeError(f'S at index {i} but stack has < 2 loops')
            top_loop = loop_stack.pop()
            below_loop = loop_stack.pop()
            t_a = top_loop[0]
            b_a = below_loop[0]
            faces.append((t_a, b_a, top_loop[1]))
            # Splice topLoop into belowLoop at the gate.
            merged = [b_a] + top_loop + below_loop[1:]
            loop_stack.append(merged)
            trace.append({'i': i, 'op': 'S', 'face': len(faces) - 1})

        else:
            raise ValueError(f'Unknown opcode {op!r} at index {i}')

    return {
        'faces': faces,
        'vertex_count': next_v,
        'open_loops': len(loop_stack),
        'trace': trace,
    }


# ─── Forward decoder (for sanity-check & seed-triangle alignment) ─────
# A CLERS stream from a Vulcan .00t doesn't include the SEED triangle's
# opcode — the seed is implicit (the 3 initial vertices given separately).
# The Vulcan format has the seed embedded in the face_section initial_verts.
# Reverse decoding handles this naturally because the LAST op (in reverse =
# the FIRST forward op) often establishes the seed in the boundary.

# To map fresh IDs back to actual coords, we'll use the FORWARD canonical
# order of vertex creation. In reverse decode, fresh IDs were assigned in
# reverse-traversal order. To get FORWARD order, invert the ID assignment.

def reorder_to_forward(decoded: dict) -> dict:
    """Reverse-decode produces IDs in BACKWARD creation order (last forward C
    becomes ID 0 in reverse). For coord-mapping, we need FORWARD order:
    seed vertices first, then C-introduced vertices in forward order.

    Strategy: forward-traverse the decoded faces and renumber as we go.
    The first face visited has the seed vertices (the LAST face emitted in
    reverse = first in forward order if no S ops). Re-walk forward.
    """
    faces = decoded['faces']
    # Faces were appended in reverse order. Reverse to get forward order.
    forward_faces = list(reversed(faces))
    # Renumber: first time we see an abstract ID, assign next forward ID.
    remap = {}
    new_faces = []
    for f in forward_faces:
        new = []
        for v in f:
            if v not in remap:
                remap[v] = len(remap)
            new.append(remap[v])
        new_faces.append(tuple(new))
    return {
        'faces': new_faces,
        'vertex_count': len(remap),
        'remap_backward_to_forward': remap,
    }
