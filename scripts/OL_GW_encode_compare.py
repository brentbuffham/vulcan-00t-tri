"""
Compare canonical EdgeBreaker encoding of each DXF triangulation to what
Vulcan's byte stream produces.

For each test file:
  1. Load DXF triangulation as (vertices, faces).
  2. Run forward EdgeBreaker encoder over the DXF mesh, trying every face as
     seed and every winding orientation. Collect all canonical CLERS strings.
  3. Extract the CLERS that Vulcan's existing parser produces (via
     dispatch_clers from OL_GW_clers_learn).
  4. Report whether Vulcan's CLERS matches ANY of the canonical encodings.

If yes for a file → Vulcan uses canonical EdgeBreaker with some specific seed/
winding. We can use the encoder to GENERATE the right CLERS for fan/etc.

If no for a file → Vulcan uses a non-canonical encoding (different triangle
visitation order, S ops, or custom dispatch). The mismatch shows where.
"""
import sys
import argparse
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'python'))
sys.path.insert(0, str(ROOT / 'scripts'))

import edgebreaker_encoder as EB  # noqa: E402
import spirale_reversi as SR  # noqa: E402
from OL_GW_spirale_harness import capture_state  # noqa: E402
from OL_GW_clers_learn import dispatch_clers  # noqa: E402
from OL_GW_spirale_apply import extract_op_tuples  # noqa: E402
from OL_GW_slot_brute import TEST_FILES, load_dxf_faces  # noqa: E402


def dxf_to_indexed(dxf_faces, tol=1.5):
    """Convert DXF face list ([(x,y,z), ...]) to (vertices, indexed_faces)."""
    verts = []
    indexed = []
    def find_or_add(p):
        for i, v in enumerate(verts):
            if abs(v[0] - p[0]) < tol and abs(v[1] - p[1]) < tol and abs(v[2] - p[2]) < tol:
                return i
        verts.append(p)
        return len(verts) - 1
    for f in dxf_faces:
        idx = tuple(find_or_add(v) for v in f)
        if len(set(idx)) == 3:  # skip degenerate
            indexed.append(idx)
    return verts, indexed


def vulcan_clers_for_file(oot_path: str) -> str:
    state = capture_state(oot_path)
    op_tuples = extract_op_tuples(state.get('face_region', b''))
    leading = state.get('leading_40_header', False)
    nvh = state.get('n_verts_header', 0)
    initial_verts = state.get('initial_verts', [])
    clers_seq = dispatch_clers(op_tuples, len(initial_verts), nvh, leading_40_header=leading)
    return ''.join(c for c in clers_seq if c in 'CLREXS')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', help='Single label')
    ap.add_argument('--list-encodings', action='store_true',
                    help='Show all successful seed encodings (not just match)')
    args = ap.parse_args()

    files = TEST_FILES
    if args.file:
        files = [t for t in TEST_FILES if t[0] == args.file]

    print(f'{"file":12s}  {"dxf_v/f":>10s}  {"vulcan_clers":>20s}  {"canon_match?":>15s}  {"min_canon":>20s}')
    print('─' * 95)

    for label, oot, dxf_path in files:
        dxf_faces = load_dxf_faces(dxf_path)
        if not dxf_faces:
            print(f'{label:12s}  no DXF')
            continue
        verts, indexed = dxf_to_indexed(dxf_faces)
        # Strip X (finalizer) from Vulcan CLERS for canonical comparison
        vulcan_clers = vulcan_clers_for_file(str(ROOT / oot))
        vulcan_canon = vulcan_clers.replace('X', '')

        # Try every seed
        successful = []
        for si in range(len(indexed)):
            r = EB.encode(indexed, seed_face_idx=si)
            if r.get('success'):
                successful.append((si, r['clers']))

        match = any(c == vulcan_canon for _, c in successful)
        min_c = min((c for _, c in successful), key=len, default='(none)')
        marker = '✓' if match else '✗'
        print(f'{label:12s}  {len(verts):2d}v/{len(indexed):2d}f       '
              f'{vulcan_canon:>20s}  {marker} {match!s:>13s}  {min_c:>20s}')
        if args.list_encodings or args.file:
            print(f'    Vulcan CLERS: {vulcan_clers!r} (canon-stripped: {vulcan_canon!r})')
            print(f'    Canonical encodings ({len(successful)} successful seeds):')
            seen = set()
            for si, c in successful:
                if c not in seen:
                    seen.add(c)
                    marker2 = '★' if c == vulcan_canon else ' '
                    print(f'      seed={si:3d}  {marker2} CLERS={c!r}')


if __name__ == '__main__':
    main()
