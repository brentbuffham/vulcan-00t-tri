"""
Brute-force search for what each face-referenced vertex INDEX should hold.

Given a file's face section (topology_ops, vertex_refs, initial_verts), the
EdgeBreaker decoder produces dec.faces[i] = (idx_a, idx_b, idx_c) using
indices into the vertex table.

For each "chimera" index that doesn't currently hold a DXF vertex, we try
every DXF vertex as a candidate and count how many DXF faces get matched.
This tells us what the encoder INTENDED each index to be — which is the raw
material for deriving the universal slot-semantics rule.

The script doesn't change the parser — it just observes "what assignment gives
the best topology" and prints results so we can study the pattern.

Usage:
    python3 scripts/OL_GW_index_brute.py fan
    python3 scripts/OL_GW_index_brute.py nonround
"""
import sys
import itertools
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'python'))

import oot_parser_v2 as P  # noqa: E402

# Reuse helpers from slot_brute
sys.path.insert(0, str(ROOT / 'scripts'))
from OL_GW_slot_brute import load_dxf_faces, count_face_matches, TEST_FILES, _pos_match  # noqa: E402


def get_parser_state(oot_path: str):
    """Run parser, capture dec.faces and the vertex table BEFORE dedup/renumber."""
    captured = {'dec_instances': []}
    # Patch EdgeBreakerDecoder to capture every instance's final faces.
    orig_dec = P.EdgeBreakerDecoder
    class SpyDec(orig_dec):
        def __init__(self, initial_tri):
            super().__init__(initial_tri)
            captured['dec_instances'].append(self)
    P.EdgeBreakerDecoder = SpyDec
    orig_bv = P.build_vertex_table
    def bv_spy(groups, n_faces=0):
        verts = orig_bv(groups, n_faces=n_faces)
        captured['raw_verts'] = list(verts)
        return verts
    P.build_vertex_table = bv_spy
    try:
        result = P.parse_oot_v2(oot_path)
    finally:
        P.EdgeBreakerDecoder = orig_dec
        P.build_vertex_table = orig_bv
    captured['result'] = result
    # The last EdgeBreakerDecoder instance has the final dec.faces
    if captured['dec_instances']:
        captured['dec_faces'] = list(captured['dec_instances'][-1].faces)
    else:
        captured['dec_faces'] = []
    return captured


def referenced_indices(dec_faces) -> List[int]:
    refs = set()
    for f in dec_faces:
        for i in f:
            refs.add(i)
    return sorted(refs)


def vert_pos(verts, idx):
    if 0 <= idx < len(verts):
        return verts[idx]
    return None


def is_dxf_vert(pos, dxf_unique, tol=1.5):
    return any(_pos_match(pos, d, tol) for d in dxf_unique)


def main():
    if len(sys.argv) < 2:
        print('usage: OL_GW_index_brute.py <label> (e.g. fan, nonround, hexhole)')
        sys.exit(1)
    label = sys.argv[1]
    match = [t for t in TEST_FILES if t[0] == label]
    if not match:
        print(f'unknown label: {label}')
        sys.exit(1)
    _, oot, dxf = match[0]
    oot_path = str(ROOT / oot)
    dxf_path = dxf

    dxf_faces = load_dxf_faces(dxf_path)
    if not dxf_faces:
        print(f'no DXF for {label}')
        sys.exit(1)
    dxf_unique = set()
    for f in dxf_faces:
        for v in f:
            dxf_unique.add(v)
    dxf_unique_list = sorted(dxf_unique)
    print(f'DXF unique verts ({len(dxf_unique_list)}):')
    for i, d in enumerate(dxf_unique_list):
        print(f'  D{i}: {d}')

    print()
    state = get_parser_state(oot_path)
    dec_faces = state['dec_faces']
    raw_verts = state['raw_verts']
    print(f'Raw vertex table ({len(raw_verts)} entries):')
    for i, v in enumerate(raw_verts):
        marker = ' '
        if is_dxf_vert(v, dxf_unique_list):
            marker = '✓'
        print(f'  V{i:2d}{marker}: ({v[0]:8.2f}, {v[1]:8.2f}, {v[2]:7.2f})')

    print()
    print(f'dec.faces ({len(dec_faces)} triangles, using indices into raw vert table):')
    for i, f in enumerate(dec_faces):
        positions = [raw_verts[idx] if 0 <= idx < len(raw_verts) else None for idx in f]
        marker = '✓' if all(p and is_dxf_vert(p, dxf_unique_list) for p in positions) else '✗'
        print(f'  F{i} {marker}: {f}  -> {positions}')

    refs = referenced_indices(dec_faces)
    print()
    print(f'Referenced indices: {refs}')
    chimera_refs = [i for i in refs if 0 <= i < len(raw_verts) and not is_dxf_vert(raw_verts[i], dxf_unique_list)]
    real_refs = [i for i in refs if i in [r for r in refs if 0 <= r < len(raw_verts) and is_dxf_vert(raw_verts[r], dxf_unique_list)]]
    print(f'  Real DXF positions: {real_refs}')
    print(f'  Chimera positions:  {chimera_refs}')

    if not chimera_refs:
        print('All referenced indices already hold DXF vertices — done!')
        return

    # Baseline: count DXF face matches with current assignment
    base_match = count_face_matches(dec_faces, raw_verts, dxf_faces)
    print(f'\nBaseline face match: {base_match}/{len(dxf_faces)}')

    # Brute force: try each combination of DXF vert for each chimera index
    # Cap at 7^5 = ~17000 to keep runtime sane
    n_chim = len(chimera_refs)
    if n_chim > 5:
        print(f'\nToo many chimera indices ({n_chim}) for brute force — try smaller file')
        return

    print(f'\nBrute-forcing {len(dxf_unique_list)}^{n_chim} = {len(dxf_unique_list)**n_chim} combinations...')
    best_match = base_match
    best_assignments = []
    for combo in itertools.product(range(len(dxf_unique_list)), repeat=n_chim):
        verts_copy = list(raw_verts)
        for ci, di in zip(chimera_refs, combo):
            verts_copy[ci] = list(dxf_unique_list[di])
        m = count_face_matches(dec_faces, verts_copy, dxf_faces)
        if m > best_match:
            best_match = m
            best_assignments = [(combo, m)]
        elif m == best_match and m > base_match:
            best_assignments.append((combo, m))

    print(f'\nBest face match: {best_match}/{len(dxf_faces)} (was {base_match})')
    if best_assignments:
        print(f'\nTop assignments (showing up to 5):')
        for combo, m in best_assignments[:5]:
            print(f'  Match {m}/{len(dxf_faces)}:')
            for ci, di in zip(chimera_refs, combo):
                print(f'    idx {ci} -> D{di} {dxf_unique_list[di]}')


if __name__ == '__main__':
    main()
