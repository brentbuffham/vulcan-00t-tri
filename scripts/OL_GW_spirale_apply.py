"""
Apply the existing parser's dispatcher-extracted CLERS to Spirale Reversi.

The dispatcher in oot_parser_v2 (lines ~1820-1893) IS the universal CLERS
extractor. It uses position + sep + last_op state. For SOLVED files it
produces correct topology; for fan/etc. it produces valid-but-different
triangulation.

Spirale Reversi takes the same CLERS and produces faces with abstract
vertex IDs. We then map those IDs to coord-derived verts (apex first,
then pairs/Y-only in encoder order).

If the resulting topology uses all real DXF verts (even with different
triangle splits), that's a "topology-valid decode" — fan would render
correctly even if triangles don't match DXF triangulation.
"""
import sys
import argparse
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'python'))
sys.path.insert(0, str(ROOT / 'scripts'))

import oot_parser_v2 as P  # noqa: E402
import spirale_reversi as SR  # noqa: E402
from OL_GW_spirale_harness import (  # noqa: E402
    capture_state, derive_coord_groups, coord_groups_to_verts,
)
from OL_GW_slot_brute import TEST_FILES, load_dxf_faces, count_face_matches, count_vert_matches  # noqa: E402
from OL_GW_clers_learn import dispatch_clers  # noqa: E402


def extract_op_tuples(face_region: bytes):
    pos = 0
    elements = []
    while pos < len(face_region):
        b = face_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(face_region): break
            elements.append(('DATA',))
            pos += 1 + nb
        elif (b & 0x07) == 0x07 and b >= 0x07:
            elements.append(('SEP', b))
            pos += 1
        elif pos + 1 < len(face_region):
            b2 = face_region[pos+1]
            hi3 = b & 0xE0
            cls_map = {0x20: '20', 0x40: '40', 0xC0: 'C0', 0xE0: 'E0'}
            cls = cls_map.get(hi3, format(b, '02x'))
            if b == 0xe1: cls = 'E1'
            elements.append(('TAG', cls, b2))
            pos += 2
        else:
            break
    last_sep = None
    op_tuples = []
    for el in elements:
        if el[0] == 'SEP':
            last_sep = el[1]
        elif el[0] == 'TAG' and el[1] in ('40','C0','E1'):
            cls, b2 = el[1], el[2]
            lo = b2 & 0xF
            op_tuples.append((last_sep, lo, cls, b2))
            last_sep = None
    return op_tuples


def run_file(label, oot, dxf, verbose=False):
    state = capture_state(str(ROOT / oot))
    op_tuples = extract_op_tuples(state.get('face_region', b''))
    leading = state.get('leading_40_header', False)
    nvh = state.get('n_verts_header', 0)
    initial_verts = state.get('initial_verts', [])
    clers_seq = dispatch_clers(op_tuples, len(initial_verts), nvh, leading_40_header=leading)
    # Filter out SKIP and ? for Spirale (Spirale handles X, C, L, R, E, S)
    clers_filtered = [c for c in clers_seq if c in ('C', 'L', 'R', 'E', 'X', 'S')]
    clers_str = ''.join(clers_filtered)

    seed_loop = [0, 1, 2]
    try:
        decoded = SR.decode(clers_str, seed_loop=seed_loop, seed_face=True)
    except Exception as e:
        return {'label': label, 'clers': clers_str, 'error': str(e)}

    forward = SR.reorder_to_forward(decoded)

    # Build coord-derived vertex list
    groups = derive_coord_groups(state['coord_region'], state['new_format'])
    verts_in_order = coord_groups_to_verts(groups)
    while len(verts_in_order) < forward['vertex_count']:
        verts_in_order.append(verts_in_order[0] if verts_in_order else (0, 0, 0))

    dxf_faces = load_dxf_faces(dxf)
    fm = count_face_matches(forward['faces'], verts_in_order, dxf_faces) if dxf_faces else None
    vm, vt = count_vert_matches(verts_in_order, dxf_faces) if dxf_faces else (None, None)

    # Existing parser baseline
    base_r = P.parse_oot_v2(str(ROOT / oot))
    base_fm = count_face_matches(base_r.faces, base_r.vertices, dxf_faces) if dxf_faces else 0

    if verbose:
        print(f'\n=== {label} ===')
        print(f'  CLERS (dispatcher): {clers_seq}')
        print(f'  Filtered for Spirale: {clers_str!r}')
        print(f'  Coord-derived verts ({len(verts_in_order)}):')
        for i, v in enumerate(verts_in_order):
            print(f'    V{i}: ({v[0]:.2f}, {v[1]:.2f}, {v[2]:.2f})')
        print(f'  Forward-renumbered faces ({len(forward["faces"])}):')
        for i, f in enumerate(forward['faces']):
            positions = [verts_in_order[idx] for idx in f]
            print(f'    F{i}: {f} -> {[tuple(round(c, 2) for c in p) for p in positions]}')

    return {
        'label': label,
        'clers': clers_str,
        'face_match': fm or 0,
        'face_total': len(dxf_faces) if dxf_faces else 0,
        'vert_match': vm or 0,
        'vert_total': vt or 0,
        'baseline_face_match': base_fm or 0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', help='Single label to test (e.g. fan)')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    files = TEST_FILES
    if args.file:
        files = [t for t in TEST_FILES if t[0] == args.file]

    print(f'{"file":12s}  {"baseline":>10s}  {"spirale":>10s}  {"verts":>8s}  clers')
    print('─' * 80)
    for label, oot, dxf in files:
        r = run_file(label, oot, dxf, verbose=args.verbose)
        if 'error' in r:
            print(f'{label:12s}  ERROR: {r["error"]}  clers={r["clers"]!r}')
            continue
        marker = '↑' if r['face_match'] > r['baseline_face_match'] else (
            '↓' if r['face_match'] < r['baseline_face_match'] else ' ')
        print(f'{marker}{label:12s}  {r["baseline_face_match"]}/{r["face_total"]:<8d}  {r["face_match"]}/{r["face_total"]:<8d}  {r["vert_match"]}/{r["vert_total"]:<6d}  {r["clers"][:40]}')


if __name__ == '__main__':
    main()
