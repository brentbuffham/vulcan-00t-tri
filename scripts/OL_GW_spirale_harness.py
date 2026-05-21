"""
Spirale Reversi harness for Vulcan .00t files.

For each test file, this harness:
  1. Parses topology_ops from the face section.
  2. Maps the Vulcan 40:xx tag bytes to CLERS opcodes.
  3. Runs Spirale Reversi reverse-pass decoder.
  4. Validates counting invariants (C+2 == expected vertex count).
  5. Tries to map abstract vertex IDs to actual coord-derived vertices.
  6. Scores face-match against DXF.

The mapping from Vulcan tag bytes → CLERS is the unknown we need to discover.
We try several hypotheses and report which (if any) work.

Usage:
    python3 scripts/OL_GW_spirale_harness.py                # all files, default mapping
    python3 scripts/OL_GW_spirale_harness.py --file fan     # single file
    python3 scripts/OL_GW_spirale_harness.py --mapping lo_nib_simple
"""
import sys
import argparse
import itertools
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'python'))
sys.path.insert(0, str(ROOT / 'scripts'))

import oot_parser_v2 as P  # noqa: E402
import spirale_reversi as SR  # noqa: E402
from OL_GW_slot_brute import (  # noqa: E402
    TEST_FILES,
    load_dxf_faces,
    count_face_matches,
    count_vert_matches,
    _pos_match,
)


# ─── Capture parser state for each file ──────────────────────────────
def capture_state(oot_path: str):
    """Run parser, capture topology_ops, vertex_refs, initial_verts, and coord groups."""
    captured = {}

    orig_pfs = P.parse_face_section
    def pfs_spy(face_region, n_verts_header):
        topology_ops, vertex_refs, initial_verts, leading_40_header = orig_pfs(face_region, n_verts_header)
        captured['topology_ops'] = topology_ops
        captured['vertex_refs'] = vertex_refs
        captured['initial_verts'] = initial_verts
        captured['leading_40_header'] = leading_40_header
        captured['n_verts_header'] = n_verts_header
        captured['face_region'] = bytes(face_region)
        return topology_ops, vertex_refs, initial_verts, leading_40_header
    P.parse_face_section = pfs_spy

    orig_pce = P.parse_coord_elements
    def pce_spy(region, new_format=False):
        captured['coord_region'] = bytes(region)
        captured['new_format'] = new_format
        return orig_pce(region, new_format=new_format)
    P.parse_coord_elements = pce_spy

    try:
        result = P.parse_oot_v2(oot_path)
    finally:
        P.parse_face_section = orig_pfs
        P.parse_coord_elements = orig_pce
    captured['result'] = result
    return captured


def derive_coord_groups(coord_region: bytes, new_format: bool):
    """Re-run group_coord_elements + assign_axes to get group list."""
    els = P.parse_coord_elements(coord_region, new_format=new_format)
    groups = P.group_coord_elements(els)
    P.assign_axes(groups)
    return groups


# ─── CLERS mapping hypotheses ────────────────────────────────────────
# Each mapping takes a list of topology_ops dicts and returns a CLERS string.
# topology_ops entry: {cls, byte2, lo, hi, offset}

def mapping_lo_nib_simple(topology_ops: List[dict]) -> str:
    """Map by lo_nib bits:
        lo & 0x3 == 0 → E
        lo & 0x3 == 1 → R  (e.g. 0x7 -> 0b0111 & 0x3 = 0x3 → no, try different)
    Actually: lo=3 → C, lo=7 → R, lo=B → L, lo=F → E. (Guess from existing parser hints.)
    """
    chars = []
    for op in topology_ops:
        lo = op['lo']
        if lo == 3:
            chars.append('C')
        elif lo == 7:
            chars.append('R')
        elif lo == 0xB:
            chars.append('L')
        elif lo == 0xF:
            chars.append('E')
        else:
            chars.append('?')
    return ''.join(chars)


def mapping_lo_nib_v2(topology_ops: List[dict]) -> str:
    """Alternate mapping:
        lo & 0x4 → C-family (C if no L bit, else L)
    Just experiment."""
    chars = []
    for op in topology_ops:
        lo = op['lo']
        # Try: count bits set in lo
        bits = bin(lo).count('1')
        if bits == 1:
            chars.append('E')
        elif bits == 2:
            chars.append('R')
        elif bits == 3:
            chars.append('C')
        elif bits == 4:
            chars.append('L')
        else:
            chars.append('?')
    return ''.join(chars)


def mapping_lo7_C_lo15_E(topology_ops: List[dict]) -> str:
    """Cube observation: 12 faces, mostly C. Try:
        lo=7  → C
        lo=B  → R
        lo=3  → L
        lo=F  → E
    """
    chars = []
    for op in topology_ops:
        lo = op['lo']
        if lo == 7:
            chars.append('C')
        elif lo == 0xB:
            chars.append('R')
        elif lo == 3:
            chars.append('L')
        elif lo == 0xF:
            chars.append('E')
        else:
            chars.append('?')
    return ''.join(chars)


def mapping_all_C(topology_ops: List[dict]) -> str:
    """Sanity-check: pretend every op is C. Used to test counting invariant."""
    return 'C' * len(topology_ops)


def mapping_all_C_with_E(topology_ops: List[dict]) -> str:
    """All C plus a terminating E (last op = E)."""
    return 'C' * (len(topology_ops) - 1) + 'E'


# CLERS mapping table — names → functions.
MAPPINGS: Dict[str, Callable[[List[dict]], str]] = {
    'lo_nib_simple':    mapping_lo_nib_simple,
    'lo_nib_v2':        mapping_lo_nib_v2,
    'lo7_C_lo15_E':     mapping_lo7_C_lo15_E,
    'all_C':            mapping_all_C,
    'all_C_with_E':     mapping_all_C_with_E,
}


# ─── Coord-to-fresh-ID mapping ───────────────────────────────────────
def coord_groups_to_verts(groups, base_z_override=None) -> List[Tuple[float, float, float]]:
    """Walk coord groups and emit one vertex per (X, Y) pair.

    Strategy:
      - apex from G0, G1, G2 (first 3 groups: X, Y, Z)
      - pair completion: when Y group follows X group, emit (X, Y, base_z)
      - Y-only group: emit (?, Y, base_z) — X reuse strategy varies
    """
    if len(groups) < 3:
        return []
    base_z = base_z_override if base_z_override is not None else groups[2].value
    base_x = groups[0].value
    base_y = groups[1].value
    verts = [(base_x, base_y, base_z)]
    most_recent_x = base_x
    prev_axis = -1
    for i, g in enumerate(groups):
        if i < 3:
            if 0 <= g.axis <= 2:
                prev_axis = g.axis
            continue
        ax = g.axis
        if ax == 0:
            most_recent_x = g.value
        elif ax == 1 and prev_axis == 0:
            verts.append((most_recent_x, g.value, base_z))
        elif ax == 1 and prev_axis == 1:
            # Y-only — reuse most recent X (simplest rule)
            verts.append((most_recent_x, g.value, base_z))
        if 0 <= ax <= 2:
            prev_axis = ax
    return verts


# ─── Main harness ────────────────────────────────────────────────────
def try_decode(label, oot_path, dxf_path, mapping_name='lo_nib_simple', verbose=False):
    state = capture_state(str(ROOT / oot_path))
    topology_ops = state.get('topology_ops', [])
    groups = derive_coord_groups(state['coord_region'], state['new_format'])
    if verbose:
        print(f'\n=== {label} ===')
        print(f'  topology_ops ({len(topology_ops)}):')
        for op in topology_ops:
            print(f'    cls={op["cls"]} b2=0x{op["byte2"]:02x} lo={op["lo"]:x} hi={op["hi"]:x}')
        print(f'  initial_verts: {state["initial_verts"]}')

    mapping_fn = MAPPINGS[mapping_name]
    clers = mapping_fn(topology_ops)
    if verbose:
        print(f'  CLERS ({mapping_name}): {clers!r}')

    # Validate counts
    if '?' in clers:
        if verbose:
            print(f'  SKIP: unknown opcodes in CLERS')
        return {'error': 'unknown opcodes', 'clers': clers}

    try:
        inv = SR.validate_counts(clers)
    except Exception as e:
        return {'error': f'validate_counts: {e}', 'clers': clers}

    # Decode
    # Initialize seed loop from initial_verts (Vulcan stores seed separately).
    # Convert 1-based to 0-based abstract IDs.
    seed_loop = [v - 1 for v in state.get('initial_verts', [])][:3]
    if len(seed_loop) < 3:
        seed_loop = [0, 1, 2]  # fallback
    try:
        decoded = SR.decode(clers, seed_loop=seed_loop, seed_face=True)
    except Exception as e:
        return {'error': f'decode: {e}', 'clers': clers}

    forward = SR.reorder_to_forward(decoded)
    if verbose:
        print(f'  counts: {inv["counts"]}, expected_verts={inv["expected_vertices"]}, open_loops={decoded["open_loops"]}')
        print(f'  forward faces ({len(forward["faces"])}): {forward["faces"]}')

    # Build coord-derived vertex list
    verts_in_order = coord_groups_to_verts(groups)
    if verbose:
        print(f'  coord-derived verts ({len(verts_in_order)}):')
        for i, v in enumerate(verts_in_order):
            print(f'    V{i}: {v}')

    # Map fresh IDs to coord verts and score against DXF
    dxf_faces = load_dxf_faces(dxf_path)
    if not dxf_faces:
        return {
            'clers': clers, 'inv': inv, 'open_loops': decoded['open_loops'],
            'face_count': len(forward['faces']),
            'verts_needed': forward['vertex_count'],
            'verts_available': len(verts_in_order),
            'no_dxf': True,
        }

    if len(verts_in_order) < forward['vertex_count']:
        if verbose:
            print(f'  WARN: only {len(verts_in_order)} coord verts, need {forward["vertex_count"]}')
        # Pad with apex repeats so face indices are valid
        while len(verts_in_order) < forward['vertex_count']:
            verts_in_order.append(verts_in_order[0])

    parser_verts = list(verts_in_order)
    face_match = count_face_matches(forward['faces'], parser_verts, dxf_faces)
    vert_match, vert_total = count_vert_matches(parser_verts, dxf_faces)

    return {
        'clers': clers,
        'inv': inv,
        'open_loops': decoded['open_loops'],
        'face_count': len(forward['faces']),
        'face_match': face_match,
        'face_total': len(dxf_faces),
        'vert_match': vert_match,
        'vert_total': vert_total,
        'verts_needed': forward['vertex_count'],
        'verts_available': len(verts_in_order),
    }


def make_lo_mapping_strategy(lo_to_op: Dict[int, str], drop_leading=True):
    """Build a mapping function from lo_nib -> CLERS opcode dict.

    Universal pre-rules applied first:
      - byte2 == 0x1B  → 'X' (Vulcan finalizer — no face)
      - cls == 'E1'    → 'E' (cube's seed-ish op)
      - If drop_leading: the first 40-class op (= leading_40_header) is skipped
        when the file flags it (passed via topology_ops[0].get('skip', False)).
    """
    def fn(topology_ops):
        chars = []
        for i, op in enumerate(topology_ops):
            if op.get('skip'):
                continue
            if op['byte2'] == 0x1B:
                chars.append('X')
                continue
            if op['cls'] == 'E1':
                chars.append('E')
                continue
            chars.append(lo_to_op.get(op['lo'], '?'))
        return ''.join(chars)
    return fn


def brute_force_lo_mappings(files, baseline_solved_face_counts):
    """Try all 5^6 = 15,625 mappings of {lo_3, lo_4, lo_7, lo_B, lo_C, lo_F} -> CLERS.
    byte2=0x1B → X (finalizer). E1 class → E. Score by face_match with regression penalty.
    """
    ops_set = ['C', 'L', 'R', 'E', 'X']
    best = []
    total = 5 ** 6
    count = 0
    for c3, c4, c7, cb, cc, cf in itertools.product(ops_set, repeat=6):
        count += 1
        if count % 1000 == 0:
            print(f'  progress: {count}/{total}', file=sys.stderr)
        lo_map = {0x3: c3, 0x4: c4, 0x7: c7, 0xB: cb, 0xC: cc, 0xF: cf}
        strategy = make_lo_mapping_strategy(lo_map)
        scores = {}
        for label, oot, dxf in files:
            try:
                state = capture_state(str(ROOT / oot))
                topology_ops = list(state.get('topology_ops', []))
                # Mark leading_40_header op as skip (matches existing parser)
                if state.get('leading_40_header') and topology_ops:
                    topology_ops[0] = dict(topology_ops[0], skip=True)
                groups = derive_coord_groups(state['coord_region'], state['new_format'])
                clers = strategy(topology_ops)
                if '?' in clers:
                    scores[label] = {'face_match': 0, 'error': 'unknown'}
                    continue
                seed_loop = [v - 1 for v in state.get('initial_verts', [])][:3]
                if len(seed_loop) < 3:
                    seed_loop = [0, 1, 2]
                try:
                    decoded = SR.decode(clers, seed_loop=seed_loop, seed_face=True)
                except Exception as e:
                    scores[label] = {'face_match': 0, 'error': f'decode: {e}'}
                    continue
                forward = SR.reorder_to_forward(decoded)
                verts_in_order = coord_groups_to_verts(groups)
                while len(verts_in_order) < forward['vertex_count']:
                    verts_in_order.append(verts_in_order[0] if verts_in_order else (0, 0, 0))
                dxf_faces = load_dxf_faces(dxf)
                if not dxf_faces:
                    scores[label] = {'face_match': 0, 'no_dxf': True}
                    continue
                fm = count_face_matches(forward['faces'], verts_in_order, dxf_faces)
                scores[label] = {'face_match': fm or 0, 'face_total': len(dxf_faces)}
            except Exception as e:
                scores[label] = {'face_match': 0, 'error': str(e)}
        # Score: total face_match, with regression penalty
        total_fm = sum(s.get('face_match', 0) for s in scores.values())
        regressions = sum(1 for name, sc in scores.items()
                          if name in baseline_solved_face_counts
                          and sc.get('face_match', 0) < baseline_solved_face_counts[name])
        best.append((lo_map, total_fm, regressions, scores))
    best.sort(key=lambda x: (x[2], -x[1]))  # fewest regressions, then highest total
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', help='Single label to test (e.g. fan)')
    ap.add_argument('--mapping', default='lo_nib_simple', choices=list(MAPPINGS))
    ap.add_argument('--all-mappings', action='store_true', help='Try every CLERS mapping')
    ap.add_argument('--brute-lo', action='store_true', help='Brute-force lo_nib -> CLERS mappings')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if args.brute_lo:
        # First compute baseline (existing parser face match per file)
        files = TEST_FILES
        if args.file:
            files = [t for t in TEST_FILES if t[0] == args.file]
        print('Computing baseline (existing parser)...')
        baseline = {}
        for label, oot, dxf in files:
            try:
                r = P.parse_oot_v2(str(ROOT / oot))
                dxf_faces = load_dxf_faces(dxf)
                fm = count_face_matches(r.faces, r.vertices, dxf_faces) if dxf_faces else 0
                baseline[label] = fm or 0
            except Exception:
                baseline[label] = 0
        print(f'Baseline face matches: {baseline}')
        print('\nBrute-forcing 4^4 = 256 lo_nib -> CLERS mappings...')
        best = brute_force_lo_mappings(files, baseline)
        print('\nTop 10 mappings (sorted: fewest regressions, then highest total face_match):')
        for lo_map, total, regs, scores in best[:10]:
            print(f'  lo_map={lo_map}  total_fm={total}  regressions={regs}')
            for name, sc in scores.items():
                base = baseline.get(name, 0)
                fm = sc.get('face_match', 0)
                marker = '↓' if fm < base else ('↑' if fm > base else ' ')
                err = f' err={sc.get("error", "")}' if sc.get('error') else ''
                print(f'    {marker} {name:12s} fm={fm}/{sc.get("face_total", "?")} (was {base}){err}')
        return

    files = TEST_FILES
    if args.file:
        files = [t for t in TEST_FILES if t[0] == args.file]
        if not files:
            print(f'unknown file: {args.file}')
            sys.exit(1)

    mappings = list(MAPPINGS) if args.all_mappings else [args.mapping]

    for mapping_name in mappings:
        print(f'\n══ MAPPING: {mapping_name} ══')
        for label, oot, dxf in files:
            try:
                r = try_decode(label, oot, dxf, mapping_name=mapping_name, verbose=args.verbose)
            except Exception as e:
                print(f'  {label:12s}  ERROR: {e}')
                continue
            if 'error' in r:
                print(f'  {label:12s}  {r["error"]}  clers={r.get("clers", "?")!r}')
                continue
            if r.get('no_dxf'):
                print(f'  {label:12s}  no DXF; faces={r["face_count"]}  verts_need={r["verts_needed"]}/{r["verts_available"]} clers={r["clers"]!r}')
                continue
            print(f'  {label:12s}  faces={r["face_match"]}/{r["face_total"]}  verts={r["vert_match"]}/{r["vert_total"]}  open_loops={r["open_loops"]}  needs={r["verts_needed"]}/{r["verts_available"]}  clers={r["clers"]!r}')


if __name__ == '__main__':
    main()
