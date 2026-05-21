"""
Learn the (sep, lo, cls) -> CLERS mapping from SOLVED files, then apply to unsolved.

Strategy:
  1. Instrument the existing parser to log every C/L/R/E call paired with the
     (sep, lo, cls) tuple of the topology_op that triggered it.
  2. For SOLVED files (where the parser's topology decode is correct), build a
     dict mapping each tuple to its CLERS opcode. If the same tuple maps to
     different ops in different files, flag the inconsistency.
  3. Build a consistent universal mapping. Apply via Spirale Reversi to all
     files. Score against DXF.

If the solved-file mapping IS consistent, this gives us the universal rule the
encoder uses (at least within the cases the solved files cover). Tuples seen
only in unsolved files become "free" parameters we can brute force separately.
"""
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'python'))
sys.path.insert(0, str(ROOT / 'scripts'))

import oot_parser_v2 as P  # noqa: E402
import spirale_reversi as SR  # noqa: E402
from OL_GW_spirale_harness import (  # noqa: E402
    capture_state, derive_coord_groups, coord_groups_to_verts,
)
from OL_GW_slot_brute import TEST_FILES, load_dxf_faces, count_face_matches  # noqa: E402


# ─── Standalone re-implementation of the existing parser's CLERS dispatcher ─
# Mirrors python/oot_parser_v2.py lines ~1820-1893 (the inline EdgeBreaker
# dispatch). Returns the CLERS sequence the existing parser WOULD execute,
# but without touching dec.faces. Used to extract ground-truth CLERS from
# solved files.

def dispatch_clers(op_tuples, initial_boundary_size, n_verts_header,
                   leading_40_header=False, shared_base_decode=False):
    """Replay the existing parser's per-tuple dispatch and return the CLERS
    sequence (list of ops including 'X' for finalizers and 'SKIP' for the
    dropped leading_40_header op)."""
    bnd_size = initial_boundary_size  # mutable count of boundary verts
    c_ops_remaining = max(n_verts_header - initial_boundary_size, 0)
    last_op = None
    clers = []
    ops = list(op_tuples)
    if leading_40_header and ops:
        clers.append('SKIP')
        ops = ops[1:]
    for sep, lo, cls, b2 in ops:
        if bnd_size <= 0:
            clers.append('?')
            continue
        # Finalizer: byte2 == 0x1B → no face, gate advances -1 (no boundary change)
        if b2 == 0x1B:
            clers.append('X')
            continue
        n = bnd_size
        if shared_base_decode:
            if c_ops_remaining > 0:
                clers.append('C')
                c_ops_remaining -= 1
                bnd_size += 1  # C inserts a new boundary vert
                last_op = 'C'
            else:
                clers.append('X')
            continue
        if sep is not None:
            if sep in (0x5F, 0x87):
                if n >= 4:
                    clers.append('R')
                    bnd_size -= 1
                    last_op = 'R'
                else:
                    clers.append('?')
            else:
                if c_ops_remaining > 0:
                    clers.append('C')
                    c_ops_remaining -= 1
                    bnd_size += 1
                    last_op = 'C'
                elif n >= 4:
                    clers.append('R')
                    bnd_size -= 1
                    last_op = 'R'
                else:
                    clers.append('E')
                    bnd_size -= 3
                    last_op = 'E'
        else:
            if last_op is None or last_op == 'E':
                if c_ops_remaining > 0:
                    clers.append('C')
                    c_ops_remaining -= 1
                    bnd_size += 1
                    last_op = 'C'
                else:
                    clers.append('E')
                    bnd_size -= 3
                    last_op = 'E'
            elif last_op == 'C':
                if n >= 4:
                    clers.append('R')
                    bnd_size -= 1
                    last_op = 'R'
                else:
                    clers.append('E')
                    bnd_size -= 3
                    last_op = 'E'
            elif last_op == 'R':
                if n >= 4:
                    clers.append('L')
                    bnd_size -= 1
                    last_op = 'L'
                elif n == 3:
                    clers.append('E')
                    bnd_size -= 3
                    last_op = 'E'
                else:
                    clers.append('?')
            elif last_op == 'L':
                if n == 3:
                    clers.append('E')
                    bnd_size -= 3
                    last_op = 'E'
                elif n >= 4:
                    clers.append('L')
                    bnd_size -= 1
                    last_op = 'L'
                else:
                    clers.append('?')
            else:
                clers.append('?')
    return clers


# ─── Instrument existing parser to log CLERS dispatch ─────────────────
def instrument_and_run(oot_path: str):
    """Run parser; capture (sep, lo, cls, byte2) -> op-decision for each
    topology op processed. Returns list of (tuple, decided_op, op_index)."""
    log = []
    state_holder = {}

    orig_pfs = P.parse_face_section
    def pfs_spy(face_region, n_verts_header):
        state_holder['face_region'] = bytes(face_region)
        state_holder['n_verts_header'] = n_verts_header
        return orig_pfs(face_region, n_verts_header)
    P.parse_face_section = pfs_spy

    orig_dec = P.EdgeBreakerDecoder
    decoder_instances = []
    class SpyDec(orig_dec):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._call_log = []
            decoder_instances.append(self)
        def C(self):
            r = super().C(); self._call_log.append('C'); return r
        def R(self):
            r = super().R(); self._call_log.append('R'); return r
        def L(self):
            r = super().L(); self._call_log.append('L'); return r
        def E(self):
            r = super().E(); self._call_log.append('E'); return r
    P.EdgeBreakerDecoder = SpyDec

    try:
        result = P.parse_oot_v2(oot_path)
    finally:
        P.parse_face_section = orig_pfs
        P.EdgeBreakerDecoder = orig_dec

    # The LAST decoder instance is the one used for output
    if decoder_instances:
        ops_log = decoder_instances[-1]._call_log
    else:
        ops_log = []

    # Re-parse face_region into elements to align ops with tuples
    fr = state_holder.get('face_region', b'')
    pos = 0
    elements = []
    while pos < len(fr):
        b = fr[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(fr): break
            elements.append(('DATA',))
            pos += 1 + nb
        elif (b & 0x07) == 0x07 and b >= 0x07:
            elements.append(('SEP', b))
            pos += 1
        elif pos + 1 < len(fr):
            b2 = fr[pos+1]
            hi3 = b & 0xE0
            cls_map = {0x20: '20', 0x40: '40', 0xC0: 'C0', 0xE0: 'E0'}
            cls = cls_map.get(hi3, format(b, '02x'))
            if b == 0xe1: cls = 'E1'
            elements.append(('TAG', cls, b2))
            pos += 2
        else:
            break

    # Extract topology ops with sep context
    last_sep = None
    op_tuples = []  # (sep, lo, cls, byte2)
    for el in elements:
        if el[0] == 'SEP':
            last_sep = el[1]
        elif el[0] == 'TAG' and el[1] in ('40','C0','E1'):
            cls, b2 = el[1], el[2]
            lo = b2 & 0xF
            op_tuples.append((last_sep, lo, cls, b2))
            last_sep = None

    return {
        'result': result,
        'op_tuples': op_tuples,
        'decoded_ops': ops_log,
        'state': state_holder,
    }


# ─── Verify mapping consistency across solved files ──────────────────
# Cube uses a hardcoded FAST PATH (CUBE_SEQ) that doesn't follow per-tuple
# dispatch — exclude it from the learning corpus until we crack the rest.
SOLVED_FILES = ['triangle', 'plane', 'linear', 'prism', '4sides']


def build_consistent_mapping():
    """For each solved file, log every (sep, lo, cls) -> op pair.
    Detect inconsistencies (same tuple, different op)."""
    mapping = {}  # (sep, lo, cls) -> set of ops seen
    file_logs = {}

    for label, oot, dxf in TEST_FILES:
        if label not in SOLVED_FILES:
            continue
        # Capture state via the existing parser (gives us topology_ops, initial_verts, etc.)
        state = capture_state(str(ROOT / oot))
        leading_40_header = state.get('leading_40_header', False)
        n_verts_header = state.get('n_verts_header', 0)
        initial_verts = state.get('initial_verts', [])
        # Re-derive op_tuples from face_region
        fr = state.get('face_region', b'')
        pos = 0
        elements = []
        while pos < len(fr):
            b = fr[pos]
            if b <= 0x06:
                nb = b + 1
                if pos + 1 + nb > len(fr): break
                elements.append(('DATA',))
                pos += 1 + nb
            elif (b & 0x07) == 0x07 and b >= 0x07:
                elements.append(('SEP', b))
                pos += 1
            elif pos + 1 < len(fr):
                b2 = fr[pos+1]
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

        # Use re-implemented dispatcher (mirrors existing parser logic)
        clers_seq = dispatch_clers(op_tuples,
                                    initial_boundary_size=len(initial_verts),
                                    n_verts_header=n_verts_header,
                                    leading_40_header=leading_40_header)
        log = list(zip(op_tuples, clers_seq))
        file_logs[label] = log

        for t, op in log:
            key = (t[0], t[1], t[2])  # (sep, lo, cls) — ignore byte2
            if key not in mapping:
                mapping[key] = set()
            mapping[key].add(op)

    # Print inconsistencies
    print('=== Per-file decode logs ===')
    for label, log in file_logs.items():
        print(f'\n{label}:')
        for t, op in log:
            sep_s = f'0x{t[0]:02x}' if t[0] is not None else '----'
            print(f'  ({sep_s}, lo={t[1]:x}, cls={t[2]}, b2=0x{t[3]:02x}) -> {op}')

    print('\n=== Universal mapping candidate ===')
    inconsistent = []
    consistent = {}
    for key, ops in sorted(mapping.items(), key=lambda x: (x[0][0] if x[0][0] else -1, x[0][1])):
        sep_s = f'0x{key[0]:02x}' if key[0] is not None else '----'
        if len(ops) == 1:
            op = next(iter(ops))
            consistent[key] = op
            print(f'  ({sep_s}, lo={key[1]:x}, cls={key[2]}) -> {op}')
        else:
            inconsistent.append((key, ops))
            print(f'  ({sep_s}, lo={key[1]:x}, cls={key[2]}) -> AMBIGUOUS {ops}')

    print(f'\nConsistent mappings: {len(consistent)}')
    print(f'Inconsistent (need disambiguation): {len(inconsistent)}')
    return consistent, inconsistent


def apply_mapping_and_score(mapping: Dict[Tuple, str], files=None):
    """Use mapping (sep, lo, cls) -> CLERS op to decode all files with Spirale.
    Score against DXF face match. Returns per-file results."""
    if files is None:
        files = TEST_FILES
    results = {}
    for label, oot, dxf in files:
        state = capture_state(str(ROOT / oot))
        topology_ops = list(state.get('topology_ops', []))
        if state.get('leading_40_header') and topology_ops:
            topology_ops = topology_ops[1:]
        # Re-parse face_region with seps
        fr = state.get('face_region', b'')
        pos = 0
        elements = []
        while pos < len(fr):
            b = fr[pos]
            if b <= 0x06:
                nb = b + 1
                if pos + 1 + nb > len(fr): break
                elements.append(('DATA',))
                pos += 1 + nb
            elif (b & 0x07) == 0x07 and b >= 0x07:
                elements.append(('SEP', b))
                pos += 1
            elif pos + 1 < len(fr):
                b2 = fr[pos+1]
                hi3 = b & 0xE0
                cls_map = {0x20: '20', 0x40: '40', 0xC0: 'C0', 0xE0: 'E0'}
                cls = cls_map.get(hi3, format(b, '02x'))
                if b == 0xe1: cls = 'E1'
                elements.append(('TAG', cls, b2))
                pos += 2
            else:
                break

        last_sep = None
        clers_chars = []
        op_count = 0
        for el in elements:
            if el[0] == 'SEP':
                last_sep = el[1]
            elif el[0] == 'TAG' and el[1] in ('40','C0','E1'):
                cls, b2 = el[1], el[2]
                lo = b2 & 0xF
                # leading_40_header drop: first 40-class op is skipped if flagged
                if op_count == 0 and state.get('leading_40_header') and cls == '40':
                    op_count += 1
                    last_sep = None
                    continue
                if b2 == 0x1B:
                    clers_chars.append('X')
                else:
                    key = (last_sep, lo, cls)
                    clers_chars.append(mapping.get(key, '?'))
                op_count += 1
                last_sep = None
        clers = ''.join(clers_chars)
        if '?' in clers:
            results[label] = {'clers': clers, 'error': 'unmapped tuple'}
            continue
        # Seed loop from initial_verts
        seed_loop = [v - 1 for v in state.get('initial_verts', [])][:3]
        if len(seed_loop) < 3:
            seed_loop = [0, 1, 2]
        try:
            decoded = SR.decode(clers, seed_loop=seed_loop, seed_face=True)
        except Exception as e:
            results[label] = {'clers': clers, 'error': f'decode: {e}'}
            continue
        forward = SR.reorder_to_forward(decoded)
        groups = derive_coord_groups(state['coord_region'], state['new_format'])
        verts_in_order = coord_groups_to_verts(groups)
        while len(verts_in_order) < forward['vertex_count']:
            verts_in_order.append(verts_in_order[0] if verts_in_order else (0, 0, 0))
        dxf_faces = load_dxf_faces(dxf)
        fm = count_face_matches(forward['faces'], verts_in_order, dxf_faces) if dxf_faces else None
        results[label] = {
            'clers': clers,
            'face_match': fm or 0,
            'face_total': len(dxf_faces) if dxf_faces else 0,
        }
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true', help='Apply learned mapping to all files')
    args = ap.parse_args()

    print('Building universal (sep, lo, cls) -> CLERS mapping from SOLVED files...')
    print(f'Solved files used: {SOLVED_FILES}\n')
    consistent, inconsistent = build_consistent_mapping()

    if args.apply:
        # Build a partial mapping using consistent entries only
        mapping = dict(consistent)
        print('\n=== Applying mapping to all files (Spirale Reversi) ===')
        results = apply_mapping_and_score(mapping)
        # Baseline for comparison
        print('Baseline (existing parser) -> Spirale w/ learned mapping:')
        for label, oot, dxf in TEST_FILES:
            r = results.get(label, {})
            try:
                rp = P.parse_oot_v2(str(ROOT / oot))
                dxf_faces = load_dxf_faces(dxf)
                base_fm = count_face_matches(rp.faces, rp.vertices, dxf_faces) if dxf_faces else 0
            except Exception:
                base_fm = 0
            fm = r.get('face_match', 0)
            total = r.get('face_total', '?')
            err = r.get('error', '')
            marker = '↑' if fm > (base_fm or 0) else ('↓' if fm < (base_fm or 0) else ' ')
            print(f'  {marker} {label:12s} base={base_fm}  spirale={fm}/{total}  err={err}  clers={r.get("clers", "")[:40]}')


if __name__ == '__main__':
    main()
