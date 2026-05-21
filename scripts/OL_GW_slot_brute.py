"""
Brute-force search for the universal c0_slot interpretation rule.

The c0_slot building rule is the universal piece we haven't cracked. SOLVED
files (triangle, plane, prism, 4sides, linear, cube) happen to decode
correctly under the current rule because their slot tag sequences cover all 3
axes per slot. Fan/NonRound/Hexhole/etc. do not — slot tags often cover only
1 or 2 axes, and the missing axes default to base (apex) producing chimera
vertices that the face decoder then references.

This harness defines a SPACE of plausible strategies and runs each against
every test file, scoring by FACE MATCH (real topology, not just coord
presence). Strategies that regress any currently-solved file are rejected.
The rest are ranked by total improvement.

Add more strategies as ideas come up — the search is intentionally
open-ended. Run with:

    python3 scripts/OL_GW_slot_brute.py            # quick smoke
    python3 scripts/OL_GW_slot_brute.py --all      # full enumeration
"""
import sys
import json
import argparse
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'python'))

import oot_parser_v2 as P  # noqa: E402


# ─── Test corpus ──────────────────────────────────────────────────────
# (label, .00t path, .dxf path)
TEST_FILES = [
    ('triangle', 'exampleFiles/tri-crack-triangle.00t', 'exampleFiles/tri-crack-triangle.dxf'),
    ('plane',    'exampleFiles/tri-crack.00t',          'exampleFiles/tri-crack.dxf'),
    ('linear',   'exampleFiles/tri-crack-linear.00t',   'exampleFiles/tri-crack-linear.dxf'),
    ('prism',    'exampleFiles/tri-crack-prism.00t',    'exampleFiles/tri-crack-prism.dxf'),
    ('4sides',   'exampleFiles/tri-crack-4sides-prism.00t', 'exampleFiles/tri-crack-4sides-prism.dxf'),
    ('cube',     'exampleFiles/tri-crack-solid.00t',    'exampleFiles/tri-crack-solid.dxf'),
    ('fan',      'exampleFiles/tri-crack-fan.00t',      'exampleFiles/tri-crack-fan.dxf'),
    ('hexhole',  'exampleFiles/tri-crack-Hexhole.00t',  'exampleFiles/tri-crack-HexHole.dxf'),
    ('lshape',   'exampleFiles/tri-crack-L-SHAPE.00t',  'exampleFiles/tri-crack-L-Shape.dxf'),
    ('nonround', 'exampleFiles/tri-crack-NonRound.00t', 'exampleFiles/tri-crack-NonRound.dxf'),
    ('stepped',  'exampleFiles/tri-crack-Stepped-pyramid.00t', 'exampleFiles/tri-crack-Stepped-pyramid.dxf'),
    ('sphere',   'exampleFiles/tri-crack-SPHERE.00t',   'exampleFiles/tri-crack-Sphere.dxf'),
]

# Baseline face-match counts under the default strategy.
# A strategy that drops ANY of these is rejected as a regression.
SOLVED_BASELINE_FACES = {
    'triangle': 1,
    'plane':    2,
    'linear':   5,
    'prism':    2,
    '4sides':   None,  # filled at startup
    'cube':     None,  # filled at startup
}


# ─── DXF face loading ──────────────────────────────────────────────────
_DXF_CACHE: Dict[str, Optional[List[Tuple[Tuple[float, float, float], ...]]]] = {}

def load_dxf_faces(path: str):
    if path in _DXF_CACHE:
        return _DXF_CACHE[path]
    p = ROOT / path
    if not p.exists():
        _DXF_CACHE[path] = None
        return None
    try:
        import ezdxf
    except ImportError:
        _DXF_CACHE[path] = None
        return None
    doc = ezdxf.readfile(str(p))
    msp = doc.modelspace()
    faces = []
    for e in msp:
        if e.dxftype() == '3DFACE':
            tri = (
                (round(e.dxf.vtx0[0], 2), round(e.dxf.vtx0[1], 2), round(e.dxf.vtx0[2], 2)),
                (round(e.dxf.vtx1[0], 2), round(e.dxf.vtx1[1], 2), round(e.dxf.vtx1[2], 2)),
                (round(e.dxf.vtx2[0], 2), round(e.dxf.vtx2[1], 2), round(e.dxf.vtx2[2], 2)),
            )
            faces.append(tri)
    _DXF_CACHE[path] = faces
    return faces


def _pos_match(a, b, tol=1.5):
    return abs(a[0] - b[0]) < tol and abs(a[1] - b[1]) < tol and abs(a[2] - b[2]) < tol


def count_face_matches(parser_faces, parser_verts, dxf_faces, tol=1.5):
    """Count how many DXF faces are exactly matched (3-vertex set) by a parser face.

    Two faces match if they share the same 3 vertex positions (unordered, within tol).
    Each DXF face matches at most once.
    """
    if not dxf_faces:
        return None
    matched = set()
    for pf in parser_faces:
        # Resolve parser-vertex positions
        if not all(0 <= i < len(parser_verts) for i in pf):
            continue
        pos_list = [parser_verts[i] for i in pf]
        for j, df in enumerate(dxf_faces):
            if j in matched:
                continue
            # Check if each parser pos has a corresponding DXF pos in df
            df_remaining = list(df)
            ok = True
            for p in pos_list:
                found = -1
                for k, d in enumerate(df_remaining):
                    if _pos_match(p, d, tol):
                        found = k
                        break
                if found < 0:
                    ok = False
                    break
                df_remaining.pop(found)
            if ok:
                matched.add(j)
                break
    return len(matched)


def count_vert_matches(parser_verts, dxf_faces, tol=1.5):
    """Count how many UNIQUE DXF vertex positions appear in parser_verts."""
    if not dxf_faces:
        return None, 0
    dxf_unique = set()
    for f in dxf_faces:
        for v in f:
            dxf_unique.add(v)
    matched = 0
    for d in dxf_unique:
        if any(_pos_match(pv, d, tol) for pv in parser_verts):
            matched += 1
    return matched, len(dxf_unique)


def score_with_strategy(strategy) -> Dict[str, Dict[str, int]]:
    """Run parser on all test files with the given c0_slot strategy. Return scores."""
    P.set_c0_strategy(strategy)
    results = {}
    for name, oot, dxf in TEST_FILES:
        try:
            r = P.parse_oot_v2(str(ROOT / oot))
        except Exception as e:
            results[name] = {'error': str(e), 'face_match': 0, 'dxf_total': 0}
            continue
        dxf_faces = load_dxf_faces(dxf)
        fm = count_face_matches(r.faces, r.vertices, dxf_faces) if dxf_faces else None
        vm, vt = count_vert_matches(r.vertices, dxf_faces) if dxf_faces else (None, None)
        results[name] = {
            'verts': len(r.vertices),
            'faces': len(r.faces),
            'face_match': fm if fm is not None else 0,
            'dxf_total': len(dxf_faces) if dxf_faces else 0,
            'vert_match': vm if vm is not None else 0,
            'vert_total': vt if vt is not None else 0,
        }
    P.set_c0_strategy(None)  # reset to default
    return results


# ─── Strategy library ─────────────────────────────────────────────────
# Each strategy is a function:
#   strategy(groups, base, base_z, alt_z, assigner_classes, apex_y_synth) -> {slot: [x,y,z]}

def s_baseline(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Current behavior — every-tag axis update, base init, lo_nib Z modifier."""
    c0 = {}
    running = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        if 0 <= ax <= 2:
            running[ax] = apex_y_synth.get(i, g.value)
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                c0[sl] = list(base)
            if 0 <= ax <= 2:
                c0[sl][ax] = g.value
            if t.lo_nib == 0x7:
                c0[sl][2] = base_z
            elif t.lo_nib == 0xF:
                c0[sl][2] = alt_z
    return c0


def s_first_tag_snapshot_after(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Only set on first tag with each hi_nib. Snapshot AFTER current group's update."""
    c0 = {}
    running = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        if 0 <= ax <= 2:
            running[ax] = apex_y_synth.get(i, g.value)
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                c0[sl] = list(running)
                if t.lo_nib == 0x7:
                    c0[sl][2] = base_z
                elif t.lo_nib == 0xF:
                    c0[sl][2] = alt_z
    return c0


def s_first_tag_snapshot_before(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Only set on first tag. Snapshot BEFORE current group's update."""
    c0 = {}
    running = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                c0[sl] = list(running)
                if t.lo_nib == 0x7:
                    c0[sl][2] = base_z
                elif t.lo_nib == 0xF:
                    c0[sl][2] = alt_z
        if 0 <= ax <= 2:
            running[ax] = apex_y_synth.get(i, g.value)
    return c0


def s_last_tag_snapshot(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Set on EVERY tag — final value is the running state at the LAST tag."""
    c0 = {}
    running = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        if 0 <= ax <= 2:
            running[ax] = apex_y_synth.get(i, g.value)
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            c0[sl] = list(running)
            if t.lo_nib == 0x7:
                c0[sl][2] = base_z
            elif t.lo_nib == 0xF:
                c0[sl][2] = alt_z
    return c0


def s_axis_only_from_tag(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Tag updates the slot's CURRENT-GROUP axis only. Missing axes from running state."""
    c0 = {}
    running = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        if 0 <= ax <= 2:
            running[ax] = apex_y_synth.get(i, g.value)
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                # Init from running (instead of base)
                c0[sl] = list(running)
            if 0 <= ax <= 2:
                c0[sl][ax] = g.value
            if t.lo_nib == 0x7:
                c0[sl][2] = base_z
            elif t.lo_nib == 0xF:
                c0[sl][2] = alt_z
    return c0


def s_pair_init(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Init slot from MOST RECENT (X, Y, Z) per axis. Each tag updates current axis."""
    c0 = {}
    most_recent = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        if 0 <= ax <= 2:
            most_recent[ax] = apex_y_synth.get(i, g.value)
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                c0[sl] = list(most_recent)
            if 0 <= ax <= 2:
                c0[sl][ax] = g.value
            if t.lo_nib == 0x7:
                c0[sl][2] = base_z
            elif t.lo_nib == 0xF:
                c0[sl][2] = alt_z
    return c0


def s_pair_complete_lookback(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Slot = the (X,Y) pair that COMPLETED most recently before/at the tag."""
    c0 = {}
    most_recent_x = base[0]
    most_recent_y = base[1]
    # Track last completed pair: when a Y group follows an X group, pair = (last_X, current_Y).
    last_pair_x = base[0]
    last_pair_y = base[1]
    prev_axis = -1
    for i, g in enumerate(groups):
        ax = g.axis
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                c0[sl] = [last_pair_x, last_pair_y, base_z]
                if t.lo_nib == 0x7:
                    c0[sl][2] = base_z
                elif t.lo_nib == 0xF:
                    c0[sl][2] = alt_z
        # Update running state AFTER tags fire so they see prev state
        if ax == 0:
            most_recent_x = apex_y_synth.get(i, g.value)
        elif ax == 1:
            most_recent_y = apex_y_synth.get(i, g.value)
            # If previous axis was X, the (X,Y) pair completes here
            if prev_axis == 0:
                last_pair_x = most_recent_x
                last_pair_y = most_recent_y
        if 0 <= ax <= 2:
            prev_axis = ax
    return c0


def s_pair_complete_after(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Slot = (X,Y) pair completed AT the tag's group (if group is Y after X)."""
    c0 = {}
    most_recent_x = base[0]
    most_recent_y = base[1]
    last_pair_x = base[0]
    last_pair_y = base[1]
    prev_axis = -1
    for i, g in enumerate(groups):
        ax = g.axis
        if ax == 0:
            most_recent_x = apex_y_synth.get(i, g.value)
        elif ax == 1:
            most_recent_y = apex_y_synth.get(i, g.value)
            if prev_axis == 0:
                last_pair_x = most_recent_x
                last_pair_y = most_recent_y
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                c0[sl] = [last_pair_x, last_pair_y, base_z]
                if t.lo_nib == 0x7:
                    c0[sl][2] = base_z
                elif t.lo_nib == 0xF:
                    c0[sl][2] = alt_z
        if 0 <= ax <= 2:
            prev_axis = ax
    return c0


def s_lo_nib_axis_modifier(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """Variant where lo_nib bit 3 (8 vs not-8) toggles axis source."""
    c0 = {}
    running = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        if 0 <= ax <= 2:
            running[ax] = apex_y_synth.get(i, g.value)
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl not in c0:
                c0[sl] = list(base) if (t.lo_nib & 0x8) == 0 else list(running)
            if 0 <= ax <= 2:
                c0[sl][ax] = g.value
            if t.lo_nib == 0x7:
                c0[sl][2] = base_z
            elif t.lo_nib == 0xF:
                c0[sl][2] = alt_z
    return c0


def s_pair_index_lookup(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """slot N = the N-th (X,Y) PAIR vertex in the encoded sequence.
    Pairs are completed when a Y group follows an X group. Index 1-based."""
    c0 = {}
    # First pass: enumerate pairs in order
    pairs = []  # list of (x, y, z=base_z)
    most_recent_x = base[0]
    prev_axis = -1
    for i, g in enumerate(groups):
        ax = g.axis
        if ax == 0:
            most_recent_x = apex_y_synth.get(i, g.value)
        elif ax == 1 and prev_axis == 0:
            pairs.append([most_recent_x, apex_y_synth.get(i, g.value), base_z])
        if 0 <= ax <= 2:
            prev_axis = ax
    # Second pass: assign slot N = pairs[N-1] if available
    seen_slots = set()
    for g in groups:
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl in seen_slots:
                continue
            seen_slots.add(sl)
            if 1 <= sl <= len(pairs):
                c0[sl] = list(pairs[sl - 1])
            else:
                c0[sl] = list(base)
            if t.lo_nib == 0x7:
                c0[sl][2] = base_z
            elif t.lo_nib == 0xF:
                c0[sl][2] = alt_z
    return c0


def s_pair_index_minus_one(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """slot N = the (N-1)-th pair (0-based). Slot 1 = first pair = pair[0]."""
    c0 = {}
    pairs = []
    most_recent_x = base[0]
    prev_axis = -1
    for i, g in enumerate(groups):
        ax = g.axis
        if ax == 0:
            most_recent_x = apex_y_synth.get(i, g.value)
        elif ax == 1 and prev_axis == 0:
            pairs.append([most_recent_x, apex_y_synth.get(i, g.value), base_z])
        if 0 <= ax <= 2:
            prev_axis = ax
    seen = set()
    for g in groups:
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl in seen: continue
            seen.add(sl)
            if 0 <= sl < len(pairs):
                c0[sl] = list(pairs[sl])
            else:
                c0[sl] = list(base)
            if t.lo_nib == 0x7:
                c0[sl][2] = base_z
            elif t.lo_nib == 0xF:
                c0[sl][2] = alt_z
    return c0


def s_apex_for_lo_F(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """lo=F means 'slot = apex (base XYZ)'. lo=7 keeps baseline-like behavior."""
    c0 = {}
    running = list(base)
    for i, g in enumerate(groups):
        ax = g.axis
        if 0 <= ax <= 2:
            running[ax] = apex_y_synth.get(i, g.value)
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if t.lo_nib == 0xF:
                # Slot = apex (frozen)
                c0[sl] = list(base)
            else:
                if sl not in c0:
                    c0[sl] = list(base)
                if 0 <= ax <= 2:
                    c0[sl][ax] = g.value
                if t.lo_nib == 0x7:
                    c0[sl][2] = base_z
    return c0


def s_loF_apex_lo7_pair(groups, base, base_z, alt_z, assigner_classes, apex_y_synth):
    """lo=F → slot = apex; lo=7 → slot = most recent completed pair vertex."""
    c0 = {}
    most_recent_x = base[0]
    most_recent_y = base[1]
    last_pair = [base[0], base[1], base_z]
    prev_axis = -1
    for i, g in enumerate(groups):
        ax = g.axis
        if ax == 0:
            most_recent_x = apex_y_synth.get(i, g.value)
        elif ax == 1:
            most_recent_y = apex_y_synth.get(i, g.value)
            if prev_axis == 0:
                last_pair = [most_recent_x, most_recent_y, base_z]
        for t in g.tags:
            if not (t.cls in assigner_classes and t.hi_nib > 0):
                continue
            sl = t.hi_nib
            if sl in c0:
                continue
            if t.lo_nib == 0xF:
                c0[sl] = list(base)
            elif t.lo_nib == 0x7:
                c0[sl] = list(last_pair)
            else:
                c0[sl] = list(base)
        if 0 <= ax <= 2:
            prev_axis = ax
    return c0


STRATEGIES = {
    'baseline':                  s_baseline,
    'first_tag_after':           s_first_tag_snapshot_after,
    'first_tag_before':          s_first_tag_snapshot_before,
    'last_tag_snapshot':         s_last_tag_snapshot,
    'axis_only_from_tag':        s_axis_only_from_tag,
    'pair_init_most_recent':     s_pair_init,
    'pair_complete_lookback':    s_pair_complete_lookback,
    'pair_complete_after':       s_pair_complete_after,
    'lo_nib_axis_modifier':      s_lo_nib_axis_modifier,
    'pair_index_lookup':         s_pair_index_lookup,
    'pair_index_minus_one':      s_pair_index_minus_one,
    'apex_for_lo_F':             s_apex_for_lo_F,
    'loF_apex_lo7_pair':         s_loF_apex_lo7_pair,
}


# ─── Reporting ────────────────────────────────────────────────────────
def _fill_baseline():
    """Compute baseline face-match counts for 4sides + cube (and any None entries)."""
    base_results = score_with_strategy(s_baseline)
    for name in list(SOLVED_BASELINE_FACES):
        if SOLVED_BASELINE_FACES[name] is None:
            SOLVED_BASELINE_FACES[name] = base_results.get(name, {}).get('face_match', 0)
    return base_results


def evaluate(strategy_name, strategy_func, baseline):
    """Run a strategy and report wins/regressions vs baseline."""
    results = score_with_strategy(strategy_func)
    regressions = []
    improvements = []
    for name in sorted(results):
        base = baseline.get(name, {}).get('face_match', 0)
        curr = results[name].get('face_match', 0)
        if curr < base:
            regressions.append((name, base, curr))
        elif curr > base:
            improvements.append((name, base, curr))
    return results, regressions, improvements


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--all', action='store_true', help='Run all strategies (default: smoke test)')
    ap.add_argument('--strategy', type=str, help='Run a single named strategy')
    args = ap.parse_args()

    print('Computing baseline (default strategy)...')
    baseline = _fill_baseline()
    print('Baseline scores per file:')
    for name in sorted(baseline):
        d = baseline[name]
        print(f'  {name:12s} {d.get("verts",0):3d}v/{d.get("faces",0):3d}f  faces={d.get("face_match",0)}/{d.get("dxf_total",0)}  verts={d.get("vert_match",0)}/{d.get("vert_total",0)}')

    print()

    if args.strategy:
        strategy_names = [args.strategy]
    elif args.all:
        strategy_names = list(STRATEGIES)
    else:
        strategy_names = ['baseline', 'first_tag_after', 'first_tag_before', 'last_tag_snapshot']

    summary = []
    for sname in strategy_names:
        sfunc = STRATEGIES[sname]
        print(f'─── Strategy: {sname} ' + '─' * 40)
        results, regressions, improvements = evaluate(sname, sfunc, baseline)
        for name in sorted(results):
            base_f = baseline.get(name, {}).get('face_match', 0)
            curr_f = results[name].get('face_match', 0)
            base_v = baseline.get(name, {}).get('vert_match', 0)
            curr_v = results[name].get('vert_match', 0)
            marker = '  '
            if curr_f > base_f or (curr_f == base_f and curr_v > base_v):
                marker = '↑ '
            elif curr_f < base_f or (curr_f == base_f and curr_v < base_v):
                marker = '↓ '
            print(f'  {marker}{name:12s} {results[name].get("verts",0):3d}v/{results[name].get("faces",0):3d}f  faces={curr_f}/{results[name].get("dxf_total",0)} (was {base_f})  verts={curr_v}/{results[name].get("vert_total",0)} (was {base_v})')
        net = sum(c - b for _, b, c in improvements) - sum(b - c for _, b, c in regressions)
        print(f'  Net delta: {net:+d}  ({len(improvements)} improvements, {len(regressions)} regressions)')
        summary.append((sname, net, len(regressions), results))

    print()
    print('─── Ranked summary ' + '─' * 40)
    # Strategies with zero regressions first, sorted by net improvement
    summary.sort(key=lambda x: (x[2], -x[1]))
    for sname, net, nregs, _ in summary:
        marker = '✓' if nregs == 0 else '✗'
        print(f'  {marker} {sname:30s} net={net:+d}  regressions={nregs}')


if __name__ == '__main__':
    main()
