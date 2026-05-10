#!/usr/bin/env python3
"""
OL_GW_cube_brute.py — cube-focused exhaustive brute force.

Score = total cube corners covered (cube1+cube2+cube3, max 24) using the
ground truth in OL_GW_ground_truth.py (cube2 = cube1 rotated -25°,
cube3 = -75°).

Guard rails:
  - Solved files (Triangle/Plane/Linear/Solid/Prism/4-Prism) must stay at or
    above SOLVED_THRESHOLDS. Any change that drops them is rejected.
  - Other partial-win files (Hexhole 3, NonRound 2, SPHERE 3) also gated.

Search space:
  Tier-1 SINGLES (60 combos):
    48 axis-state-machine overrides (16 lo_nibs × {STAY, BACK, FORWARD})
    12 DELTA-decode overrides (4 prev_sources × 3 byte positions)
  Tier-2 PAIRS (~3500 combos): cartesian product of above
  Tier-3 TRIPLES (escalation): only if --triples passed

Run:
  python3 scripts/OL_GW_cube_brute.py                 # singles only, no commit
  python3 scripts/OL_GW_cube_brute.py --pairs         # add pair search
  python3 scripts/OL_GW_cube_brute.py --commit        # commit best find
  python3 scripts/OL_GW_cube_brute.py --pairs --commit
"""
import sys, subprocess, argparse, json, time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))

import OL_GW_regression as regression
import OL_GW_brute_force as bf_axis
import OL_GW_brute_force_decode as bf_decode
from OL_GW_ground_truth import SOLVED_THRESHOLDS

PARSER_PATH = ROOT / 'python' / 'oot_parser_v2.py'
LOG_PATH = ROOT / 'agent_runs' / 'cube_brute.jsonl'

CUBE_FILES = ('cube1', 'cube2', 'cube3')


def git(*args, check=True, capture=True):
    return subprocess.run(['git'] + list(args), check=check,
                          capture_output=capture, text=True, cwd=str(ROOT))


def revert():
    git('checkout', '--', str(PARSER_PATH))


def cube_score(scores):
    """Sum gt_coverage across cube1, cube2, cube3 — max 24."""
    s = 0
    for f in CUBE_FILES:
        if f in scores and scores[f].get('gt_coverage') is not None:
            s += scores[f]['gt_coverage']
    return s


def cube_value_score(scores):
    """Sum value_match (per-axis distinct value hits) across cubes — finer signal."""
    s = 0
    for f in CUBE_FILES:
        if f in scores and scores[f].get('value_match') is not None:
            s += scores[f]['value_match']
    return s


def solved_violation(scores):
    """Return error string if any solved file dropped below threshold, else None."""
    for fname, threshold in SOLVED_THRESHOLDS.items():
        if fname in scores:
            sc = scores[fname]
            # Check whichever metric is the live one for this file
            actual = sc.get('dxf_match')
            if actual is None:
                actual = sc.get('gt_coverage') or 0
            if actual < threshold:
                return f'{fname} {actual} < {threshold}'
    return None


def evaluate(label, apply_fn, baseline_corner, baseline_value):
    """Apply, score on cubes, revert. Returns dict with cube delta or None."""
    if not apply_fn():
        return None
    try:
        scores = regression.run_full_regression()
    except Exception as e:
        revert()
        return {'error': str(e)}

    delta_corner = cube_score(scores) - baseline_corner
    delta_value = cube_value_score(scores) - baseline_value
    violation = solved_violation(scores)

    # Per-cube breakdown
    per_cube = {}
    for f in CUBE_FILES:
        if f in scores:
            per_cube[f] = {
                'corners': scores[f].get('gt_coverage'),
                'values': scores[f].get('value_match'),
                'verts': scores[f].get('verts'),
            }
    revert()
    return {
        'delta_corner': delta_corner,
        'delta_value': delta_value,
        'violation': violation,
        'per_cube': per_cube,
    }


def axis_singles():
    """48 axis-rule overrides."""
    for lo in range(16):
        for action in bf_axis.ACTIONS:
            yield (f'axis lo=0x{lo:X} {action}',
                   lambda lo=lo, action=action: bf_axis.patch_with_rule(lo, action))


def decode_singles():
    """12 decode-rule overrides."""
    for src in ['running', 'base_X', 'base_Y', 'base_Z']:
        for pos in [1, 2, 3]:
            yield (f'decode {src} pos={pos}',
                   lambda src=src, pos=pos: bf_decode.patch_with_decode_rule(src, pos))


def all_singles():
    yield from axis_singles()
    yield from decode_singles()


def all_pairs(items):
    items = list(items)
    for i, a in enumerate(items):
        for j, b in enumerate(items):
            if i != j:
                yield (f'{a[0]} + {b[0]}',
                       lambda fa=a[1], fb=b[1]: fa() and fb())


def search_tier(tier_name, gen, baseline_corner, baseline_value, log_f):
    """Run all candidates; return best safe improvement or None."""
    print(f'\n--- Tier: {tier_name} ---')
    best = None
    count = 0
    n_helped = 0
    for label, apply_fn in gen:
        count += 1
        result = evaluate(label, apply_fn, baseline_corner, baseline_value)
        if result is None or 'error' in result:
            continue
        log_f.write(json.dumps({
            'tier': tier_name, 'label': label, **result,
        }) + '\n')
        log_f.flush()

        # Print progress: only show non-zero deltas or violations
        delta_c = result['delta_corner']
        delta_v = result['delta_value']
        viol = result['violation']
        if delta_c != 0 or delta_v != 0 or viol:
            mark = '✗' if viol else ('✓' if delta_c > 0 else (' ' if delta_c == 0 else '↓'))
            v = f'reg={viol}' if viol else ''
            print(f'  [{count:5d}] {label:50s} corners={delta_c:+3d} values={delta_v:+3d} {mark} {v}')

        if not viol and delta_c > 0:
            n_helped += 1
            if best is None or delta_c > best['delta_corner'] or \
               (delta_c == best['delta_corner'] and delta_v > best['delta_value']):
                best = {
                    'label': label, 'apply_fn': apply_fn,
                    'delta_corner': delta_c, 'delta_value': delta_v,
                    'per_cube': result['per_cube'],
                }
    print(f'\n  Tested {count}; {n_helped} helped without solved-regression.')
    return best


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--commit', action='store_true')
    p.add_argument('--pairs', action='store_true',
                   help='Escalate to pairs if singles fail')
    args = p.parse_args()

    s = git('status', '--porcelain', str(PARSER_PATH), check=False)
    if s.stdout.strip():
        print(f'❌ {PARSER_PATH} has uncommitted changes.')
        return 1

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    print('Computing baseline cube scores...')
    baseline = regression.run_full_regression()
    bc = cube_score(baseline)
    bv = cube_value_score(baseline)
    print(f'\nBaseline cube CORNER score: {bc}/24 (cube1+2+3)')
    print(f'Baseline cube VALUE score:  {bv}')
    for f in CUBE_FILES:
        if f in baseline:
            sc = baseline[f]
            print(f'  {f}: corners={sc.get("gt_coverage")}/8 values={sc.get("value_match")}/{sc.get("value_total")} verts={sc.get("verts")}')

    log_f = open(LOG_PATH, 'a')
    log_f.write(json.dumps({'event': 'baseline', 'corners': bc, 'values': bv,
                            'time': time.time()}) + '\n')

    # Tier 1: singles
    best = search_tier('singles', all_singles(), bc, bv, log_f)

    # Tier 2: pairs
    if best is None and args.pairs:
        print('\n  No single helps. Trying PAIRS...')
        best = search_tier('pairs', all_pairs(all_singles()), bc, bv, log_f)

    log_f.close()

    if best is None:
        print('\n✗ No improvement found. Either:')
        print('   - The 60-combo single-parameter space is exhausted')
        print('   - The cube failure modes need new rule kinds (multi-byte DELTA, slot-tag interpretation)')
        print('   - Or pairs/triples needed (re-run with --pairs)')
        return 0

    # Apply and report
    print(f'\n✓ BEST: {best["label"]}')
    print(f'  corner delta: +{best["delta_corner"]}  value delta: +{best["delta_value"]}')
    for f, pc in best['per_cube'].items():
        print(f'  {f}: corners={pc["corners"]}/8 values={pc["values"]} verts={pc["verts"]}')

    if args.commit:
        best['apply_fn']()
        scores = regression.run_full_regression()
        viol = solved_violation(scores)
        if viol:
            print(f'\n❌ Re-applied change caused violation: {viol}. Reverting.')
            revert()
            return 1
        msg = (f'CUBE-BRUTE: {best["label"]} (cube corners +{best["delta_corner"]})\n\n'
               + '\n'.join(f'  {f}: corners {pc["corners"]}/8'
                           for f, pc in best['per_cube'].items())
               + '\n\nFound by cube-focused brute-force search.\n'
               + 'No solved-file regression.\n')
        git('add', str(PARSER_PATH))
        git('commit', '-m', msg)
        git('push', check=False)
        print('Committed and pushed.')
    else:
        print('\nRun with --commit to apply the top result.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
