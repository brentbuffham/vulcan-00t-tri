#!/usr/bin/env python3
"""
OL_GW_evolve.py — evolutionary brute-force search.

Greedy hill-climbing: each cycle tests every single-parameter change against
the current parser. If any improves total score without regression, commit it
as the new baseline. Then repeat — the next cycle's "current" is the improved
version, so the search compounds.

When no single-parameter change helps, escalate to PAIRS (two simultaneous
changes), then TRIPLES if pairs don't help. Stops when no combination helps
or STOP file appears.

Search space per cycle:
  Tier 1 (singles, ~60 combos, ~2 min):
    - 48 axis-rule overrides (lo_nib × {STAY, BACK, FORWARD})
    - 12 decode-rule overrides (prev_source × byte_position)
  Tier 2 (pairs, ~3500 combos, ~2 hours):
    - 48*48 axis pairs
    - 12*12 decode pairs
    - 48*12 mixed pairs

Run:
  python3 scripts/OL_GW_evolve.py                # default: singles only, no commit
  python3 scripts/OL_GW_evolve.py --commit       # commit improvements as found
  python3 scripts/OL_GW_evolve.py --pairs --commit  # also try pairs
  python3 scripts/OL_GW_evolve.py --max-cycles 20 --commit  # cap cycles

Stop early: touch agent_runs/EVOLVE_STOP
"""
import sys, os, subprocess, time, json, argparse
from itertools import product
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))

import OL_GW_regression as regression
import OL_GW_brute_force as bf_axis
import OL_GW_brute_force_decode as bf_decode

PARSER_PATH = ROOT / 'python' / 'oot_parser_v2.py'
LOG_PATH = ROOT / 'agent_runs' / 'evolve.jsonl'
STOP_FILE = ROOT / 'agent_runs' / 'EVOLVE_STOP'


def git(*args, check=True, capture=True):
    return subprocess.run(['git'] + list(args), check=check,
                          capture_output=capture, text=True, cwd=str(ROOT))


def revert():
    git('checkout', '--', str(PARSER_PATH))


def total_score(scores):
    t = 0
    for s in scores.values():
        for k in ('dxf_match', 'gt_coverage', 'value_match'):
            v = s.get(k)
            if v is not None:
                t += v
    return t


# Single-change generators: each returns (label, apply_fn)
# apply_fn takes no args, applies the change to PARSER_PATH, returns True/False

def axis_singles():
    for lo in range(16):
        for action in bf_axis.ACTIONS:
            yield (f'axis lo=0x{lo:X} {action}',
                   lambda lo=lo, action=action: bf_axis.patch_with_rule(lo, action))


def decode_singles():
    for src in ['running', 'base_X', 'base_Y', 'base_Z']:
        for pos in [1, 2, 3]:
            yield (f'decode {src} pos={pos}',
                   lambda src=src, pos=pos: bf_decode.patch_with_decode_rule(src, pos))


def all_singles():
    yield from axis_singles()
    yield from decode_singles()


def all_pairs(items):
    """Cartesian product of items × items (excluding self-pairs)."""
    items = list(items)
    for i, a in enumerate(items):
        for j, b in enumerate(items):
            if i != j:
                yield (f'{a[0]} + {b[0]}',
                       lambda fa=a[1], fb=b[1]: fa() and fb())


def evaluate(label, apply_fn, baseline):
    """Apply, score, revert. Returns (delta, regressions, improvements)."""
    if not apply_fn():
        return None, None, None  # patch failed
    try:
        scores = regression.run_full_regression()
    except Exception:
        revert()
        return None, None, None
    delta = total_score(scores) - total_score(baseline)
    regs = regression.is_regression(baseline, scores)
    imps = regression.is_improvement(baseline, scores)
    revert()
    return delta, regs, imps


def search_one_tier(tier_name, candidate_gen, baseline, log_f):
    """Run all candidates in this tier; return best safe improvement or None."""
    print(f'\n--- Tier: {tier_name} ---')
    best = None
    count = 0
    for label, apply_fn in candidate_gen:
        count += 1
        if STOP_FILE.exists():
            print('  STOP file found, exiting.')
            STOP_FILE.unlink()
            return None
        delta, regs, imps = evaluate(label, apply_fn, baseline)
        if delta is None:
            continue
        log_f.write(json.dumps({
            'tier': tier_name, 'label': label,
            'delta': delta,
            'regressions': regs, 'improvements': imps,
        }) + '\n')
        log_f.flush()
        marker = '✗' if regs else (' ' if delta == 0 else '✓')
        if delta != 0 or regs:
            print(f'  [{count:4}] {label:50s} delta={delta:+3d} {marker}')
        if not regs and delta > 0:
            if best is None or delta > best['delta']:
                best = {
                    'label': label, 'apply_fn': apply_fn,
                    'delta': delta, 'improvements': imps,
                }
    return best


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--commit', action='store_true',
                   help='Commit and push each improvement as it is found')
    p.add_argument('--pairs', action='store_true',
                   help='Escalate to pair-search if singles produce no improvement')
    p.add_argument('--max-cycles', type=int, default=10,
                   help='Maximum number of evolution cycles (default 10)')
    args = p.parse_args()

    s = git('status', '--porcelain', str(PARSER_PATH), check=False)
    if s.stdout.strip():
        print(f'❌ {PARSER_PATH} has uncommitted changes. Commit/revert first.')
        return 1

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_f = open(LOG_PATH, 'a')

    cycle = 0
    while cycle < args.max_cycles:
        cycle += 1
        if STOP_FILE.exists():
            print('STOP file found, exiting.')
            STOP_FILE.unlink()
            break

        print(f'\n╔══ CYCLE {cycle} ══╗')
        baseline = regression.run_full_regression()
        baseline_total = total_score(baseline)
        print(f'Baseline total score: {baseline_total}')

        # Tier 1: singles
        best = search_one_tier('singles', all_singles(), baseline, log_f)

        # Tier 2: pairs (if singles failed and --pairs given)
        if best is None and args.pairs:
            print('  No single helps. Trying pairs...')
            best = search_one_tier('pairs', all_pairs(all_singles()), baseline, log_f)

        if best is None:
            print(f'\n✗ Cycle {cycle}: no improvement found. Stopping.')
            log_f.write(json.dumps({'cycle': cycle, 'event': 'no_improvement'}) + '\n')
            break

        # Apply the best change
        best['apply_fn']()
        new_baseline = regression.run_full_regression()
        new_total = total_score(new_baseline)
        print(f'\n✓ Cycle {cycle}: {best["label"]} → +{best["delta"]} (total now {new_total})')
        for imp in best['improvements']:
            print(f'    {imp["file"]}.{imp["metric"]}: {imp["before"]} → {imp["after"]}')

        if args.commit:
            git('add', str(PARSER_PATH))
            msg = (f'EVOLVE-{cycle:03d}: {best["label"]} (delta=+{best["delta"]})\n\n'
                   + '\n'.join(f'  {i["file"]}.{i["metric"]}: {i["before"]}→{i["after"]}'
                               for i in best["improvements"])
                   + '\n\nFound by greedy hill-climbing search.\n')
            git('commit', '-m', msg)
            git('push', check=False)
            print('  → committed and pushed')
        else:
            print('  → not committed (run with --commit to apply)')
            revert()
            print('  → reverted; cycle ends. Use --commit to chain improvements.')
            break

        log_f.write(json.dumps({
            'cycle': cycle, 'event': 'committed',
            'label': best['label'], 'delta': best['delta'],
        }) + '\n')

    log_f.close()
    print(f'\nDone. {cycle} cycles run.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
