#!/usr/bin/env python3
"""
OL_GW_brute_force.py — exhaustive search for axis-state-machine rules.

Unlike the LLM-driven agent loop, this script doesn't ask anyone — it
systematically tries every value of the (E0:lo_nib → axis_action) mapping
and reports which produce improvements.

Strategy:
  For each lo_nib in {0..15}:
    For each action in {STAY, CYCLE_BACK, CYCLE_FORWARD}:
      1. Patch assign_axes to add `lo == X → action` as a special case
      2. Run regression
      3. Score: total improvement vs. baseline, no solved-file regression
      4. Revert
  Report ranked list of (lo_nib, action, delta_score) tuples.

Optionally: commit and push the BEST single change found.

Run:
  python3 scripts/OL_GW_brute_force.py            # report only, don't commit
  python3 scripts/OL_GW_brute_force.py --commit   # commit best improvement
"""
import sys
import os
import subprocess
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))

import OL_GW_regression as regression


PARSER_PATH = ROOT / 'python' / 'oot_parser_v2.py'
LOG_PATH = ROOT / 'agent_runs' / 'brute_force.jsonl'

# Actions
ACTIONS = ['STAY', 'BACK', 'FORWARD']


def git(*args, check=True, capture=True):
    return subprocess.run(['git'] + list(args), check=check,
                          capture_output=capture, text=True, cwd=str(ROOT))


def revert():
    git('checkout', '--', str(PARSER_PATH))


def total_score(scores):
    """Sum dxf_match + gt_coverage across all files. Higher = better."""
    total = 0
    for name, s in scores.items():
        if s.get('dxf_match') is not None:
            total += s['dxf_match']
        if s.get('gt_coverage') is not None:
            total += s['gt_coverage']
    return total


def patch_with_rule(lo_nib: int, action: str) -> bool:
    """Patch assign_axes to special-case a specific lo_nib with the given action.

    Inserts a new `elif first_e0_lo == X` branch BEFORE the existing rule for
    lo==7-or-A. The new branch takes priority for the given lo_nib value.
    Returns True on success."""
    src = PARSER_PATH.read_text()

    action_map = {
        'STAY': 'prev_g.axis',
        'BACK': '(prev_g.axis - 1) % 3',
        'FORWARD': '(prev_g.axis + 1) % 3',
    }

    # Find the existing `elif first_e0_lo == 7 or first_e0_lo == 0xA:` branch
    # and insert our new override BEFORE it.
    existing = '                elif first_e0_lo == 7 or first_e0_lo == 0xA:'
    if existing not in src:
        return False
    if src.count(existing) > 1:
        return False  # ambiguous

    insertion = (
        f'                elif first_e0_lo == 0x{lo_nib:X}:\n'
        f'                    sm_pred = {action_map[action]}  # BRUTEFORCE: lo=0x{lo_nib:X} → {action}\n'
    )
    new_src = src.replace(existing, insertion + existing)
    PARSER_PATH.write_text(new_src)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--commit', action='store_true',
                        help='Commit + push the single best improvement')
    parser.add_argument('--all-pairs', action='store_true',
                        help='Try all (lo, action) combos in addition to single overrides')
    args = parser.parse_args()

    # Verify parser is clean before starting
    p = git('status', '--porcelain', str(PARSER_PATH), check=False)
    if p.stdout.strip():
        print(f'❌ {PARSER_PATH} has uncommitted changes. Commit/revert first.')
        return 1

    print('Computing baseline scores...')
    baseline = regression.run_full_regression()
    baseline_total = total_score(baseline)
    print(f'Baseline total score: {baseline_total}')
    print(regression.summarize(baseline))

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_f = open(LOG_PATH, 'a')

    results = []
    total_runs = 16 * 3  # 16 lo_nibs × 3 actions
    run_idx = 0
    print(f'\nBrute-forcing {total_runs} (lo_nib, action) combinations...\n')

    for lo in range(16):
        for action in ACTIONS:
            run_idx += 1
            if not patch_with_rule(lo, action):
                print(f'[{run_idx:3}/{total_runs}] lo=0x{lo:X}, {action}: PATCH FAILED (anchor missing)')
                revert()
                continue
            try:
                scores = regression.run_full_regression()
            except Exception as e:
                print(f'[{run_idx:3}/{total_runs}] lo=0x{lo:X}, {action}: PARSER CRASH: {e}')
                revert()
                continue

            score_total = total_score(scores)
            delta = score_total - baseline_total
            regressions = regression.is_regression(baseline, scores)
            improvements = regression.is_improvement(baseline, scores)

            entry = {
                'lo_nib': lo,
                'action': action,
                'baseline_total': baseline_total,
                'after_total': score_total,
                'delta': delta,
                'regressions': regressions,
                'improvements': improvements,
            }
            log_f.write(json.dumps(entry) + '\n')
            log_f.flush()
            results.append(entry)

            r = '✗' if regressions else (' ' if delta == 0 else '✓')
            ireg = f'reg={len(regressions)}' if regressions else ''
            iimp = f'imp={len(improvements)}' if improvements else ''
            print(f'[{run_idx:3}/{total_runs}] lo=0x{lo:X}, {action:8s}: '
                  f'total={score_total:3d} delta={delta:+3d} {r} {ireg} {iimp}')

            revert()

    log_f.close()
    print('\n=== TOP IMPROVEMENTS (no regression, delta > 0) ===')
    keepers = [r for r in results if not r['regressions'] and r['delta'] > 0]
    keepers.sort(key=lambda x: -x['delta'])
    for k in keepers[:20]:
        imp_summary = '; '.join(
            f"{i['file']}.{i['metric']} {i['before']}→{i['after']}"
            for i in k['improvements']
        )
        print(f"  lo=0x{k['lo_nib']:X}, {k['action']}: delta=+{k['delta']}, {imp_summary}")

    if not keepers:
        print('  (none — no single (lo, action) override produced an improvement without regression)')
        return 0

    if args.commit and keepers:
        best = keepers[0]
        print(f'\nCommitting best: lo=0x{best["lo_nib"]:X}, {best["action"]}, delta=+{best["delta"]}')
        patch_with_rule(best['lo_nib'], best['action'])
        msg = (f'BRUTEFORCE: lo=0x{best["lo_nib"]:X} → {best["action"]} '
               f'(delta=+{best["delta"]})\n\n'
               f'Improvements:\n'
               + '\n'.join(f'  {i["file"]} {i["metric"]}: {i["before"]} → {i["after"]}'
                           for i in best["improvements"])
               + '\n\nFound by exhaustive search over (lo_nib, action) pairs.\n')
        git('add', str(PARSER_PATH))
        git('commit', '-m', msg)
        git('push', check=False)
        print('Committed and pushed.')
    elif keepers:
        print('\nRun with --commit to apply the top result.')

    return 0


if __name__ == '__main__':
    sys.exit(main())
