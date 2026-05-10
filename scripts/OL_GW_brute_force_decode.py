#!/usr/bin/env python3
"""
OL_GW_brute_force_decode.py — exhaustive search for DELTA-decode rules.

Targets the DELTA-decode logic in parse_coord_elements, NOT the axis state
machine. The first brute force (over axis rules) found all 48 combinations
produced zero score change, proving the axis rule isn't the bottleneck.

The actual cube.00t problem: bytes 0x60 and 0x8B decode as 130 and 872
when overlaid at IEEE byte 1 with running prev. They should decode as
157420 and 27180 when overlaid at byte 3 / byte 2 with base_Y / base_X
prev.

This script tries every (prev_source, byte_position) combination for
post-base DELTAs and reports which produce improvements.

Search space:
  prev_source: running, base_X, base_Y, base_Z  (4 options)
  byte_position: 1, 2, 3                        (3 options)
  trigger condition:
    - default: use chosen rule for ANY post-base 1-byte DELTA
    - We could add more sophisticated triggers but start simple
  4 × 3 = 12 combos. Plus baseline.

Run:
  python3 scripts/OL_GW_brute_force_decode.py             # report only
  python3 scripts/OL_GW_brute_force_decode.py --commit    # commit best
"""
import sys
import subprocess
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))

import OL_GW_regression as regression


PARSER_PATH = ROOT / 'python' / 'oot_parser_v2.py'
LOG_PATH = ROOT / 'agent_runs' / 'brute_force_decode.jsonl'


def git(*args, check=True, capture=True):
    return subprocess.run(['git'] + list(args), check=check,
                          capture_output=capture, text=True, cwd=str(ROOT))


def revert():
    git('checkout', '--', str(PARSER_PATH))


def total_score(scores):
    total = 0
    for s in scores.values():
        if s.get('dxf_match') is not None:
            total += s['dxf_match']
        if s.get('gt_coverage') is not None:
            total += s['gt_coverage']
        if s.get('value_match') is not None:
            total += s['value_match']  # finer-grained per-axis-value matches
    return total


def patch_with_decode_rule(prev_source: str, byte_pos: int) -> bool:
    """Inject an alternate DELTA-decode path that, for 1-byte DELTAs after
    base FULLs are seen, tries the configured (prev_source, byte_pos) overlay.

    The patch wraps the existing DELTA decode: after the standard r is
    computed, also compute an alternative_r using the experimental rule.
    Use the alternative if its decoded value matches an expected coord
    range better — but we just always use the alternative for this brute
    force to see if any (source, pos) produces score improvements.
    """
    src = PARSER_PATH.read_text()

    # Find the existing standard DELTA-decode block in parse_coord_elements
    # (old format keep-trailing case).
    anchor = '''                if new_format:
                    # New format: zero out trailing bytes
                    r = [base_for_delta[0]] + stored + [0] * (8 - nb - 1)
                else:
                    # Old format: keep trailing bytes from previous value
                    r = [base_for_delta[0]] + stored + list(base_for_delta[nb + 1:8])'''

    if anchor not in src:
        return False
    if src.count(anchor) > 1:
        return False

    # Build the experimental decode block. For 1-byte DELTAs, use the
    # alternative prev source and byte position.
    prev_expr = {
        'running': 'prev',
        'base_X': 'full_bytes_history[0] if len(full_bytes_history) > 0 else prev',
        'base_Y': 'full_bytes_history[1] if len(full_bytes_history) > 1 else prev',
        'base_Z': 'full_bytes_history[2] if len(full_bytes_history) > 2 else prev',
    }[prev_source]

    insertion = f'''                # BRUTEFORCE: try alternate decode for 1-byte DELTAs
                if nb == 1 and len(full_bytes_history) >= 3:
                    alt_prev = {prev_expr}
                    alt_r = list(alt_prev[:8])
                    # Overlay stored byte at byte position {byte_pos}
                    alt_r[{byte_pos}] = stored[0]
                    # Zero trailing bytes after position {byte_pos}
                    for _bzi in range({byte_pos} + 1, 8):
                        alt_r[_bzi] = 0
                    r = alt_r
                else:
{anchor}'''

    new_src = src.replace(anchor, insertion)
    PARSER_PATH.write_text(new_src)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--commit', action='store_true')
    args = parser.parse_args()

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

    sources = ['running', 'base_X', 'base_Y', 'base_Z']
    positions = [1, 2, 3]
    results = []
    print(f'\nBrute-forcing {len(sources) * len(positions)} (prev_source, byte_pos) combinations...\n')

    for src_name in sources:
        for pos in positions:
            if not patch_with_decode_rule(src_name, pos):
                print(f'[{src_name:10s}, pos={pos}] PATCH FAILED')
                revert()
                continue
            try:
                scores = regression.run_full_regression()
            except Exception as e:
                print(f'[{src_name:10s}, pos={pos}] PARSER CRASH: {e}')
                revert()
                continue

            score_total = total_score(scores)
            delta = score_total - baseline_total
            regs = regression.is_regression(baseline, scores)
            imps = regression.is_improvement(baseline, scores)

            entry = {
                'prev_source': src_name, 'byte_pos': pos,
                'baseline_total': baseline_total, 'after_total': score_total,
                'delta': delta, 'regressions': regs, 'improvements': imps,
            }
            log_f.write(json.dumps(entry) + '\n')
            log_f.flush()
            results.append(entry)

            r = '✗' if regs else (' ' if delta == 0 else '✓')
            ireg = f'reg={len(regs)}' if regs else ''
            iimp = f'imp={len(imps)}' if imps else ''
            print(f'[{src_name:10s}, pos={pos}]: total={score_total:3d} delta={delta:+3d} {r} {ireg} {iimp}')

            revert()

    log_f.close()
    keepers = [r for r in results if not r['regressions'] and r['delta'] > 0]
    keepers.sort(key=lambda x: -x['delta'])

    print('\n=== TOP IMPROVEMENTS (no regression, delta > 0) ===')
    for k in keepers[:10]:
        imp_summary = '; '.join(
            f"{i['file']}.{i['metric']} {i['before']}→{i['after']}"
            for i in k['improvements']
        )
        print(f"  {k['prev_source']:10s} pos={k['byte_pos']}: delta=+{k['delta']}, {imp_summary}")

    if not keepers:
        print('  (none)')
        print('\nThis means even alternate DELTA decoding doesn\'t help — the')
        print('artifact bytes don\'t map to expected values via simple rules.')
        print('The encoder uses a more complex scheme (probably needs context).')
        return 0

    if args.commit:
        best = keepers[0]
        print(f'\nCommitting: {best["prev_source"]} pos={best["byte_pos"]}, delta=+{best["delta"]}')
        patch_with_decode_rule(best['prev_source'], best['byte_pos'])
        msg = (f'BRUTEFORCE-DECODE: {best["prev_source"]} pos={best["byte_pos"]} '
               f'(delta=+{best["delta"]})\n\n'
               f'For 1-byte DELTAs, use this prev_source and byte_position\n'
               f'when computing the IEEE overlay. Found by exhaustive search.\n')
        git('add', str(PARSER_PATH))
        git('commit', '-m', msg)
        git('push', check=False)
        print('Committed and pushed.')

    return 0


if __name__ == '__main__':
    sys.exit(main())
