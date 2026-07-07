#!/usr/bin/env python3
"""refhunt2 -- characterize the pinned wrong-site jumps (LABELING ONLY).

For each pinned single-axis-wrong site:
  - true jump  tv - last  (how far the encoder's reference must reach)
  - specificity: how many of the last 400 decoded values are within half-window
    of tv (chance control)
  - fold hypothesis: is tv within half-window of the value at/before the most
    recent LARGE decoded jump on that axis (row-start alignment)?
  - dump 25 X examples + 25 Z examples with local context.
Usage: python refhunt2.py <case>
"""
import sys, numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
exec(open(__file__.replace('refhunt2', 'refhunt1')).read().split("# Q1:")[0])

MAXP = 400
HALF = {0: 4.0, 1: 16.0, 2: 0.0625}
JUMP = {0: 20.0, 1: 40.0, 2: 1.0}   # "large jump" thresholds from step stats
from collections import Counter
for a in range(3):
    rows = pins_by_axis[a]
    if not rows: continue
    seqfull = P[:, a]
    jumps = []; spec = []; foldhit = 0; foldtot = 0
    dump = []
    for (i, tv) in rows:
        seq = seqfull[:i]
        if len(seq) < 3: continue
        d1 = tv - seq[-1]
        jumps.append(d1)
        lo = max(0, len(seq) - MAXP)
        w = seq[lo:]
        nin = int((np.abs(tv - w) < HALF[a]).sum())
        spec.append(nin)
        # most recent large decoded jump before i
        dj = np.abs(np.diff(seq))
        js = np.where(dj > JUMP[a])[0]  # jump between js and js+1
        if len(js):
            foldtot += 1
            j = js[-1]
            # candidates: value just after previous jump (row start), just before it
            cands = {'after_prev_jump': seq[j + 1], 'before_prev_jump': seq[j]}
            if len(js) >= 2:
                cands['after_prev2_jump'] = seq[js[-2] + 1]
            if any(abs(tv - v) < HALF[a] for v in cands.values()):
                foldhit += 1
        if len(dump) < 25 and abs(d1) > HALF[a]:
            dump.append((i, tv, seq[-1], d1, nin))
    jumps = np.array(jumps)
    print(f'\n=== axis {"XYZ"[a]} ({len(rows)} pins) ===')
    print(f'true jump |tv-last|: median {np.median(np.abs(jumps)):.3f}  '
          f'p90 {np.percentile(np.abs(jumps),90):.3f}  max {np.abs(jumps).max():.3f}')
    print(f'jump sign: +{int((jumps>0).sum())} / -{int((jumps<0).sum())}')
    # quantization of jumps? (multiples of window unit)
    unit = HALF[a] * 2
    q = jumps / unit
    print(f'jump/window-unit: median|q| {np.median(np.abs(q)):.2f}  '
          f'frac near-integer(<0.05) {np.mean(np.abs(q-np.round(q))<0.05):.2f}')
    print(f'specificity: mean #in-halfwindow among last 400 = {np.mean(spec):.1f}  '
          f'(1-2 = specific, >10 = chancy)')
    print(f'fold hypothesis: tv within half-window of prev-jump-adjacent value: '
          f'{foldhit}/{foldtot}')
    print('examples (i, true, last, jump, #inwin):')
    for r in dump[:12]:
        print(f'  i={r[0]:5d} true={r[1]:12.4f} last={r[2]:12.4f} jump={r[3]:+10.4f} inwin={r[4]}')
