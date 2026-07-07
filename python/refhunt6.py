#!/usr/bin/env python3
"""refhunt6 -- are wrong decoded values LEGITIMATE GT coordinates (alignment
slip) or junk (reconstruction error)?  LABELING ONLY.
Usage: python refhunt6.py <case>
"""
import sys, numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
exec(open(__file__.replace('refhunt6', 'refhunt1')).read().split("# Q1:")[0])

rng = np.random.default_rng(1)
for a in range(3):
    rows = pins_by_axis[a]
    if not rows: continue
    gvals = np.unique(np.round(G[:, a], 4))
    hits = 0; ctrl_hits = 0; near = 0
    for (i, tv) in rows:
        dv = P[i, a]
        j = np.searchsorted(gvals, round(dv, 4))
        ok = False
        for jj in (j - 1, j, j + 1):
            if 0 <= jj < len(gvals) and abs(gvals[jj] - dv) < 1e-3: ok = True
        if ok: hits += 1
        # control: random value in the axis span
        rv = rng.uniform(gvals[0], gvals[-1])
        j = np.searchsorted(gvals, rv)
        for jj in (j - 1, j, j + 1):
            if 0 <= jj < len(gvals) and abs(gvals[jj] - rv) < 1e-3: ctrl_hits += 1; break
    print(f'axis {"XYZ"[a]}: decoded-wrong value is a REAL GT coord: {hits}/{len(rows)}'
          f'   (control random: {ctrl_hits}/{len(rows)})')
