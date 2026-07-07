#!/usr/bin/env python3
"""refhunt9 -- teacher-force pinned sites at <1m (scoring criterion):
which (placement k0, hi-delta dh) lands within 1m of truth?
Census: placement-fixable (right k0, |dh|<=1) vs far-dh (reference unknowable).
Usage: python refhunt9.py <case>
"""
import struct, sys
import numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
exec(open(__file__.replace('refhunt9', 'refhunt4')).read().split("# teacher-force")[0])

from collections import Counter
cens = {0: Counter(), 1: Counter(), 2: Counter()}
onset_cens = {0: Counter(), 1: Counter(), 2: Counter()}
noex = {0: 0, 1: 0, 2: 0}
TOL = 1e-3
for (i, wa, tv) in pins:
    rec = info[i].get(wa)
    onset = dist[i - 1] < TOL if i >= 1 else False
    if rec is None or rec[0] != 'V': noex[wa] += 1; continue
    kind, pay, T, R = rec
    nb = len(pay)
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    hits = []
    for k0 in range(0, 8 - nb + 1):
        hb = k0; tail = R[k0 + nb:]
        hi = int.from_bytes(R[:hb], 'big') if hb else 0
        for dh in range(-300, 301):
            h2 = hi + dh
            if hb and not (0 <= h2 < (1 << (8 * hb))): continue
            if not hb and dh != 0: continue
            vb = (h2.to_bytes(hb, 'big') if hb else b'') + pay + tail
            v = be(vb)
            if np.isfinite(v) and abs(v - tv) < 1.0:
                hits.append((k0, dh))
    if not hits: noex[wa] += 1; continue
    k0, dh = min(hits, key=lambda h: (abs(h[1]), abs(h[0] - k0r)))
    dhc = 'dh0' if dh == 0 else 'dh+-1' if abs(dh) == 1 else 'dh2-4' if abs(dh) <= 4 else 'dhFAR'
    key = (nb, 'k0=rule' if k0 == k0r else f'k0={k0}(rule{k0r})', dhc)
    cens[wa][key] += 1
    if onset: onset_cens[wa][key] += 1
for a in range(3):
    print(f'\n=== axis {"XYZ"[a]} ===  no-hit: {noex[a]}')
    print('  ALL pinned:')
    for k, c in cens[a].most_common(10): print(f'    {k}: {c}')
    print('  ONSETS only:')
    for k, c in onset_cens[a].most_common(10): print(f'    {k}: {c}')
