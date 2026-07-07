#!/usr/bin/env python3
"""refhunt3 -- test SPATIAL-NEIGHBOR reference hypotheses at pinned sites.

Hypothesis: encoder's reconstruction reference = a topologically adjacent
(spatially near) EARLIER vertex, not the immediately-previous one.
GT used ONLY to pin true values. Proxies tested (all computable GT-free at
decode time):
  Z: ref = Z of earlier vertex nearest in decoded (X,Y) of current vertex
     (X,Y decoded before Z in the phase cycle).
  Y: ref = Y of earlier vertex nearest in decoded X of current vertex (weak).
  X: ref = X of earlier vertex nearest to previous full point P[i-1].
Also ORACLE: nearest earlier vertex to the TRUE position (upper bound).
Usage: python refhunt3.py <case>
"""
import sys, numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
exec(open(__file__.replace('refhunt3', 'refhunt1')).read().split("# Q1:")[0])

HALF = {0: 4.0, 1: 16.0, 2: 0.0625}
ok = dist < 1  # well-decoded mask (for oracle candidate pool quality checks)

for a, name in ((2, 'Z'), (0, 'X'), (1, 'Y')):
    rows = pins_by_axis[a]
    if not rows: continue
    oa = [x for x in range(3) if x != a]
    prox_hit = prox_hit_half = orac_hit = tot = 0
    prox_err = []; orac_err = []
    for (i, tv) in rows:
        if i < 5: continue
        tot += 1
        # true full position
        tpos = P[i].copy(); tpos[a] = tv
        prev = P[:i]
        # GT-free proxy: nearest earlier vertex in the other-axes plane,
        # using DECODED coords of current vertex (available pre-a in phase order
        # for Z; for X we use P[i-1]'s other axes as stand-in)
        if a == 2:
            q = P[i, oa]                     # X,Y of current vertex (decoded already)
        elif a == 1:
            q = P[i, oa]; q[1] = P[i - 1, 2] # X current + Z of prev vertex
        else:
            q = P[i - 1, oa]                 # Y,Z of previous vertex
        dd = np.linalg.norm(prev[:, oa] - q, axis=1)
        j = int(np.argmin(dd))
        e = abs(tv - prev[j, a]); prox_err.append(e)
        if e < HALF[a]: prox_hit += 1
        # allow top-5 nearest (is the right ref among near neighbors?)
        top5 = np.argsort(dd)[:5]
        if min(abs(tv - prev[t, a]) for t in top5) < HALF[a]: prox_hit_half += 1
        # ORACLE: nearest earlier vertex to TRUE position (3D)
        dd3 = np.linalg.norm(prev - tpos, axis=1)
        j3 = int(np.argmin(dd3))
        e3 = abs(tv - prev[j3, a]); orac_err.append(e3)
        if e3 < HALF[a]: orac_hit += 1
    prox_err = np.array(prox_err); orac_err = np.array(orac_err)
    print(f'\n=== axis {name}: {tot} pinned (half-window {HALF[a]}) ===')
    print(f'  GT-free proxy NN ref : within half {prox_hit}/{tot}  '
          f'(top5 any: {prox_hit_half}/{tot})  median err {np.median(prox_err):.4f}')
    print(f'  ORACLE 3D-NN ref     : within half {orac_hit}/{tot}  '
          f'median err {np.median(orac_err):.4f}')
