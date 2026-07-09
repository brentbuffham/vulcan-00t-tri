#!/usr/bin/env python3
"""Phase 10: cross-checks of the refined extraction (refs_v2.pkl):
(1) ma_slotanchor's stream objective: consecutive refs -> mesh neighbors
    (was 6.0% identity under old extraction; random ~0.2%).
(2) boundary check: refs in (2963,2974] should map to OPEN-boundary verts.
GT = labeling only."""
import pickle
import numpy as np
from collections import defaultdict, Counter

groups = pickle.load(open('refs_v2.pkl', 'rb'))
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
ecount = Counter()
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
        ecount[(min(u, v), max(u, v))] += 1

# (1) consecutive-ref mesh-neighbor rate in stream order
ref_seq = [r for g in groups for r in g['refs']]
hit = tot = 0
prev = None
for r in ref_seq:
    g = map11.get(r)
    if g is None: prev = None; continue
    if prev is not None and g != prev:
        tot += 1
        if g in nbr[prev]: hit += 1
    prev = g
print(f'(1) consecutive-ref mesh-neighbor rate: {hit}/{tot} = {100*hit/max(tot,1):.1f}% '
      f'(old extraction: 6.0%; random ~0.2%)')

# also |d|<=1 slot-adjacency of consecutive refs (GT-free)
d1 = t = 0
prevr = None
for r in ref_seq:
    if prevr is not None:
        t += 1
        if abs(r - prevr) <= 1: d1 += 1
    prevr = r
print(f'    consecutive-ref |d|<=1 rate (GT-free): {d1}/{t} = {100*d1/max(t,1):.1f}%')

# (2) boundary refs
bverts = set()
for (u, v), n in ecount.items():
    if n == 1: bverts.add(u); bverts.add(v)
print(f'\n(2) GT boundary verts: {len(bverts)}')
hi = [r for r in set(ref_seq) if 2963 < r <= 2974]
for r in sorted(hi):
    g = map11.get(r)
    print(f'    ref {r}: GT {g}  boundary={g in bverts if g is not None else "unmapped"}')
