#!/usr/bin/env python3
"""Verify serpentine-mirror allocation: n = S - r, S constant per rail.
1) fit S per rail by voting over mapped GT-neighbor cands (cross-rail only);
2) score n = S - r on ALL checkable motif pairs (GT-edge test);
3) also test whether (n(t)) covers slots contiguously (counter view);
4) census of S values -> are they fold points (column boundaries)?"""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
F = np.load('faces_gt.npy')
E = set(); nbr = defaultdict(set)
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)):
        E.add((min(u,v),max(u,v))); nbr[u].add(v); nbr[v].add(u)

# map group index -> rail id for ref groups (use ref_events)
g2rail = {}
for gi, r, rid in ref_events:
    g2rail[gi] = (rid, r)

# for each idless e003 group, find preceding ref group's rail
# rows: (k, gi, last_ref, cands)
rail_sums = defaultdict(Counter)
items = []   # (k, gi, r, rid, cands)
for k, gi, r, cands in rows:
    # find the ref group just before gi
    rid = None
    for gj in range(gi-1, max(gi-5, -1), -1):
        if gj in g2rail and g2rail[gj][1] == r:
            rid = g2rail[gj][0]; break
    items.append((k, gi, r, rid, cands))
    if rid is None: continue
    for n in cands:
        if abs(n - r) > 3:            # cross-rail candidates only
            rail_sums[rid][n + r] += 1

fitS = {}
for rid, cnt in rail_sums.items():
    S, c = cnt.most_common(1)[0]
    if c >= 2: fitS[rid] = S
print(f'rails with fitted S (>=2 votes): {len(fitS)}')
print('sample S fits:', dict(list(fitS.items())[:15]))

# score n = S - r
chk = hit = 0; miss = []
for k, gi, r, rid, cands in items:
    if rid not in fitS: continue
    n = fitS[rid] - r
    gr, gn = slot2gt.get(r), slot2gt.get(n)
    if gr is None or gn is None: continue
    chk += 1
    if (min(gr,gn),max(gr,gn)) in E: hit += 1
    else: miss.append((k, gi, r, n))
print(f'\nserpentine-mirror score: {hit}/{chk} = {hit/max(chk,1)*100:.1f}% GT-edge hits')
print('sample misses:', miss[:12])

# S census — fold points
sc = sorted(set(fitS.values()))
print(f'\ndistinct S values ({len(sc)}):', sc[:40])
# do consecutive rails have S values ~2*colwidth apart?
diffs = np.diff(sc)
print('S diffs:', diffs[:40].tolist())
