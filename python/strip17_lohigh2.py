"""Condition v == n>>8 on mirror-VERIFIED events only:
events where map11[r], map11[n] both exist AND are GT-adjacent (the 92.7%
mirror-edge subset) -- there n is almost surely the true alloc slot.
Report v == n>>8 there vs on unverified events. Also per-value confusion.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

byrail = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        byrail[g2[gi][0]].append((gi, g2[gi][1]))
fitS = {}
for rid, ts in byrail.items():
    votes = Counter()
    for gi, r in ts:
        gt = map11.get(r)
        if gt is None:
            continue
        for vv in nbr[gt]:
            s = gt2slot11.get(vv)
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S

conf = Counter()
res = defaultdict(Counter)
cur = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = g2[gi]
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if not (0 <= v <= 13) or cur is None:
        continue
    rid, r = cur
    S = fitS.get(rid)
    if S is None:
        continue
    n = S - r
    if not (0 <= n <= 2974):
        continue
    a, b = map11.get(r), map11.get(n)
    verified = a is not None and b is not None and b in nbr[a]
    res['verified' if verified else 'unverified'][v == (n >> 8)] += 1
    if verified:
        conf[(v, n >> 8)] += 1

for name, c in res.items():
    t = c[True] + c[False]
    print('%-11s v==n>>8: %d/%d = %.1f%%' % (name, c[True], t,
                                             100 * c[True] / max(t, 1)))
print('confusion (v, n>>8) on verified, top20:', conf.most_common(20))
