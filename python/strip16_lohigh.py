"""Decisive test: lo value v == HIGH BYTE of the alloc slot n (v = n >> 8)?

n obtained teacher-forced via fitS mirror n = S - r (mechanism validation
only; category stated). Also test v vs r>>8, (S-r)>>8 +/- 1, and check
whether no-lo alloc groups have n>>8 == previous group's n>>8 (i.e. lo is
emitted only when the high byte CHANGES -- coord-codec-style announcement).
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

# fitS per rail (teacher-forced, as strip10)
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

tests = defaultdict(Counter)
noLo_same = Counter()
cur = None
prev_hi = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = g2[gi]
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs']:
        continue
    if cur is None:
        continue
    rid, r = cur
    S = fitS.get(rid)
    if S is None:
        continue
    n = S - r
    if not (0 <= n <= 2974):
        continue
    hi = n >> 8
    if len(g['lo']) == 1 and 0 <= g['lo'][0] <= 13:
        v = g['lo'][0]
        tests['v == n>>8'][v == hi] += 1
        tests['v == (n>>8)+1'][v == hi + 1] += 1
        tests['v == (n>>8)-1'][v == hi - 1] += 1
        tests['v == r>>8'][v == (r >> 8)] += 1
        tests['v == n//200'][v == n // 200] += 1
        tests['v == n//250'][v == n // 250] += 1
    elif not g['lo']:
        if prev_hi is not None:
            noLo_same[hi == prev_hi] += 1
    prev_hi = hi

for name, c in sorted(tests.items()):
    t = c[True] + c[False]
    print('%-16s %d/%d = %.1f%%' % (name, c[True], t, 100 * c[True] / max(t, 1)))
t = noLo_same[True] + noLo_same[False]
print('no-lo allocs: n>>8 same as prev alloc: %d/%d = %.1f%%'
      % (noLo_same[True], t, 100 * noLo_same[True] / max(t, 1)))
