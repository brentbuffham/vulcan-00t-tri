"""GT-free per-rail S estimation by MIRROR-GEOMETRY voting.
For each rail (rails_v3, GT-free), sweep candidate S; the mirror slot
n = S - r must be spatially adjacent to r (P_v11 XY distance ~2-6 m,
one horizontal mesh edge). The true S aligns many refs at once.
Score S_geo against fitS (teacher key) where both exist.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

P = np.load('P_v11_intercepts.npy')
N = len(P)
XY = P[:, :2]

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
railrefs = defaultdict(list)
for (gi, r, fo, dl), rid in zip(refs, assign):
    if 0 <= r < N:
        railrefs[rid].append(r)

DMAX = 6.0
S_geo = {}
for rid, rs in railrefs.items():
    if len(rs) < 2:
        continue
    lo = 2 * min(rs) - 320
    hi = 2 * max(rs) + 320
    best = None
    for S in range(lo, hi + 1):
        cnt = 0
        dsum = 0.0
        for r in rs:
            n = S - r
            if not (0 <= n < N) or abs(n - r) < 6:
                continue
            d = np.hypot(XY[n, 0] - XY[r, 0], XY[n, 1] - XY[r, 1])
            if d < DMAX:
                cnt += 1
                dsum += d
        if cnt:
            key = (cnt, -dsum / cnt)
            if best is None or key > best[0]:
                best = (key, S)
    if best is not None:
        cnt = best[0][0]
        if cnt >= max(2, int(np.ceil(0.5 * len(rs)))):
            S_geo[rid] = (best[1], cnt, len(rs))
print('rails with S_geo:', len(S_geo), '/', len(railrefs))

# teacher comparison
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for x, y in ((a, b), (b, c), (c, a)):
        nbr[x].add(y); nbr[y].add(x)
g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
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
        if gt is None: continue
        for vv in nbr[gt]:
            s = gt2slot11.get(vv)
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S

both = [rid for rid in S_geo if rid in fitS]
diffs = Counter()
for rid in both:
    d = S_geo[rid][0] - fitS[rid]
    diffs[max(-9, min(9, d))] += 1
n0 = sum(v for k, v in diffs.items() if abs(k) <= 0)
n1 = sum(v for k, v in diffs.items() if abs(k) <= 1)
n2 = sum(v for k, v in diffs.items() if abs(k) <= 2)
print('rails with both S_geo and fitS:', len(both))
print('  S_geo == fitS exact: %d = %.1f%%' % (n0, 100 * n0 / len(both)))
print('  |diff|<=1: %d = %.1f%%   |diff|<=2: %d = %.1f%%' %
      (n1, 100 * n1 / len(both), n2, 100 * n2 / len(both)))
print('  diff histogram:', sorted(diffs.items()))
# by ref count
for minref in (2, 3, 5):
    sel = [rid for rid in both if len(railrefs[rid]) >= minref]
    if sel:
        h = sum(1 for rid in sel if abs(S_geo[rid][0] - fitS[rid]) <= 2)
        print('  refs>=%d: %d rails, |diff|<=2 = %.1f%%' % (minref, len(sel), 100 * h / len(sel)))
