"""Decompose the GT-free S problem: geometry vote per SIDE.
S_geo_L (n<r) and S_geo_R (n>r) per rail; then:
 A. side-oracle accuracy (teacher-forced 1 bit): pick the fitS side's peak.
 B. GT-free single-peak coverage: rails where only one side has a strong
    peak (mesh edge/first-last column) -> side determined GT-free.
 C. combined potential: if a GT-free side bit existed, S accuracy = ?
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
def vote(rs, side):
    """side=+1: n>r ; side=-1: n<r. return (S, cnt, meand) or None"""
    lo = 2 * min(rs) - 320
    hi = 2 * max(rs) + 320
    best = None
    for S in range(lo, hi + 1):
        cnt = 0; dsum = 0.0
        for r in rs:
            n = S - r
            if not (0 <= n < N) or abs(n - r) < 6:
                continue
            if side * (n - r) < 0:
                continue
            d = np.hypot(XY[n, 0] - XY[r, 0], XY[n, 1] - XY[r, 1])
            if d < DMAX:
                cnt += 1; dsum += d
        if cnt:
            key = (cnt, -dsum / cnt)
            if best is None or key > best[0]:
                best = (key, S)
    if best is None:
        return None
    (cnt, negd), S = best
    if cnt >= max(2, int(np.ceil(0.5 * len(rs)))):
        return (S, cnt, -negd)
    return None

peaks = {}
for rid, rs in railrefs.items():
    if len(rs) < 2:
        continue
    peaks[rid] = (vote(rs, -1), vote(rs, +1))

# teacher fitS
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

both = [rid for rid in peaks if rid in fitS]
oracle_hit = 0; oracle_tot = 0
single = 0; single_hit = 0
for rid in both:
    pl, pr = peaks[rid]
    S = fitS[rid]
    rmed = int(np.median(railrefs[rid]))
    true_side = 1 if S - rmed > rmed else -1
    pk = pr if true_side > 0 else pl
    if pk is not None:
        oracle_tot += 1
        oracle_hit += (abs(pk[0] - S) <= 2)
    strongL = pl is not None and pl[1] >= max(2, int(np.ceil(0.6 * len(railrefs[rid]))))
    strongR = pr is not None and pr[1] >= max(2, int(np.ceil(0.6 * len(railrefs[rid]))))
    if strongL != strongR:
        single += 1
        pk1 = pl if strongL else pr
        single_hit += (abs(pk1[0] - S) <= 2)
print('rails with fitS & peaks:', len(both))
print('A. side-ORACLE (teacher-forced 1 bit/rail): peak found %d, |S-fitS|<=2 = %d = %.1f%%'
      % (oracle_tot, oracle_hit, 100 * oracle_hit / max(oracle_tot, 1)))
print('B. GT-free single-strong-peak rails: %d (%.0f%%), of those correct: %d = %.1f%%'
      % (single, 100 * single / len(both), single_hit, 100 * single_hit / max(single, 1)))
