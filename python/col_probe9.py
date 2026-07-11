"""Is the mirror SIDE (n>r vs n<r) predictable GT-free?
Features per rail (teacher key = fitS side):
  - column sweep direction dirs[col_r] (t-trend of the column, GT-free)
  - r-trend within the rail (first->last ref, GT-free)
  - parity of col index (GT-free)
Contingency tables.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

P = np.load('P_v11_intercepts.npy')
N = len(P)
XY = P[:, :2]
cv = pickle.load(open('columns_v1.pkl', 'rb'))
colof, bounds = cv['colof'], cv['bounds']
u = cv['u']
t = XY @ u

ncol = len(bounds) - 1
levels = []
up = np.array([-u[1], u[0]])
w = XY @ up
V = XY[1:] - XY[:-1]
L = np.hypot(V[:, 0], V[:, 1])
sane = (L > 1.0) & (L < 8.0)
dirs = np.zeros(ncol, int)
for k in range(ncol):
    lo, hi = bounds[k], bounds[k + 1]
    lv = float(np.median(w[lo:hi]))
    onl = [s for s in range(lo, hi) if abs(w[s] - lv) < 1.2]
    if len(onl) >= 4:
        a = np.median([t[s] for s in onl[:3]])
        b = np.median([t[s] for s in onl[-3:]])
        dirs[k] = 1 if b > a else -1
    else:
        dirs[k] = 0

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
railseq = defaultdict(list)     # in stream order (gi)
for (gi, r, fo, dl), rid in zip(refs, assign):
    railseq[rid].append((gi, r))
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

tab = Counter()
for rid, S in fitS.items():
    seq = sorted(railseq[rid])
    rs = [r for gi, r in seq]
    rmed = int(np.median(rs))
    if not (0 <= rmed < N):
        continue
    n_med = S - rmed
    side = 1 if n_med > rmed else -1
    rtrend = np.sign(rs[-1] - rs[0]) if rs[-1] != rs[0] else 0
    cd = dirs[colof[rmed]]
    par = colof[rmed] % 2
    tab[('dir', cd, side)] += 1
    tab[('rtrend', int(rtrend), side)] += 1
    tab[('dir*rtrend', int(cd * rtrend), side)] += 1
    tab[('par', par, side)] += 1

for feat in ('dir', 'rtrend', 'dir*rtrend', 'par'):
    print(feat)
    for val in (-1, 0, 1):
        a = tab[(feat, val, 1)]
        b = tab[(feat, val, -1)]
        if a + b:
            print('  %s=%2d: side+1 %3d  side-1 %3d  (%.0f%%)' %
                  (feat, val, a, b, 100 * max(a, b) / (a + b)))
