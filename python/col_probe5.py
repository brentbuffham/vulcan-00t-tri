"""Residual analysis of columns_v1 vs fitS: histogram of S - (base_r+top_n),
which boundaries are wrong, and whether the odd-S teacher folds we MISS are
w-invisible (decode-error zones) or detector bugs.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

cv = pickle.load(open('columns_v1.pkl', 'rb'))
colof, bounds, u, levels = cv['colof'], cv['bounds'], cv['u'], cv['levels']
N = len(colof)
ncol = len(bounds) - 1
base = {k: bounds[k] for k in range(ncol)}
top = {k: bounds[k + 1] - 1 for k in range(ncol)}

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
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

resid = Counter()
residB = Counter()
for rid, S in fitS.items():
    for gi, r in byrail[rid]:
        n = S - r
        if not (0 <= n < N): continue
        a, b = map11.get(r), map11.get(n)
        if a is None or b is None or b not in nbr[a]: continue
        cr, cn = colof[r], colof[n]
        d = S - (base[cr] + top[cn])
        resid[max(-15, min(15, d))] += 1
        d2 = S - (top[cr] + base[cn])
        residB[max(-15, min(15, d2))] += 1
print('resid S-(br+tn):', sorted(resid.items()))
print('resid S-(tr+bn):', sorted(residB.items()))

# missed teacher folds: odd-S folds with no boundary within 2
implied = sorted({(S - 1) // 2 for S in fitS.values() if S % 2 == 1})
folds = np.array([b - 1 for b in bounds[1:-1]])
missed = [kf for kf in implied if np.min(np.abs(folds - kf)) > 2]
print('missed teacher folds:', missed)
P = np.load('P_v11_intercepts.npy')
up = np.array([-u[1], u[0]])
w = P[:, :2] @ up
for kf in missed[:6]:
    print(f'--- around missed fold {kf} (w values) ---')
    for s in range(kf - 6, kf + 7):
        if 0 <= s < N:
            print('  %4d w=%9.2f col=%d' % (s, w[s], colof[s]))
