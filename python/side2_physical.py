"""SIDE-BIT HUNT 2, probe 3: PHYSICAL side vs sweep frontier.
Hypothesis: the alloc column (mirror n) is always on the UN-SWEPT physical
side of the ref line — i.e. the physical offset direction w(n)-w(r) equals
the local sweep direction of the serpentine (sign of dw/dslot at r).
The slot-space side (n>r vs n<r) then falls out of where that physical
neighbour sits in emission order.

[teacher-scored]: physical side p from fitS mirror; local sweep drift GT-free.
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P)
XY = P[:, :2]
cv = pickle.load(open('columns_v1.pkl', 'rb'))
colof, bounds, u = cv['colof'], cv['bounds'], cv['u']
up = np.array([-u[1], u[0]])
w = XY @ up
t = XY @ u

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']

# teacher key (SCORING ONLY)
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
side = {}
for rid, S in fitS.items():
    rs = [r for gi, r in byrail[rid]]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side[rid] = 1 if (S - rmed) > rmed else -1

# per-column median w level (GT-free)
ncol = len(bounds) - 1
wcol = np.zeros(ncol)
for k in range(ncol):
    wcol[k] = np.median(w[bounds[k]:bounds[k+1]])

# local sweep drift at slot s (GT-free): robust slope of wcol over a window
def drift_at(s, half=6):
    k = colof[s]
    ks = np.arange(max(0, k - half), min(ncol, k + half + 1))
    if len(ks) < 3:
        return 0
    sl = np.polyfit(ks, wcol[ks], 1)[0]
    return 1 if sl > 0 else -1

tab = Counter(); tab2 = Counter(); tab3 = Counter()
pdist = Counter()
for rid, S in fitS.items():
    ts = byrail[rid]
    dws = []
    for gi, r in ts:
        n = S - r
        if 0 <= n < N and 0 <= r < N:
            dws.append(w[n] - w[r])
    if not dws:
        continue
    p = 1 if np.median(dws) > 0 else -1          # physical side [teacher]
    rmed = int(np.median([r for gi, r in ts]))
    dw = drift_at(rmed)                           # GT-free
    s = side[rid]                                 # teacher slot-side
    pdist[p] += 1
    tab[(p, dw)] += 1                             # is physical side = drift?
    tab2[(p, s)] += 1                             # physical side vs slot side
    tab3[(p == dw, s == (1 if dw != 0 else 0))] += 1

print('physical side distribution:', dict(pdist))
print('\nphysical side vs GT-free local drift (p, dw):')
tot = ok = 0
for k, v in sorted(tab.items()):
    print('  p=%+d dw=%+d : %d' % (k[0], k[1], v))
    if k[1] != 0:
        tot += v
        if k[0] == k[1]: ok += v
print('  p == dw: %d/%d = %.1f%%' % (ok, tot, 100 * ok / max(tot, 1)))

print('\nphysical side vs slot side (p, s):')
for k, v in sorted(tab2.items()):
    print('  p=%+d s=%+d : %d' % (k[0], k[1], v))

# combined rule: predicted slot side = the side whose mirror (via geometry
# peak) lies at physical offset dw. Quick check of the CHAIN:
# does (slot side s) == (physical side p) x (local slot-vs-w orientation)?
# orientation o = sign of (w[higher slots] - w[lower slots]) locally, GT-free
def orient_at(s, half=250):
    lo = max(0, s - half); hi = min(N, s + half)
    ss = np.arange(lo, hi)
    sl = np.polyfit(ss, w[ss], 1)[0]
    return 1 if sl > 0 else -1

tab4 = Counter()
for rid, S in fitS.items():
    ts = byrail[rid]
    rmed = int(np.median([r for gi, r in ts]))
    o = orient_at(rmed)                           # GT-free
    dws = []
    for gi, r in ts:
        n = S - r
        if 0 <= n < N:
            dws.append(w[n] - w[r])
    if not dws:
        continue
    p = 1 if np.median(dws) > 0 else -1
    s = side[rid]
    # prediction: slot side = p * o ... but p needs dw. Full GT-free: s_pred = dw*o
    dw = drift_at(rmed)
    if dw != 0:
        tab4[(dw * o, s)] += 1
ok = tab4[(1, 1)] + tab4[(-1, -1)]
tot = sum(tab4.values())
print('\nfull GT-free rule s_pred = drift * orientation: %d/%d = %.1f%%'
      % (ok, tot, 100 * ok / max(tot, 1)))
print('  table:', dict(tab4))
