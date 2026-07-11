"""SIDE-BIT HUNT 2, probe 5: LOOK at the tiling in a slot window.
For each labelled rail: rid, birth gi, r-range, fitS, n-range, side.
Sorted by min(r). Also check: rails sharing the same fitS (fragments of one
strip); n-range overlaps between rails (double-alloc violations);
r-range vs other rails' n-ranges (who alloc'd my ref line?).
[teacher data used for DISPLAY/mechanism understanding only]
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P)
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
cv = pickle.load(open('columns_v1.pkl', 'rb'))
colof = cv['colof']

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

rows = []
for rid, S in fitS.items():
    ts = byrail[rid]
    rs = [r for gi, r in ts]
    rmed = int(np.median(rs))
    if not (0 <= rmed < N): continue
    side = 1 if (S - rmed) > rmed else -1
    nlo, nhi = S - max(rs), S - min(rs)
    rows.append(dict(rid=rid, g0=ts[0][0], g1=ts[-1][0], rlo=min(rs),
                     rhi=max(rs), S=S, nlo=nlo, nhi=nhi, side=side,
                     nref=len(ts), rmed=rmed))
rows.sort(key=lambda d: d['rlo'])

print('=== window rlo in [400, 1000] ===')
print('%6s %6s %6s | %-11s %6s | %-11s %4s %4s %5s' %
      ('rid', 'g0', 'g1', 'r-range', 'S', 'n-range', 'side', 'nref', 'dcol'))
for d in rows:
    if 400 <= d['rlo'] <= 1000:
        dcol = colof[min(max(d['S']-d['rmed'],0),N-1)] - colof[d['rmed']]
        print('%6d %6d %6d | %5d-%5d %6d | %5d-%5d %+4d %4d %5d' %
              (d['rid'], d['g0'], d['g1'], d['rlo'], d['rhi'], d['S'],
               d['nlo'], d['nhi'], d['side'], d['nref'], dcol))

# fragments: same S
byS = defaultdict(list)
for d in rows:
    byS[d['S']].append(d)
multi = {S: ds for S, ds in byS.items() if len(ds) > 1}
print('\nfitS values shared by >1 rail: %d of %d distinct S (rails involved: %d)'
      % (len(multi), len(byS), sum(len(v) for v in multi.values())))
near = 0; tot = 0
Ss = sorted(byS)
for i in range(len(Ss) - 1):
    if Ss[i+1] - Ss[i] <= 4:
        near += 1
print('adjacent distinct S within <=4 of each other: %d pairs' % near)

# n-range overlap violations (double alloc)
ov = 0; cnt = 0
for i in range(len(rows)):
    for j in range(i+1, len(rows)):
        a, b = rows[i], rows[j]
        lo = max(a['nlo'], b['nlo']); hi = min(a['nhi'], b['nhi'])
        if lo <= hi:
            if a['S'] != b['S']:
                ov += 1
        cnt += 1
print('n-range overlaps between rails with DIFFERENT S: %d pairs' % ov)

# who alloc'd my r-range? r-range covered by another rail's n-range
cov = 0; tot = 0
for a in rows:
    tot += 1
    for b in rows:
        if b is a: continue
        if b['nlo'] <= a['rmed'] <= b['nhi']:
            cov += 1
            break
print("rails whose rmed lies inside another rail's n-range: %d/%d" % (cov, tot))

# distribution of delta = n - r
deltas = [d['S'] - 2 * d['rmed'] for d in rows]
print('\ndelta = nmed - rmed: median |d| = %d; histogram (clipped +-60):' %
      int(np.median(np.abs(deltas))))
h = Counter(int(np.clip(x, -60, 60)) // 10 * 10 for x in deltas)
print(sorted(h.items()))
