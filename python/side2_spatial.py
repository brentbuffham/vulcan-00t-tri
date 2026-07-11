"""SIDE-BIT HUNT 2, probe 4: SPATIAL coherence of the side bit.
Pipeline argument: strips sharing a column must share a side (the shared
column is alloc'd by exactly one of them). So side should run in long
same-value blocks along the SPATIAL strip sequence, flipping only at
seed/sink columns. Probe 1 tested BIRTH order (51.9% - concurrency noise);
here: order rails by rmed (emission/space), by column, and by XY nearest
neighbour, and measure side agreement. [teacher-scored coherence]
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P)
XY = P[:, :2]
cv = pickle.load(open('columns_v1.pkl', 'rb'))
colof = cv['colof']

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']

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
rmedof = {}
for rid, S in fitS.items():
    rs = [r for gi, r in byrail[rid]]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side[rid] = 1 if (S - rmed) > rmed else -1
        rmedof[rid] = rmed
lab = sorted(side, key=lambda r: rmedof[r])

# A. side sequence in rmed (spatial/emission) order
seq = [side[rid] for rid in lab]
runs = 1 + sum(1 for i in range(1, len(seq)) if seq[i] != seq[i-1])
lag1 = sum(1 for i in range(1, len(seq)) if seq[i] == seq[i-1])
print('A. side in RMED order: runs=%d (of %d), lag-1 same = %d/%d = %.1f%%'
      % (runs, len(seq), lag1, len(seq)-1, 100*lag1/(len(seq)-1)))
print('   seq:', ''.join('+' if s > 0 else '-' for s in seq))
# also print rmed gaps to see strip pitch
gaps = [rmedof[lab[i+1]] - rmedof[lab[i]] for i in range(len(lab)-1)]
print('   rmed gaps: median %d  mean %.0f  <=40:%d  41-120:%d  >120:%d'
      % (int(np.median(gaps)), np.mean(gaps),
         sum(1 for g in gaps if g <= 40), sum(1 for g in gaps if 40 < g <= 120),
         sum(1 for g in gaps if g > 120)))

# B. lag-1 agreement conditioned on gap size (same pipeline vs far apart)
for gmax in (30, 60, 90, 120, 200):
    sel = [(i) for i in range(len(lab)-1) if gaps[i] <= gmax]
    if sel:
        ok = sum(1 for i in sel if side[lab[i]] == side[lab[i+1]])
        print('   gap<=%3d: same side %d/%d = %.1f%%' % (gmax, ok, len(sel), 100*ok/len(sel)))

# C. XY nearest-neighbour side agreement
pts = np.array([XY[rmedof[rid]] for rid in lab])
ok = tot = 0
dists = []
for i, rid in enumerate(lab):
    d = np.hypot(pts[:, 0] - pts[i, 0], pts[:, 1] - pts[i, 1])
    d[i] = 1e9
    j = int(np.argmin(d))
    dists.append(d[j])
    tot += 1
    ok += (side[rid] == side[lab[j]])
print('C. XY nearest-neighbour same side: %d/%d = %.1f%%  (median nn dist %.1f m)'
      % (ok, tot, 100*ok/tot, np.median(dists)))

# D. same-column / overlapping r-range rails
byslot = sorted(lab, key=lambda r: rmedof[r])
ok = tot = 0
for i in range(len(byslot)):
    for j in range(i+1, len(byslot)):
        a, b = byslot[i], byslot[j]
        if abs(rmedof[a] - rmedof[b]) > 15:
            break
        tot += 1
        ok += (side[a] == side[b])
print('D. rails within 15 slots of each other: same side %d/%d = %.1f%%'
      % (ok, tot, 100*ok/max(tot, 1)))

# E. side vs rmed plot (text): does side band by slot region?
B = 20
print('E. side by rmed vigintile (bin -> +/-):')
edges = np.percentile([rmedof[r] for r in lab], np.linspace(0, 100, B+1))
for b in range(B):
    sel = [r for r in lab if edges[b] <= rmedof[r] <= edges[b+1]]
    a = sum(1 for r in sel if side[r] > 0); c = len(sel) - a
    print('   [%5d-%5d] +%d/-%d' % (edges[b], edges[b+1], a, c))
