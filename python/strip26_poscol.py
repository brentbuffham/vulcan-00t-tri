"""Rebuild columns from 3D POSITION jumps (robust to map holes), then re-test
the boustrophedon S formula. A column boundary = large 3D step between
consecutive MAPPED slots (bridging unmapped gaps). Then:
  S ?= base_r + base_n + len_n - 1   (mesh-neighbour column pair)
computed with the mirror column found via n's own column, per verified event.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
P = np.loadtxt('intercepts_gt.csv', delimiter=',')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

maxslot = max(map11)
# ordered list of (slot, pos) for mapped slots
seq = [(s, P[map11[s]]) for s in range(maxslot + 1) if s in map11]
# typical step
steps = [np.linalg.norm(seq[i+1][1]-seq[i][1]) for i in range(len(seq)-1)]
med = np.median(steps)
thr = 4 * med
print('median mapped-slot step %.2f  boundary thr %.2f' % (med, thr))
# boundaries at slot midpoints where jump>thr; assign column id per mapped slot
colof = {}
cid = 0
colof[seq[0][0]] = 0
for i in range(1, len(seq)):
    if np.linalg.norm(seq[i][1]-seq[i-1][1]) > thr:
        cid += 1
    colof[seq[i][0]] = cid
ncol = cid + 1
# column extents in SLOT space (min/max mapped slot per col)
colslots = defaultdict(list)
for s, c in colof.items():
    colslots[c].append(s)
base = {c: min(v) for c, v in colslots.items()}
top = {c: max(v) for c, v in colslots.items()}
clen = {c: top[c]-base[c]+1 for c in colslots}
print('columns:', ncol, ' median slot-len', int(np.median(list(clen.values()))))

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
            if s is not None and abs(s - r) > 3: votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2: fitS[rid] = S

# per verified event: cols of r and n; boustrophedon predictions
hit = defaultdict(int); tot = 0; samediff = Counter()
for rid, S in fitS.items():
    for gi, r in byrail[rid]:
        n = S - r
        if not (0 <= n <= maxslot): continue
        cr, cn = colof.get(r), colof.get(n)
        if cr is None or cn is None: continue
        a, b = map11.get(r), map11.get(n)
        if a is None or b is None or b not in nbr[a]: continue
        tot += 1
        samediff[cr == cn] += 1
        preds = {
            'br+bn+ln-1': base[cr]+base[cn]+clen[cn]-1,
            'br+bn+ln':   base[cr]+base[cn]+clen[cn],
            'tr+bn':      top[cr]+base[cn],
            'br+tn':      base[cr]+top[cn],
            'tr+tn':      top[cr]+top[cn],
            'br+bn':      base[cr]+base[cn],
        }
        for name, val in preds.items():
            if abs(S - val) <= 2: hit[name] += 1
print('verified col-mapped events:', tot, ' r,n SAME col:', dict(samediff))
for name, h in sorted(hit.items(), key=lambda kv:-kv[1]):
    print('  S == %-12s (+-2): %d = %.1f%%' % (name, h, 100*h/max(tot,1)))
