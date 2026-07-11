"""Emit GT-FREE decoded triangles from the strip machine (GT-free S = side_rule).
Per quad turn: split by SHORTER decoded (P_v11) diagonal -> 2 triangles.
Per fan turn: 1 triangle. Output slot-triples + per-tri GT-correct flag
(scoring overlay only). Saves decoded_faces.json {tris, good}.
"""
import pickle, json
from collections import Counter, defaultdict
import numpy as np

P = np.load('P_v11_intercepts.npy')
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
sr = pickle.load(open('side_rule.pkl', 'rb'))
Sgt = {rid: v[1] for rid, v in sr.items()}
F = np.load('faces_gt.npy')
faceset = set(tuple(sorted(f)) for f in F)
map11, _ = pickle.load(open('map11.pkl', 'rb'))
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

turns = []
cur = None
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        cur = len(turns) if gi in g2 else None
        if gi in g2:
            turns.append([g2[gi][0], gi, g2[gi][1], 0])
        continue
    if g['delim'] == 'e003' and cur is not None:
        turns[cur][3] += 1
byrailturns = defaultdict(list)
for t in turns:
    byrailturns[t[0]].append(t)

def isgt(tri):
    if len(set(tri)) != 3:
        return False
    gs = [map11.get(s) for s in tri]
    if any(x is None for x in gs) or len(set(gs)) != 3:
        return False
    return tuple(sorted(gs)) in faceset

def dlen(a, b):
    if not (0 <= a < len(P) and 0 <= b < len(P)):
        return 1e9
    return float(np.hypot(*(P[a, :2] - P[b, :2])))

tris = []; good = []
for rid, ts in byrailturns.items():
    S = Sgt.get(rid)
    if S is None:
        continue
    dn = -(rails[rid]['dir'] or -1)
    prev = None; last_n = None
    for _, gi, r, na in ts:
        n0 = S - r
        if prev is not None and na:
            rp, np1 = prev
            dr = r - rp
            if dr == 0:
                nf = last_n + dn
                t = (r, last_n, nf)
                if len(set(t)) == 3:
                    tris.append(t); good.append(isgt(t))
                n0 = nf
            else:
                # quad {rp, np1, r, n0}: split by shorter decoded diagonal
                if dlen(rp, n0) <= dlen(np1, r):
                    t1, t2 = (rp, np1, n0), (rp, n0, r)
                else:
                    t1, t2 = (np1, r, rp), (np1, r, n0)
                for t in (t1, t2):
                    if len(set(t)) == 3:
                        tris.append(t); good.append(isgt(t))
        prev = (r, n0); last_n = n0

good = np.array(good)
# only count triangles whose 3 slots are all map11-covered as "scorable"
scor = np.array([all(s in map11 for s in t) for t in tris])
print('decoded triangles:', len(tris))
print('  scorable (all 3 slots mapped):', int(scor.sum()))
print('  GT-correct among scorable: %d/%d = %.1f%% [GT-scored]'
      % (int(good[scor].sum()), int(scor.sum()),
         100 * good[scor].sum() / max(scor.sum(), 1)))
json.dump({'tris': [list(map(int, t)) for t in tris],
           'good': good.astype(int).tolist(),
           'scor': scor.astype(int).tolist()},
          open('decoded_faces.json', 'w'))
print('wrote decoded_faces.json')
