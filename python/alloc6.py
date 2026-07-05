#!/usr/bin/env python3
"""Expand slot<->GT map using exact X,Z matching (Y is the broken axis).
Keep only UNIQUE matches both ways. Then re-derive the true allocation
sequence: for each idless e003 group, candidate n = mapped GT-neighbors of
last ref; print the (k, n_slot) thread to expose counter behaviour + resets."""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
P = np.load('P_base.npy')
G = np.loadtxt(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv', delimiter=',')
F = np.load('faces_gt.npy')
TOL = 0.002

# X,Z exact matching with uniqueness both directions
from scipy.spatial import cKDTree
kd2 = cKDTree(G[:,[0,2]])
cand = kd2.query_ball_point(P[:,[0,2]], TOL)
slot2gt = {}
gtcount = Counter()
for s, cs in enumerate(cand):
    if len(cs) == 1:
        slot2gt[s] = cs[0]; gtcount[cs[0]] += 1
slot2gt = {s:g for s,g in slot2gt.items() if gtcount[g]==1}
gt2slot = {g:s for s,g in slot2gt.items()}
print('unique XZ-exact matches:', len(slot2gt), ' (3D-exact was 693)')

E = set(); nbr = defaultdict(set)
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)):
        E.add((min(u,v),max(u,v))); nbr[u].add(v); nbr[v].add(u)

# verify: slot-offset census of GT edges with expanded map
soff = Counter()
for u,v in E:
    su,sv = gt2slot.get(u), gt2slot.get(v)
    if su is None or sv is None: continue
    soff[abs(su-sv)] += 1
tot = sum(soff.values())
print(f'edges mapped: {tot}; offset1 {soff[1]} ({soff[1]/tot*100:.0f}%), <=3 {sum(v for k,v in soff.items() if k<=3)}')

# allocation thread: k-th idless e003 group -> candidate n slots
print('\nthread (k, gi, r, candidate n slots [neighbors of r, mapped]):')
k = 0; last_ref = None
rows = []
for gi,g in enumerate(groups):
    if g['refs']:
        last_ref = g['refs'][-1]
    elif g['delim']=='e003':
        cands = []
        gr = slot2gt.get(last_ref) if last_ref is not None else None
        if gr is not None:
            cands = sorted(gt2slot[v] for v in nbr[gr] if v in gt2slot)
        rows.append((k, gi, last_ref, cands))
        k += 1
print('total idless e003:', k, ' with >=1 cand:', sum(1 for r in rows if r[3]))
for row in rows[:80]:
    print(f'  k={row[0]:4d} g{row[1]:4d} r={row[2]} cands={row[3]}')
pickle.dump((slot2gt, gt2slot, rows), open('thread.pkl','wb'))
