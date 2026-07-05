#!/usr/bin/env python3
"""Answer-key alignment: map exactly-decoded slots to GT rows, project GT edges
into slot space, and characterise the TRUE edge-offset structure (column
widths, along-column steps) as a function of slot position."""
import pickle
import numpy as np
from collections import Counter, defaultdict
from scipy.spatial import cKDTree

P = np.load('P_base.npy')
G = np.loadtxt(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv', delimiter=',')
F = np.load('faces_gt.npy')
print('P',P.shape,'G',G.shape,'F',F.shape)

kd = cKDTree(G)
dist, gi = kd.query(P)
slot2gt = {}
gt2slot = {}
for s,(d,g) in enumerate(zip(dist,gi)):
    if d < 0.002:
        if g in gt2slot:   # non-unique gt row -> drop both (dup coords in GT?)
            gt2slot[g] = None
        else:
            gt2slot[g] = s
gt2slot = {g:s for g,s in gt2slot.items() if s is not None}
slot2gt = {s:g for g,s in gt2slot.items()}
print('exact unique slot<->gt matches:', len(slot2gt))

# GT edge set
E = set()
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)):
        E.add((min(u,v),max(u,v)))
print('GT edges:', len(E))

# project into slot space
soff = []
for u,v in E:
    su, sv = gt2slot.get(u), gt2slot.get(v)
    if su is None or sv is None: continue
    soff.append(sv-su if sv>su else su-sv)
soff = np.array(soff)
print(f'edges with both endpoints mapped: {len(soff)}')
oc = Counter(soff.tolist())
print('|slot offset| census top30:', oc.most_common(30))
print('offset<=3:', (soff<=3).sum(), '  4..50:', ((soff>3)&(soff<=50)).sum(),
      '  51..200:', ((soff>50)&(soff<=200)).sum(), '  >200:', (soff>200).sum())

# column-width estimate vs slot position: for offsets in 51..200 band,
# bucket by slot position
buck = defaultdict(list)
for u,v in E:
    su, sv = gt2slot.get(u), gt2slot.get(v)
    if su is None or sv is None: continue
    o = abs(sv-su)
    if 20 <= o <= 250:
        buck[min(su,sv)//100].append(o)
print('\ncross-column offset by slot/100 bucket (median, n):')
for k in sorted(buck):
    v = buck[k]
    print(f'  {k*100:5d}: med={int(np.median(v)):4d} n={len(v):3d}  sample={sorted(v)[:8]}')
