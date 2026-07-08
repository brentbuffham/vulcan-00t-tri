#!/usr/bin/env python3
"""Build a denser slot<->GT answer-key map from P_v11 (52% exact decode).
Validate indexing (P11 row index vs ref-slot index) via GT-edge rates, then
save map11.pkl. Answer-key construction for MECHANISM testing only.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict
from scipy.spatial import cKDTree

P = np.load('P_v11_intercepts.npy')
G = np.loadtxt('intercepts_gt.csv', delimiter=',')
F = np.load('faces_gt.npy')
E=set()
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)): E.add((min(u,v),max(u,v)))

print('P11 rows', len(P), 'GT rows', len(G))

kd = cKDTree(G)
d3, g3 = kd.query(P)
# 3D matches
m3 = {}
cnt = Counter()
for s,(dd,gg) in enumerate(zip(d3,g3)):
    if dd < 0.05: m3[s]=gg; cnt[gg]+=1
m3 = {s:g for s,g in m3.items() if cnt[g]==1}
print(f'3D<5cm unique matches: {len(m3)}')

# add XY-exact (yellow class: Z broken) where unique both ways
kdxy = cKDTree(G[:,:2])
dxy, gxy = kdxy.query(P[:,:2])
cnt2=Counter(); mxy={}
for s,(dd,gg) in enumerate(zip(dxy,gxy)):
    if s in m3: continue
    if dd < 0.002: mxy[s]=gg; cnt2[gg]+=1
used=set(m3.values())
mxy={s:g for s,g in mxy.items() if cnt2[g]==1 and g not in used}
print(f'+XY-exact unique (Z-drift class): {len(mxy)}')
map11 = dict(m3); map11.update(mxy)
print(f'map11 total: {len(map11)} / {len(P)}')

# validate: emission-adjacency edge rate (expect ~40% per alloc4/6)
adj=tot=0
for s in range(len(P)-1):
    if s in map11 and s+1 in map11:
        tot+=1
        if (min(map11[s],map11[s+1]),max(map11[s],map11[s+1])) in E: adj+=1
print(f'emission-adjacent mapped pairs: {tot}, GT-edge rate {100*adj/max(tot,1):.1f}% (expect ~40-60%)')

# validate against old map (thread.pkl slots = P_base indexing)
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
agree=dis=0
for s,g in map11.items():
    if s in slot2gt:
        if slot2gt[s]==g: agree+=1
        else: dis+=1
print(f'overlap with old 1113-map: agree {agree}, disagree {dis}')

# drift probe: does agreement fall off with slot index?
band=200
for lo in range(0,3000,600):
    a=d=0
    for s,g in map11.items():
        if lo<=s<lo+600 and s in slot2gt:
            if slot2gt[s]==g: a+=1
            else: d+=1
    print(f'  slots {lo}-{lo+600}: agree {a} disagree {d}')

gt2slot11={}
for s,g in map11.items(): gt2slot11[g]=s
pickle.dump((map11, gt2slot11), open('map11.pkl','wb'))
print('saved map11.pkl')
