#!/usr/bin/env python3
"""(a) Miss analysis: are the 10% misses off-by-one counter slips?
(b) GT-FREE S recovery: concurrent rail pairs with constant sums (no GT),
    compare against GT-fitted S values.
(c) Coverage: how many slots get a mirror edge under fitted S?"""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
F = np.load('faces_gt.npy')
E = set()
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)):
        E.add((min(u,v),max(u,v)))
def isedge(s1,s2):
    g1,g2 = slot2gt.get(s1), slot2gt.get(s2)
    if g1 is None or g2 is None: return None
    return (min(g1,g2),max(g1,g2)) in E

g2rail = {}
for gi, r, rid in ref_events: g2rail[gi] = (rid, r)
rail_sums = defaultdict(Counter)
items = []
for k, gi, r, cands in rows:
    rid = None
    for gj in range(gi-1, max(gi-5,-1), -1):
        if gj in g2rail and g2rail[gj][1]==r:
            rid = g2rail[gj][0]; break
    items.append((k,gi,r,rid,cands))
    for n in cands:
        if rid is not None and abs(n-r)>3: rail_sums[rid][n+r]+=1
fitS = {rid:c.most_common(1)[0][0] for rid,c in rail_sums.items() if c.most_common(1)[0][1]>=2}

# (a) miss analysis
res = Counter()
for k,gi,r,rid,cands in items:
    if rid not in fitS: continue
    n = fitS[rid]-r
    e = isedge(r,n)
    if e is None: continue
    if e: res['hit']+=1; continue
    for dd in (1,-1,2,-2,3,-3):
        if isedge(r,n+dd):
            res[f'off{dd:+d}']+=1; break
    else:
        res['far']+=1
print('(a) miss decomposition:', dict(res))

# (b) GT-free S: concurrent big-rail pairs with constant sum
big = [r for r in rails if len(r['vals'])>=4]
gtfree_S = {}
for i in range(len(big)):
    for j in range(len(big)):
        if i==j: continue
        a,b_ = big[i], big[j]
        ga=(a['vals'][0][0],a['vals'][-1][0]); gb=(b_['vals'][0][0],b_['vals'][-1][0])
        lo,hi = max(ga[0],gb[0]), min(ga[1],gb[1])
        if hi-lo<4: continue
        va=[(g,r) for g,r in a['vals'] if lo<=g<=hi]
        vb=[(g,r) for g,r in b_['vals'] if lo<=g<=hi]
        if len(va)<3 or len(vb)<3: continue
        sums=[]
        for g,r in va:
            g2,r2 = min(vb,key=lambda x:abs(x[0]-g))
            sums.append(r+r2)
        sums=np.array(sums)
        if sums.std()<=1.5:
            aid=a['id']
            if aid not in gtfree_S or sums.std()<gtfree_S[aid][1]:
                gtfree_S[aid]=(int(round(sums.mean())), float(sums.std()), b_['id'])
print(f'\n(b) GT-free S for {len(gtfree_S)} rails (of {len(big)} big rails)')
agree=close=far=0
for rid,(S,sd,pid) in gtfree_S.items():
    if rid in fitS:
        d=abs(S-fitS[rid])
        if d==0: agree+=1
        elif d<=2: close+=1
        else: far+=1
print(f'  vs GT-fitted: exact {agree}, within2 {close}, far {far}')

# score GT-free S on motif pairs
chk=hit=0
for k,gi,r,rid,cands in items:
    if rid not in gtfree_S: continue
    n = gtfree_S[rid][0]-r
    e = isedge(r,n)
    if e is None: continue
    chk+=1; hit += bool(e)
print(f'  GT-FREE serpentine score: {hit}/{chk} = {hit/max(chk,1)*100:.1f}%')

# (c) coverage under fitted S (GT-fit + GT-free union)
allS = dict(fitS)
for rid,(S,_,_) in gtfree_S.items(): allS.setdefault(rid,S)
cov=set()
for k,gi,r,rid,cands in items:
    if rid in allS:
        n=allS[rid]-r
        if 0<=n<2975: cov.add(n); cov.add(r)
print(f'\n(c) slots touched by mirror edges: {len(cov)}/2975; '
      f'rails with S: {len(allS)}')
