#!/usr/bin/env python3
"""GT-FREE S recovery via rail handoff: for earlier rail a and later rail b,
candidate S from range endpoints; vote = |{r_b} ∩ {S - r_a}| (window +-3 on S).
Keep best (b,S) per a; compare against GT-fitted S. GT used ONLY to score."""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
F = np.load('faces_gt.npy')
E=set()
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)):
        E.add((min(u,v),max(u,v)))
def isedge(s1,s2):
    g1,g2=slot2gt.get(s1),slot2gt.get(s2)
    if g1 is None or g2 is None: return None
    return (min(g1,g2),max(g1,g2)) in E

g2rail={}
for gi,r,rid in ref_events: g2rail[gi]=(rid,r)
rail_sums=defaultdict(Counter); items=[]
for k,gi,r,cands in rows:
    rid=None
    for gj in range(gi-1,max(gi-5,-1),-1):
        if gj in g2rail and g2rail[gj][1]==r: rid=g2rail[gj][0]; break
    items.append((k,gi,r,rid,cands))
    for n in cands:
        if rid is not None and abs(n-r)>3: rail_sums[rid][n+r]+=1
fitS={rid:c.most_common(1)[0][0] for rid,c in rail_sums.items() if c.most_common(1)[0][1]>=2}

big=[r for r in rails if len(r['vals'])>=4]
print('big rails:', len(big))
def span(r):
    v=[x[1] for x in r['vals']]; return min(v),max(v)
def tspan(r):
    return r['vals'][0][0], r['vals'][-1][0]

hand={}
for a in big:
    ta0,ta1=tspan(a); alo,ahi=span(a)
    aset=set(x[1] for x in a['vals'])
    best=None
    for b in big:
        if b['id']==a['id']: continue
        tb0,tb1=tspan(b)
        if tb0 < ta0 + 5: continue          # b must start AFTER a starts
        blo,bhi=span(b)
        # S candidates from endpoint sums
        for S0 in (alo+bhi, ahi+blo):
            for S in range(S0-3, S0+4):
                bset=set(x[1] for x in b['vals'])
                inter=sum(1 for rb in bset if (S-rb) in aset)
                frac=inter/min(len(aset),len(bset))
                if best is None or (inter,frac)>(best[0],best[1]):
                    best=(inter,frac,S,b['id'])
    if best and best[0]>=3 and best[1]>=0.4:
        hand[a['id']]=best
print(f'handoff S found for {len(hand)} rails')

agree=off1=off2=far=0
for rid,(inter,frac,S,bid) in hand.items():
    if rid in fitS:
        dd=abs(S-fitS[rid])
        if dd==0: agree+=1
        elif dd<=1: off1+=1
        elif dd<=2: off2+=1
        else: far+=1
print(f'vs GT-fitted S ({sum([agree,off1,off2,far])} comparable): exact {agree}, +-1 {off1}, +-2 {off2}, far {far}')

# score motif pairs with handoff-S (GT-free) mirror rule
chk=hit=0
for k,gi,r,rid,cands in items:
    if rid not in hand: continue
    n=hand[rid][2]-r
    e=isedge(r,n)
    if e is None: continue
    chk+=1
    if e: hit+=1
    else:
        for dd in (1,-1):
            if isedge(r,n+dd): hit+=0  # count strict only
print(f'GT-FREE handoff mirror score: {hit}/{chk} = {hit/max(chk,1)*100:.1f}%')
