#!/usr/bin/env python3
"""Recover TRUE emission-slot indexing for P_v11 (2964 rows vs 2975 slots).
Locate dropped emissions: adjacent mapped v11 rows whose GT vertices are at
graph distance 2 (one vertex skipped) => a dropped emission between them.
Then true_slot = v11_row + n_drops_before. Validate: refs (true-slot indices)
should now satisfy the serpentine S-mirror + quad laws better than before.
Answer-key map construction (mechanism testing only).
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
F = np.load('faces_gt.npy')
G = np.loadtxt('intercepts_gt.csv', delimiter=',')
nbr=defaultdict(set)
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)): nbr[u].add(v); nbr[v].add(u)

def gdist(a,b,maxd=4):
    if a==b: return 0
    seen={a}; frontier={a}
    for d in range(1,maxd+1):
        nf=set()
        for x in frontier:
            for y in nbr[x]:
                if y==b: return d
                if y not in seen: seen.add(y); nf.add(y)
        frontier=nf
    return maxd+1

N=2964
# distances between consecutive mapped rows (allow gaps in map)
rows=sorted(map11)
dcen=Counter()
gap_sites=[]   # (row_i, row_j, graphdist, rowgap)
for i in range(len(rows)-1):
    a,b=rows[i],rows[i+1]
    if b-a>3: continue
    d=gdist(map11[a],map11[b])
    dcen[(b-a,d)]+=1
    if b-a==1 and d==2: gap_sites.append((a,b))
print('census (rowgap, graphdist):', sorted(dcen.items())[:20])
print(f'adjacent rows at graph distance 2 (drop candidates): {len(gap_sites)}')
print('drop candidate rows:', [a for a,b in gap_sites][:40])

# Are they clustered (each drop shifts everything after)? Expect ~11 real drops.
# Cross-check with the "insertion count" needed: 2975-2964 = 11.
# Refine: a real drop at row a means for ALL later rows true=row+1 more.
# Greedy: accept drops left-to-right, test global improvement via a ref law:
# same-group multi-ref pairs should be GT edges under true-slot map.
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
E=set()
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)): E.add((min(u,v),max(u,v)))

def build_true(drops):
    # true slot t -> v11 row: rows shift up by #drops<=row
    # map: true_slot -> GT
    drops=sorted(drops)
    tm={}
    for r,g in map11.items():
        sh=sum(1 for dr in drops if dr<=r)
        tm[r+sh]=g
    return tm

def samegroup_edge_rate(tm):
    hit=tot=0
    for g in groups:
        rs=g['refs']
        for i in range(1,len(rs)):
            a,b=tm.get(rs[i-1]),tm.get(rs[i])
            if a is None or b is None or a==b: continue
            tot+=1
            if (min(a,b),max(a,b)) in E: hit+=1
    return hit,tot

for name,drops in (('no drops',[]),('all candidates',[a for a,b in gap_sites])):
    tm=build_true(drops)
    h,t=samegroup_edge_rate(tm)
    print(f'same-group ref-pair GT-edge rate [{name}]: {h}/{t} = {100*h/max(t,1):.1f}%')

# greedy: try each candidate incrementally left-to-right, keep if rate improves
best=[]; tm=build_true(best); bh,bt=samegroup_edge_rate(tm); brate=bh/max(bt,1)
print(f'greedy start rate {100*brate:.1f}%')
for a,b in gap_sites:
    trial=sorted(best+[a])
    tm=build_true(trial)
    h,t=samegroup_edge_rate(tm)
    r=h/max(t,1)
    if r>=brate:
        best=trial; brate=r
print(f'greedy kept {len(best)} drops: {best}')
tm=build_true(best); h,t=samegroup_edge_rate(tm)
print(f'final same-group edge rate: {h}/{t} = {100*h/max(t,1):.1f}%')
pickle.dump((best,), open('drops11.pkl','wb'))
tmap={t_:g for t_,g in tm.items()}
gt2t={g:t_ for t_,g in tm.items()}
pickle.dump((tmap,gt2t,best), open('truemap.pkl','wb'))
print('saved truemap.pkl (true_slot->GT).  size', len(tmap))
