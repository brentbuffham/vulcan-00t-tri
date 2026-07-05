#!/usr/bin/env python3
"""Chained quad reconstruction of true allocation sequences.
For each motif pair on a rail: candidate n must be GT-neighbor of r AND
GT-neighbor of the rail's previous allocation n_prev (quad diagonal).
Seed rails at unambiguous single-constraint sites. Output: clean per-rail
(gi, n_true) sequences + step census + INIT list; re-census ops on clean data;
check n0 vs S parity (S = 2*fold+1?) and n0 vs concurrent fold centers."""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
F = np.load('faces_gt.npy')
E=set(); nbr=defaultdict(set)
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)):
        E.add((min(u,v),max(u,v))); nbr[u].add(v); nbr[v].add(u)

g2rail={}
for gi,r,rid in ref_events: g2rail[gi]=(rid,r)
items=[]
for k,gi,r,cands in rows:
    rid=None
    for gj in range(gi-1,max(gi-5,-1),-1):
        if gj in g2rail and g2rail[gj][1]==r: rid=g2rail[gj][0]; break
    items.append((k,gi,r,rid,cands))

byrail=defaultdict(list)
for k,gi,r,rid,cands in items:
    if rid is not None: byrail[rid].append((gi,r,cands))

def slotnb(r):
    g=slot2gt.get(r)
    if g is None: return None
    return set(gt2slot[v] for v in nbr[g] if v in gt2slot)

seqs={}
for rid,lst in byrail.items():
    n_prev=None; seq=[]
    for gi,r,_ in lst:
        cn=slotnb(r)
        if cn is None:
            n_prev=None; seq.append((gi,r,None,'unmapped')); continue
        # drop same-rail slots (r+-3) as quad-new candidates? keep, filter by chain
        if n_prev is not None:
            pn=slotnb(n_prev)
            cc = cn & pn if pn else cn
            cc = {x for x in cc if x!=n_prev}
        else:
            cc = {x for x in cn if abs(x-r)>3}
        if len(cc)==1:
            n=cc.pop(); seq.append((gi,r,n,'ok')); n_prev=n
        elif len(cc)==0:
            seq.append((gi,r,None,'none')); n_prev=None
        else:
            # ambiguous: if chain active, pick closest to n_prev+-1
            if n_prev is not None:
                n=min(cc,key=lambda x:abs(x-n_prev))
                if abs(n-n_prev)<=3:
                    seq.append((gi,r,n,'chain')); n_prev=n; continue
            seq.append((gi,r,None,f'amb{len(cc)}')); n_prev=None
    seqs[rid]=seq

stat=Counter(s[3] for q in seqs.values() for s in q)
print('resolution census:', stat.most_common())

# step census on resolved chains
steps=Counter()
inits=[]
for rid,seq in seqs.items():
    res=[(gi,n) for gi,r,n,st in seq if n is not None]
    for i in range(1,len(res)):
        if res[i][0]-res[i-1][0] < 60:
            steps[res[i][1]-res[i-1][1]]+=1
    if res: inits.append((res[0][0], rid, res[0][1]))
print('clean step census top12:', steps.most_common(12))

# op census with clean events
firstop=defaultdict(Counter)
for rid,seq in seqs.items():
    res=[(gi,n) for gi,r,n,st in seq if n is not None]
    for i,(gi,n) in enumerate(res):
        if i==0: cls='INIT'
        else:
            st=n-res[i-1][1]
            cls='CONT' if abs(st)==1 else ('STAY' if st==0 else f'JUMP')
        g=groups[gi]
        if g['ops']: firstop[cls][f"{g['ops'][0][0]:02x}:{g['ops'][0][1]:02x}"]+=1
for cls in firstop:
    print(f'{cls}: {sum(firstop[cls].values())} events, first-op top6: {firstop[cls].most_common(6)}')

# n0 list
inits.sort()
print('\nINIT (gi, rid, n0):', inits[:30])
