#!/usr/bin/env python3
"""Beam-align strip segments to the GT mesh (mechanism verification).

Per rail segment, beam search over hidden state n_gt (the current new-rail
vertex) through the event stream:
  R event: r_prev -> r_new ; reward if (gr_prev, gr_new, n_gt) is a GT face
  C event: n' = a tip of GT edge (gr, n_gt) ; reward 1  (C-face law)
           or RESET: n' = any GT neighbor of gr, penalty  (fold/strip re-entry)
Best path per segment = the aligned traversal. Outputs:
  - alignment quality (rewarded fraction)
  - slot-step census of C allocations along best paths (counter law + folds)
  - R-face law rate along best paths
  - fold/reset sites (gi) -> for op-byte census (ma_opcensus)
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
F = np.load('faces_gt.npy')
G = np.loadtxt('intercepts_gt.csv', delimiter=',')
faceset=set(tuple(sorted(f)) for f in F)
nbr=defaultdict(set); opp=defaultdict(list)
for a,b,c in F:
    for u,v,w in ((a,b,c),(b,c,a),(c,a,b)):
        opp[(min(u,v),max(u,v))].append(w)
        nbr[u].add(v); nbr[v].add(u)

g2 = {}
for gi,r,rid in ref_events: g2[gi]=(rid,r)
events=defaultdict(list)
last_rid=None
for gi,g in enumerate(groups):
    if g['refs']:
        if len(g['refs'])>10: last_rid=None; continue
        if gi in g2:
            rid,r=g2[gi]
            events[rid].append((gi,'R',g['refs'][-1]))
            last_rid=rid
        continue
    if g['delim']=='e003' and not g['refs'] and last_rid is not None:
        events[last_rid].append((gi,'C',None))

GAP=60; BEAM=16; RESET_PEN=0.75
def segments(ev):
    seg=[]; cur=[]
    for e in ev:
        if cur and e[0]-cur[-1][0]>GAP: seg.append(cur); cur=[]
        cur.append(e)
    if cur: seg.append(cur)
    return seg

def align(seg):
    # state: n_gt (or None); value: (score, path) path=[(gi,kind,n_gt,flag)]
    states={None:(0.0,[])}
    r_last=None
    for gi,k,r in seg:
        if k=='R':
            gr_prev=map11.get(r_last) if r_last is not None else None
            gr_new=map11.get(r)
            if gr_prev is not None and gr_new is not None and gr_prev!=gr_new:
                ns={}
                for n,(sc,path) in states.items():
                    add=1.0 if (n is not None and tuple(sorted((gr_prev,gr_new,n))) in faceset) else 0.0
                    ns[n]=(sc+add, path+[(gi,'R',n,add>0)])
                states=ns
            r_last=r
            continue
        gr=map11.get(r_last) if r_last is not None else None
        if gr is None:
            # lose track
            states={None:max(states.values(), key=lambda v:v[0])}
            states={None:(states[None][0], states[None][1]+[(gi,'C',None,False)])}
            continue
        ns={}
        def push(n2,sc,path,flag):
            if n2 not in ns or sc>ns[n2][0]: ns[n2]=(sc,path+[(gi,'C',n2,flag)])
        for n,(sc,path) in states.items():
            if n is not None:
                for t in opp.get((min(gr,n),max(gr,n)),[]):
                    if t==n: continue
                    push(t, sc+1.0, path, True)
            # reset branch
            for t in nbr[gr]:
                if t==n: continue
                push(t, sc-RESET_PEN, path, False)
        if not ns: ns={None:(max(v[0] for v in states.values()), [])}
        # beam prune
        top=sorted(ns.items(), key=lambda kv:-kv[1][0])[:BEAM]
        states=dict(top)
    return max(states.values(), key=lambda v:v[0])

stepc=Counter(); Rhit=Rchk=0; Chit=Cchk=0
resets=[]   # (gi, prev_slot, new_slot)
allocs=[]   # (gi, slot)
qual=[]
for rid,ev in events.items():
    for seg in segments(ev):
        if sum(1 for e in seg if e[1]=='C')<4: continue
        sc,path=align(seg)
        nC=sum(1 for p in path if p[1]=='C')
        nR=sum(1 for p in path if p[1]=='R')
        qual.append(sc/max(nC+nR,1))
        prev_slot=None
        for gi,k,n,flag in path:
            if k=='R':
                Rchk+=1; Rhit+=flag
            else:
                Cchk+=1; Chit+=flag
                s=gt2slot11.get(n) if n is not None else None
                if s is not None:
                    allocs.append((gi,s,flag))
                    if prev_slot is not None:
                        stepc[s-prev_slot]+=1
                        if not flag: resets.append((gi,prev_slot,s))
                    prev_slot=s
print(f'segments aligned: {len(qual)}, mean quality {np.mean(qual):.3f}, median {np.median(qual):.3f}')
print(f'C-face law along best paths: {Chit}/{Cchk} = {100*Chit/max(Cchk,1):.1f}%')
print(f'R-face law along best paths: {Rhit}/{Rchk} = {100*Rhit/max(Rchk,1):.1f}%')
print('C alloc slot-step census:', stepc.most_common(16))
tot=sum(stepc.values()); pm1=stepc[1]+stepc[-1]
print(f'  +-1 share {pm1}/{tot} = {100*pm1/max(tot,1):.1f}%')
print(f'reset (fold/re-entry) sites: {len(resets)}')
pickle.dump((allocs,resets), open('ma_beam_out.pkl','wb'))
print('saved ma_beam_out.pkl')
