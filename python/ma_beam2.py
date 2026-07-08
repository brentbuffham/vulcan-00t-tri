#!/usr/bin/env python3
"""Beam-align v2 — TRIANGLE-STRIP LAW (merged vertex sequence).

LAW under test: per strip, maintain vertex sequence; a REF group appends its
explicit ref vertex; an IDLESS group appends a new vertex; EVERY group emits
one triangle = the last 3 vertices of the sequence. (Zigzag => quad split A/B
by phase; fans and phase flips automatic.)

Beam state: (v1, v2) = last two GT vertex ids (hidden where unmapped).
  R event (ref r, gr = GT id): new state (v2, gr); reward if {v1,v2,gr} in F.
  C event: t must satisfy {v1,v2,t} in F  => t in tips(v1,v2); reward 1.
           RESET branch: t in nbr[v2], penalty (fold/strip re-entry).
Outputs: alignment quality, face-law rates by kind, allocation slots, phase
census, reset sites.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
F = np.load('faces_gt.npy')
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

GAP=60; BEAM=24; RESET_PEN=0.75
def segments(ev):
    seg=[]; cur=[]
    for e in ev:
        if cur and e[0]-cur[-1][0]>GAP: seg.append(cur); cur=[]
        cur.append(e)
    if cur: seg.append(cur)
    return seg

def align(seg):
    states={(None,None):(0.0,[])}
    for gi,k,r in seg:
        ns={}
        def push(key,sc,path):
            if key not in ns or sc>ns[key][0]: ns[key]=(sc,path)
        if k=='R':
            gr=map11.get(r)
            for (v1,v2),(sc,path) in states.items():
                if gr is None:
                    push((v2,None),sc,path+[(gi,'R',None,False)])
                    continue
                rew = 1.0 if (v1 is not None and v2 is not None and
                              tuple(sorted((v1,v2,gr))) in faceset) else 0.0
                push((v2,gr), sc+rew, path+[(gi,'R',gr,rew>0)])
        else:
            for (v1,v2),(sc,path) in states.items():
                if v1 is not None and v2 is not None:
                    for t in opp.get((min(v1,v2),max(v1,v2)),[]):
                        if t==v1 or t==v2: continue
                        push((v2,t), sc+1.0, path+[(gi,'C',t,True)])
                if v2 is not None:
                    for t in nbr[v2]:
                        if t==v2 or t==v1: continue
                        push((v2,t), sc-RESET_PEN, path+[(gi,'C',t,False)])
                else:
                    push((v2,None), sc-0.1, path+[(gi,'C',None,False)])
        if not ns: ns={(None,None):(0.0,[])}
        top=sorted(ns.items(), key=lambda kv:-kv[1][0])[:BEAM]
        states=dict(top)
    return max(states.values(), key=lambda v:v[0])

stepc=Counter(); Rhit=Rchk=0; Chit=Cchk=0
resets=[]; allocs=[]; qual=[]; seglist=[]
for rid,ev in events.items():
    for seg in segments(ev):
        if sum(1 for e in seg if e[1]=='C')<4: continue
        sc,path=align(seg)
        n_ev=len(path)
        qual.append(sc/max(n_ev,1))
        seglist.append((rid,seg[0][0],seg[-1][0],n_ev,sc/max(n_ev,1)))
        prev_slot=None
        for gi,k,t,flag in path:
            if k=='R': Rchk+=1; Rhit+=flag
            else:
                Cchk+=1; Chit+=flag
                s=gt2slot11.get(t) if t is not None else None
                if s is not None:
                    allocs.append((gi,s,flag))
                    if prev_slot is not None:
                        stepc[s-prev_slot]+=1
                        if not flag: resets.append((gi,prev_slot,s))
                    prev_slot=s
print(f'segments aligned: {len(qual)}, mean quality {np.mean(qual):.3f}, median {np.median(qual):.3f}')
print(f'C-face law (strip-triple): {Chit}/{Cchk} = {100*Chit/max(Cchk,1):.1f}%')
print(f'R-face law (strip-triple): {Rhit}/{Rchk} = {100*Rhit/max(Rchk,1):.1f}%')
print('C alloc slot-step census:', stepc.most_common(14))
tot=sum(stepc.values()); pm1=stepc[1]+stepc[-1]
print(f'  +-1 share {pm1}/{tot} = {100*pm1/max(tot,1):.1f}%')
print(f'resets: {len(resets)}')
qq=sorted(seglist,key=lambda x:-x[4])
print('best segments:', qq[:8])
print('worst segments:', qq[-8:])
pickle.dump((allocs,resets,seglist), open('ma_beam2_out.pkl','wb'))
