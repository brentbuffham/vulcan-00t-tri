#!/usr/bin/env python3
"""Teacher-forced decomposition of the CR machine (mechanism verification).

At each C event, instead of the counter, teacher-force n_new = the slot whose
GT vertex completes a face (r_last_gt, n_last_gt, x) — measures each law
separately:
  L1: does a completing GT vertex exist & how often unique?     (C-face law)
  L2: step census n_new - n_last (slot space)                    (counter law + folds)
  L3: with teacher-forced n_last, is (r_prev, r_new, n_last) a GT face? (R-face law)
  L4: parallelogram: is the C tip predicted by G[r]+G[n_last]-G[third of gate]?
GT used as answer key throughout — this is mechanism measurement, not a decode.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
F = np.load('faces_gt.npy')
G = np.loadtxt('intercepts_gt.csv', delimiter=',')
faceset=set(tuple(sorted(f)) for f in F)
nbr=defaultdict(set)
opp=defaultdict(list)   # sorted edge -> tips
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

GAP=60
def segments(ev):
    seg=[]; cur=[]
    for e in ev:
        if cur and e[0]-cur[-1][0]>GAP: seg.append(cur); cur=[]
        cur.append(e)
    if cur: seg.append(cur)
    return seg

L1=Counter(); steps=Counter(); L3=Counter(); L4=Counter()
HALF=0.0625
gap_after_fold=Counter()
for rid,ev in events.items():
    for seg in segments(ev):
        r_last=None; n_last_gt=None; n_last_slot=None
        for gi,k,r in seg:
            if k=='R':
                if r_last is not None and n_last_gt is not None:
                    gr_prev=map11.get(r_last); gr_new=map11.get(r)
                    if gr_prev is not None and gr_new is not None and gr_prev!=gr_new:
                        L3['chk']+=1
                        L3['hit']+= tuple(sorted((gr_prev,gr_new,n_last_gt))) in faceset
                r_last=r; continue
            if r_last is None: continue
            gr=map11.get(r_last)
            if gr is None:
                L1['r_unmapped']+=1; continue
            if n_last_gt is None:
                # seed: unknown previous n; skip (counted)
                # try: any neighbor x of gr that is mapped and forms face later
                L1['seed']+=1
                # cannot force without n_last; skip until an R..? take none
                # bootstrap: choose nothing
                # allow re-seed from next C
                # (n stays None until we seed from a resolved face below)
                # try seeding via unique slot-adjacent mapped neighbor pair:
                cands=[x for x in nbr[gr] if x in gt2slot11]
                # a fan seed would be ambiguous; skip
                if len(cands)==1:
                    n_last_gt=cands[0]; n_last_slot=gt2slot11[cands[0]]
                continue
            # teacher-force n_new: tips of edge (gr, n_last_gt), excluding used
            tips=[t for t in opp[(min(gr,n_last_gt),max(gr,n_last_gt))]]
            tips=[t for t in tips if t!=n_last_gt]
            if not tips:
                L1['no_face']+=1; n_last_gt=None; n_last_slot=None; continue
            if len(tips)==1:
                L1['unique']+=1; tip=tips[0]
            else:
                L1['multi']+=1
                # prefer the tip that is slot-adjacent to n_last
                pick=None
                for t in tips:
                    if t in gt2slot11 and n_last_slot is not None and abs(gt2slot11[t]-n_last_slot)<=3:
                        pick=t; break
                tip=pick if pick is not None else tips[0]
            # L4 parallelogram: gate tri = the OTHER tip of edge (gr,n_last)?
            others=[t for t in opp[(min(gr,n_last_gt),max(gr,n_last_gt))] if t!=tip]
            if others:
                pred=G[gr]+G[n_last_gt]-G[others[0]]
                e=np.linalg.norm(pred-G[tip])
                L4['chk']+=1; L4['hit']+= e<0.25; L4['half']+= e<HALF
            if tip in gt2slot11 and n_last_slot is not None:
                steps[gt2slot11[tip]-n_last_slot]+=1
            n_last_gt=tip
            n_last_slot=gt2slot11.get(tip, n_last_slot)
print('L1 (C-face completion):', dict(L1))
print('L2 step census (slot space, teacher-forced):', steps.most_common(14))
tot=sum(steps.values()); pm1=steps[1]+steps[-1]
print(f'   +-1 share: {pm1}/{tot} = {100*pm1/max(tot,1):.1f}%')
print(f"L3 (R-face law): {L3['hit']}/{L3['chk']} = {100*L3['hit']/max(L3['chk'],1):.1f}%")
print(f"L4 (C parallelogram across gate): <0.25m {L4['hit']}/{L4['chk']} = {100*L4['hit']/max(L4['chk'],1):.1f}%   <half {L4['half']} ({100*L4['half']/max(L4['chk'],1):.1f}%)")
