#!/usr/bin/env python3
"""MYSTERY A gate test 1 (MECHANISM VERIFICATION, GT used as answer key only).

Question: for the regular-regime motif pair (e003 ref-group r_k + e003 idless
group allocating n_k), is the idless group's C-op GATE TRIANGLE the strip quad
triangle (r_k, n_{k-1}, r_{k-1}), i.e. does the parallelogram
    pred(n_k) = G[r_k] + G[n_{k-1}] - G[r_{k-1}]
predict the allocated vertex? And do the two quad triangles exist in the GT
face set (which split)?

Chains come from alloc11 logic (GT-neighbor chained resolution — answer-key map,
mechanism testing only, per PARALLELOGRAM_PROOF.md practice).
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
F = np.load('faces_gt.npy')
gt = np.loadtxt('intercepts_gt.csv', delimiter=',')
# GT vertex table used by faces_gt indices:
# rebuild_gt built faces_gt over unique verts — need the same table.
# intercepts_gt.csv rows ARE that table (2975 rows) per RESUME-07-09.
G = gt

E=set(); nbr=defaultdict(set)
faceset=set()
for a,b,c in F:
    faceset.add(tuple(sorted((a,b,c))))
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

# alloc11 chained resolution
seqs={}
for rid,lst in byrail.items():
    n_prev=None; seq=[]
    for gi,r,_ in lst:
        cn=slotnb(r)
        if cn is None:
            n_prev=None; seq.append((gi,r,None,'unmapped')); continue
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
            if n_prev is not None:
                n=min(cc,key=lambda x:abs(x-n_prev))
                if abs(n-n_prev)<=3:
                    seq.append((gi,r,n,'chain')); n_prev=n; continue
            seq.append((gi,r,None,f'amb{len(cc)}')); n_prev=None
    seqs[rid]=seq

def gpos(slot):
    g=slot2gt.get(slot)
    return None if g is None else G[g]

# consecutive resolved pairs on a rail = quad sites
sites=[]  # (rid, gi_prev, gi, r_prev, n_prev, r, n)
for rid,seq in seqs.items():
    res=[(gi,r,n) for gi,r,n,st in seq if n is not None]
    for i in range(1,len(res)):
        if res[i][0]-res[i-1][0] < 60:
            sites.append((rid,res[i-1][0],res[i][0],res[i-1][1],res[i-1][2],res[i][1],res[i][2]))
print(f'quad sites (consecutive resolved allocs on a rail): {len(sites)}')

HALF=0.0625
hyp_err=defaultdict(list)
for rid,gp,gi,rp,np_,rk,nk in sites:
    Pr,Pn_,Prp,Pnk = gpos(rk),gpos(np_),gpos(rp),gpos(nk)
    if any(x is None for x in (Pr,Pn_,Prp,Pnk)): continue
    preds={
      'H1 quad  r_k+n_prev-r_prev': Pr+Pn_-Prp,
      'H0 null  n_prev            ': Pn_,
      'H2 mirror r_k+r_prev-n_prev': Pr+Prp-Pn_,
      'H3 rail  2*n_prev-? (skip)': None,
    }
    for h,p in preds.items():
        if p is None: continue
        hyp_err[h].append(np.linalg.norm(p-Pnk))
print('\n[GATE HYPOTHESES] 3D error of pred(n_k) vs GT position:')
for h,e in hyp_err.items():
    e=np.array(e)
    print(f'  {h}: n={len(e)} median {np.median(e):.4f} m  <{HALF} {np.mean(e<HALF)*100:.1f}%  <0.25m {np.mean(e<0.25)*100:.1f}%')

# also Z-only (the stored-low-window axis)
zerr=[]
for rid,gp,gi,rp,np_,rk,nk in sites:
    Pr,Pn_,Prp,Pnk = gpos(rk),gpos(np_),gpos(rp),gpos(nk)
    if any(x is None for x in (Pr,Pn_,Prp,Pnk)): continue
    zerr.append(abs((Pr+Pn_-Prp)[2]-Pnk[2]))
zerr=np.array(zerr)
print(f'  H1 Z-only: median {np.median(zerr):.4f}  <{HALF} {np.mean(zerr<HALF)*100:.1f}%')

# quad triangle split vs GT faces
def gid(s): return slot2gt.get(s)
splitA=splitB=both=neither=0; checked=0
triA_hit=triB_hit=0
for rid,gp,gi,rp,np_,rk,nk in sites:
    ids=[gid(x) for x in (rp,np_,rk,nk)]
    if any(x is None for x in ids): continue
    grp,gnp,grk,gnk=ids
    checked+=1
    # split A: (r_prev, r_k, n_prev) + (r_k, n_k, n_prev)
    a1=tuple(sorted((grp,grk,gnp))); a2=tuple(sorted((grk,gnk,gnp)))
    # split B: (r_prev, r_k, n_k) + (r_prev, n_k, n_prev)
    b1=tuple(sorted((grp,grk,gnk))); b2=tuple(sorted((grp,gnk,gnp)))
    inA=(a1 in faceset)+(a2 in faceset)
    inB=(b1 in faceset)+(b2 in faceset)
    triA_hit+=inA; triB_hit+=inB
    if inA==2 and inB<2: splitA+=1
    elif inB==2 and inA<2: splitB+=1
    elif inA==2 and inB==2: both+=1
    else: neither+=1
print(f'\n[QUAD->FACES vs GT] sites checked {checked}')
print(f'  split A (rp,rk,np)+(rk,nk,np): full-quad {splitA}, tri hits {triA_hit}/{2*checked}')
print(f'  split B (rp,rk,nk)+(rp,nk,np): full-quad {splitB}, tri hits {triB_hit}/{2*checked}')
print(f'  both {both}  neither {neither}')
