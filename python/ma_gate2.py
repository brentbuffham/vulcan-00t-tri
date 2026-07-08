#!/usr/bin/env python3
"""MYSTERY A gate test 2 — strict adjacency.

Fix ma_gate1's site contamination: only motif pairs that are ADJACENT events on
their rail (no unresolved event in between), so (r_prev,n_prev)->(r_k,n_k) is a
true single strip step. Also classify by (dr, dn) step and score H1 per class.
And: bypass chains entirely with the counter view — n_k = n_prev - d where
d = -(rail direction): score H1 with n_prev from chain and n_k = n_prev+-1.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
F = np.load('faces_gt.npy')
G = np.loadtxt('intercepts_gt.csv', delimiter=',')

E=set(); nbr=defaultdict(set); faceset=set()
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

seqs={}
for rid,lst in byrail.items():
    n_prev=None; seq=[]
    for gi,r,_ in lst:
        cn=slotnb(r)
        if cn is None:
            n_prev=None; seq.append((gi,r,None)); continue
        if n_prev is not None:
            pn=slotnb(n_prev)
            cc = cn & pn if pn else cn
            cc = {x for x in cc if x!=n_prev}
        else:
            cc = {x for x in cn if abs(x-r)>3}
        if len(cc)==1:
            n=cc.pop(); seq.append((gi,r,n)); n_prev=n
        elif len(cc)==0:
            seq.append((gi,r,None)); n_prev=None
        else:
            if n_prev is not None:
                n=min(cc,key=lambda x:abs(x-n_prev))
                if abs(n-n_prev)<=3:
                    seq.append((gi,r,n)); n_prev=n; continue
            seq.append((gi,r,None)); n_prev=None
    seqs[rid]=seq

def gpos(slot):
    g=slot2gt.get(slot)
    return None if g is None else G[g]
def gid(s): return slot2gt.get(s)

# STRICT: adjacent seq entries both resolved
sites=[]
for rid,seq in seqs.items():
    for i in range(1,len(seq)):
        gp,rp,npv=seq[i-1]; gi,rk,nk=seq[i]
        if npv is None or nk is None: continue
        if gi-gp>=60: continue
        sites.append((rid,gp,gi,rp,npv,rk,nk))
print(f'strict-adjacent quad sites: {len(sites)}')

HALF=0.0625
bycls=defaultdict(list)
face_bycls=defaultdict(lambda:[0,0,0])   # [full-quad-A hits, tri hits, count]
for rid,gp,gi,rp,npv,rk,nk in sites:
    Pr,Pn_,Prp,Pnk = gpos(rk),gpos(npv),gpos(rp),gpos(nk)
    if any(x is None for x in (Pr,Pn_,Prp,Pnk)): continue
    dr,dn = rk-rp, nk-npv
    cls=(dr,dn)
    e=np.linalg.norm(Pr+Pn_-Prp-Pnk)
    bycls[cls].append(e)
    ids=[gid(x) for x in (rp,npv,rk,nk)]
    if all(x is not None for x in ids):
        grp,gnp,grk,gnk=ids
        a1=tuple(sorted((grp,grk,gnp))); a2=tuple(sorted((grk,gnk,gnp)))
        b1=tuple(sorted((grp,grk,gnk))); b2=tuple(sorted((grp,gnk,gnp)))
        fc=face_bycls[cls]
        fc[0]+= (a1 in faceset)+(a2 in faceset)
        fc[1]+= (b1 in faceset)+(b2 in faceset)
        fc[2]+=1

print('\n[H1 by step class (dr,dn)]  err = |r_k+n_prev-r_prev - n_k| 3D:')
tot=0; tothit=0
for cls in sorted(bycls, key=lambda c:-len(bycls[c])):
    e=np.array(bycls[cls]); fA,fB,fn=face_bycls[cls]
    hit=(e<HALF).sum(); tot+=len(e); tothit+=hit
    print(f'  (dr,dn)={cls}: n={len(e)} median {np.median(e):.4f}  <HALF {hit}/{len(e)}'
          f'   facesA {fA}/{2*fn} facesB {fB}/{2*fn}')
print(f'  TOTAL: {tothit}/{tot} = {100*tothit/max(tot,1):.1f}% within half-window')
