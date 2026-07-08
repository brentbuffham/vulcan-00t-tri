#!/usr/bin/env python3
"""MYSTERY A gate test 3 — full-density (map11) chain + gate + face-split census.

Rebuild motif pairs and alloc11-style chains with the 1931-slot v11 answer map.
For each strict-adjacent pair/triple on a rail:
  - class (dr, dn)
  - H1 quad gate:  pred = G[r_k]+G[n_prev]-G[r_prev]      (serpentine step)
  - Hf fan gate:   pred = G[r_k]+G[n_prev]-G[n_prev2]     (dr=0, needs triple)
  - face membership of split A / split B triangles per class
Mechanism verification (GT as answer key only).
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
F = np.load('faces_gt.npy')
G = np.loadtxt('intercepts_gt.csv', delimiter=',')

nbr=defaultdict(set); faceset=set(); E=set()
for a,b,c in F:
    faceset.add(tuple(sorted((a,b,c))))
    for u,v in ((a,b),(b,c),(c,a)):
        E.add((min(u,v),max(u,v))); nbr[u].add(v); nbr[v].add(u)

# ---- motif pairs: idless e003 groups paired with last preceding ref ----
g2rail={}
for gi,r,rid in ref_events: g2rail[gi]=(rid,r)

pairs=[]   # (gi_idless, r, rid)
last_ref=None; last_rid=None
for gi,g in enumerate(groups):
    if g['refs']:
        if len(g['refs'])>10: last_ref=None; last_rid=None; continue  # misparse blob
        last_ref=g['refs'][-1]
        last_rid=g2rail.get(gi,(None,None))[0]
        continue
    if g['delim']=='e003' and not g['refs'] and last_ref is not None:
        pairs.append((gi,last_ref,last_rid))
print(f'idless e003 pairs with a preceding ref: {len(pairs)}')

def slotnb(r):
    g=map11.get(r)
    if g is None: return None
    return set(gt2slot11[v] for v in nbr[g] if v in gt2slot11)

byrail=defaultdict(list)
for gi,r,rid in pairs:
    if rid is not None: byrail[rid].append((gi,r))

seqs={}
for rid,lst in byrail.items():
    n_prev=None; seq=[]
    for gi,r in lst:
        cn=slotnb(r)
        if cn is None:
            n_prev=None; seq.append((gi,r,None)); continue
        if n_prev is not None:
            pn=slotnb(n_prev)
            cc = cn & pn if pn else set()
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

nres=sum(1 for q in seqs.values() for s in q if s[2] is not None)
print(f'resolved allocations: {nres} / {sum(len(q) for q in seqs.values())}')

def gpos(s):
    g=map11.get(s); return None if g is None else G[g]
def gid(s): return map11.get(s)

HALF=0.0625
sites=[]; triples=[]
for rid,seq in seqs.items():
    for i in range(1,len(seq)):
        gp,rp,npv=seq[i-1]; gi,rk,nk=seq[i]
        if npv is None or nk is None or gi-gp>=60: continue
        sites.append((rid,gp,gi,rp,npv,rk,nk))
        if i>=2 and seq[i-2][2] is not None and gp-seq[i-2][0]<60:
            triples.append((rid,seq[i-2],seq[i-1],seq[i]))
print(f'strict-adjacent pair sites: {len(sites)}, triples: {len(triples)}')

bycls=defaultdict(list)
face_bycls=defaultdict(lambda:[0,0,0,0,0])  # a1,a2,b1,b2,count
for rid,gp,gi,rp,npv,rk,nk in sites:
    P=[gpos(x) for x in (rp,npv,rk,nk)]
    if any(x is None for x in P): continue
    Prp,Pnp,Prk,Pnk=P
    cls=(rk-rp, nk-npv)
    bycls[cls].append(np.linalg.norm(Prk+Pnp-Prp-Pnk))
    ids=[gid(x) for x in (rp,npv,rk,nk)]
    grp,gnp,grk,gnk=ids
    fc=face_bycls[cls]
    fc[0]+=tuple(sorted((grp,grk,gnp))) in faceset
    fc[1]+=tuple(sorted((grk,gnk,gnp))) in faceset
    fc[2]+=tuple(sorted((grp,grk,gnk))) in faceset
    fc[3]+=tuple(sorted((grp,gnk,gnp))) in faceset
    fc[4]+=1

print('\n[per class] H1 err + face membership (a1=rp,rk,np  a2=rk,nk,np  b1=rp,rk,nk  b2=rp,nk,np):')
for cls in sorted(bycls,key=lambda c:-len(bycls[c]))[:10]:
    e=np.array(bycls[cls]); a1,a2,b1,b2,n=face_bycls[cls]
    print(f'  (dr,dn)={cls}: n={len(e)} H1 median {np.median(e):.4f} <HALF {np.mean(e<HALF)*100:.0f}%'
          f'  | faces a1 {a1}/{n} a2 {a2}/{n} b1 {b1}/{n} b2 {b2}/{n}')

# fan gate on triples with dr=0 at the last step
fan_h1=[]; fan_hf=[]
for rid,(g2,r2,n2),(g1,r1,n1),(g0,r0,n0) in triples:
    if r0-r1!=0: continue
    P=[gpos(x) for x in (r0,n0,n1,n2,r1)]
    if any(x is None for x in P): continue
    Pr,Pn0,Pn1,Pn2,Prp=P
    fan_h1.append(np.linalg.norm(Pr+Pn1-Prp-Pn0))
    fan_hf.append(np.linalg.norm(Pr+Pn1-Pn2-Pn0))
fan_h1=np.array(fan_h1); fan_hf=np.array(fan_hf)
if len(fan_hf):
    print(f'\n[FAN dr=0, triples n={len(fan_hf)}]')
    print(f'  H1 (r+np-rp):  median {np.median(fan_h1):.4f}  <HALF {np.mean(fan_h1<HALF)*100:.1f}%')
    print(f'  Hf (r+np-np2): median {np.median(fan_hf):.4f}  <HALF {np.mean(fan_hf<HALF)*100:.1f}%')

# serpentine-step gate on triples (does np2 ever beat rp for |dr|=1?)
s_h1=[]; s_hf=[]
for rid,(g2,r2,n2),(g1,r1,n1),(g0,r0,n0) in triples:
    if abs(r0-r1)!=1: continue
    P=[gpos(x) for x in (r0,n0,n1,n2,r1)]
    if any(x is None for x in P): continue
    Pr,Pn0,Pn1,Pn2,Prp=P
    s_h1.append(np.linalg.norm(Pr+Pn1-Prp-Pn0))
    s_hf.append(np.linalg.norm(Pr+Pn1-Pn2-Pn0))
s_h1=np.array(s_h1); s_hf=np.array(s_hf)
if len(s_h1):
    print(f'\n[STEP |dr|=1, triples n={len(s_h1)}]')
    print(f'  H1 (r+np-rp):  median {np.median(s_h1):.4f}  <HALF {np.mean(s_h1<HALF)*100:.1f}%')
    print(f'  Hf (r+np-np2): median {np.median(s_hf):.4f}  <HALF {np.mean(s_hf<HALF)*100:.1f}%')

pickle.dump((seqs,sites,triples), open('ma_chains.pkl','wb'))
print('\nsaved ma_chains.pkl')
