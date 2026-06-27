#!/usr/bin/env python3
"""Supervised robust assembler. Values decode correctly; the problem is per-record
AXIS + vertex boundaries (cascade after dedup/escape). Use grid-landing to pick the
axis robustly (splice into each axis; the correct one lands on its coarse grid, wrong
ones miss; nb<=3 prefers Z), update ONLY that axis (no cascade). Emit snapshot each
record. Tabulate (tagclass,nb)->axis to extract the GT-FREE rule. GT = scoring/label."""
import sys, struct, pickle
import numpy as np
from collections import Counter, defaultdict
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 26_222_853
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
def gdist(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(abs(a[i]-v))
    if i>0:c.append(abs(a[i-1]-v))
    return min(c) if c else 9e9
def gsnap(v,ax,tol):
    a=gt[ax]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(a[i])
    if i>0:c.append(a[i-1])
    if not c: return None
    b=min(c,key=lambda x:abs(x-v)); return b if abs(b-v)<=tol else None
SNAP={0:0.08,1:0.12,2:0.02}
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
def splice(ax,payload,nb):
    if payload[0] in FULL_IND: return (payload+b'\x00'*(8-nb))
    return bytes(prev[ax][:8-nb])+payload
decoded=set(); rule=defaultdict(Counter); assigned=Counter(); nrec=0; unresolved=0
def emit():
    k=(gsnap(cur[0],0,SNAP[0]),gsnap(cur[1],1,SNAP[1]),gsnap(cur[2],2,SNAP[2]))
    if None in k: return
    decoded.add((round(k[0]*100),round(k[1]*100),round(k[2]*100)))
emit()
pos=8352; last_tag=0x20
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            nrec+=1; cls=last_tag&0xE0
            # candidate axes by grid-landing of the splice
            cand=[]
            for ax in range(3):
                v=be(splice(ax,payload,nb)); dd=gdist(v,ax)
                cand.append((ax,v,dd))
            # nb-based axis preference: nb<=3 -> Z first; nb>=4 -> X/Y first
            order=[2,0,1] if nb<=3 else [0,1,2]
            tolm={0:0.08,1:0.12,2:0.004}
            chosen=None
            for ax in order:
                dd=cand[ax][2]
                if dd<=tolm[ax]: chosen=ax; break
            if chosen is None:
                # fallback: min grid distance, weighted (penalize Z so it's not always)
                w=[cand[0][2],cand[1][2],cand[2][2]*30]
                chosen=int(np.argmin(w)); unresolved+=1
            prev[chosen][:]=splice(chosen,payload,nb); cur[chosen]=be(prev[chosen])
            rule[(hex(cls),nb)][chosen]+=1; assigned[chosen]+=1
            emit()
        pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
inter=decoded&GT
print(f'records={nrec:,}  assigned X={assigned[0]:,} Y={assigned[1]:,} Z={assigned[2]:,}  unresolved={unresolved:,}')
print(f'decoded={len(decoded):,}  GT={len(GT):,}  matched={len(inter):,}  RECALL={len(inter)/len(GT)*100:.2f}%')
print('\n(tagclass,nb) -> axis  [X,Y,Z]  (top 20):')
for k in sorted(rule, key=lambda x:-sum(rule[x].values()))[:20]:
    c=rule[k]; tot=sum(c.values()); top=max(range(3),key=lambda a:c[a])
    print(f'  {k}: X={c[0]} Y={c[1]} Z={c[2]}  -> {"XYZ"[top]} {c[top]/tot*100:.0f}% (n={tot})')
