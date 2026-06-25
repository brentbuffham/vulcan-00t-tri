#!/usr/bin/env python3
"""Recall test with GRID SNAPPING. The .00t stores full-precision doubles; the
GT CSV is snapped to the DTM grid (X/Y ~0.25 m, Z ~0.01 m). Keying raw doubles
can never match GT. So snap each decoded axis to its nearest GT grid value
(within tol) BEFORE keying. This isolates 'is the decode right?' from 'does the
float happen to round to the same 0.01 bucket?'."""
import sys, struct, pickle
import numpy as np

oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
with open(f'{cachedir}/gt_keys.pkl','rb') as f: GT=pickle.load(f)
# per-axis snap tolerance: half the median grid step
TOL={0:0.30,1:0.30,2:0.02}
def snap(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v)
    cands=[]
    if i<len(a): cands.append(a[i])
    if i>0: cands.append(a[i-1])
    if not cands: return None
    best=min(cands,key=lambda c:abs(c-v))
    return best if abs(best-v)<=TOL[ax] else None
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
def near(v,ax,tol=0.006):
    a=gt[ax]; i=np.searchsorted(a,v)
    if i<=0: return abs(a[0]-v)<tol
    if i>=len(a): return abs(a[-1]-v)<tol
    return min(abs(a[i]-v),abs(a[i-1]-v))<tol

prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
decoded=set()
def emit():
    sx=snap(cur[0],0); sy=snap(cur[1],1); sz=snap(cur[2],2)
    if sx is None or sy is None or sz is None: return
    decoded.add((round(sx*100),round(sy*100),round(sz*100)))
emit()
pos=8328+24
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        if near(cx,0): ax,val=0,cx
        elif near(cy,1): ax,val=1,cy
        elif 511<=cz<=543: ax,val=2,cz
        else: continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]; cur[ax]=val
        if ax==2: emit()
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1

inter=decoded & GT
print(f'decoded (snapped, unique): {len(decoded):,}')
print(f'ground-truth             : {len(GT):,}')
print(f'matched                  : {len(inter):,}')
print(f'RECALL                   : {len(inter)/len(GT)*100:.2f}%')
print(f'PRECISION                : {len(inter)/max(1,len(decoded))*100:.2f}%')
