#!/usr/bin/env python3
"""Full vertex decode + recall/precision vs ground truth.
Walk the coord section, per-axis running prev, greedy grid axis assignment,
emit a vertex on each Z-update. Measure how much of the surface we recover."""
import sys, struct, pickle
import numpy as np

oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
with open(f'{cachedir}/gt_keys.pkl','rb') as f: GT=pickle.load(f)
def near(v,ax,tol=0.006):
    a=gt[ax]; i=np.searchsorted(a,v)
    if i<=0: return abs(a[0]-v)<tol
    if i>=len(a): return abs(a[-1]-v)<tol
    return min(abs(a[i]-v),abs(a[i-1]-v))<tol
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07

prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
decoded=set()
def key(x,y,z): return (round(x*100),round(y*100),round(z*100))
decoded.add(key(*cur))
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
        if ax==2:
            decoded.add(key(cur[0],cur[1],cur[2]))
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1

inter=decoded & GT
print(f'decoded vertices (unique keys): {len(decoded):,}')
print(f'ground-truth vertices         : {len(GT):,}')
print(f'matched (decoded AND GT)        : {len(inter):,}')
print(f'RECALL    (matched/GT)        : {len(inter)/len(GT)*100:.2f}%')
print(f'PRECISION (matched/decoded)   : {len(inter)/len(decoded)*100:.2f}%')
