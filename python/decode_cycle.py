#!/usr/bin/env python3
"""Structural decode: 0x60-tag = low-byte refinement of current axis (no new
coord); 0x20-tag = new coordinate. Y when the Y-candidate hits the sparse Y
grid; otherwise alternate X/Z. Emit a vertex on each Z. Measure recall."""
import sys, struct, pickle
import numpy as np

oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
variant=sys.argv[4] if len(sys.argv)>4 else 'A'
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
def key(): return (round(cur[0]*100),round(cur[1]*100),round(cur[2]*100))
decoded={key()}
toggle=0  # next non-Y new-coord axis: 0=X, 2=Z
last_axis=0
REFINE_TAGS={0x60,0x80,0x84,0x88,0xa3,0xfd}  # candidates for "refinement"
pos=8328+24
while pos<min(geo_end,BOUND):
    b=d[pos];
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); tag=last_tag; pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        cy=be(prev[1][:8-nb]+payload)
        is_refine = (variant in ('A','C')) and (tag in REFINE_TAGS)
        if is_refine:
            ax=last_axis
        elif near(cy,1):
            ax=1
        else:
            ax = toggle; toggle = 2 - toggle    # alternate 0<->2
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
        cur[ax]=be(prev[ax]); last_axis=ax
        if ax==2: decoded.add(key())
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1

inter=decoded & GT
print(f'variant {variant}: decoded={len(decoded):,}  GT={len(GT):,}  matched={len(inter):,}  '
      f'RECALL={len(inter)/len(GT)*100:.2f}%  PREC={len(inter)/max(1,len(decoded))*100:.2f}%')
