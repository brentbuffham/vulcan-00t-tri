#!/usr/bin/env python3
"""Track real Y CHANGES (value moves >0.1 m) under v3 grammar. Count them vs
2907 GT rows. Report the distribution of Y-step sizes (should be ~0.25 if row
advance) and the byte signature (preceding 6 bytes) at each change."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
def near(v,a,t=0.006):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
curY=be(prev[1])
changes=0; steps=Counter(); nbc=Counter(); tagc=Counter()
pos=8328+24; last_tag=0x20; last_axis=0
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): pos=npos; continue
        hi=last_tag&0xE0
        if hi==0x60: ax=last_axis
        else:
            cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
            if near(cx,0): ax=0
            elif near(cy,1): ax=1
            elif 511<=cz<=543: ax=2
            else: pos=npos; continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]; val=be(prev[ax]); last_axis=ax
        if ax==1 and abs(val-curY)>0.1:
            changes+=1; steps[round(val-curY,2)]+=1; nbc[nb]+=1; tagc[last_tag]+=1
            curY=val
        elif ax==1: curY=val
        pos=npos
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
print(f'Y changes (>0.1m): {changes:,}   (GT rows=2907)')
print('top Y-step sizes:', steps.most_common(15))
print('nb (payload+1) at Y change:', dict(sorted(nbc.items())))
print('TAG at Y change:', tagc.most_common(8))
