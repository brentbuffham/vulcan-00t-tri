#!/usr/bin/env python3
"""Decisive: are the 0xE0 data-records the missing Y coordinate? Splice each 0xE0
payload onto a Y prefix (running, seeded mid-range) and tally Y-grid membership.
Compare also onto X and Z. If Y-grid hit-rate is high, [25M..] holds Y, not topo."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]; SP=sys.argv[2]
START=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
N=int(sys.argv[4]) if len(sys.argv)>4 else 300000
gt={0:np.load(f'{SP}/gt_x.npy'),1:np.load(f'{SP}/gt_y.npy'),2:np.load(f'{SP}/gt_z.npy')}
def near(v,a,t=0.02):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
# running prev per axis, updated when a value lands on that axis's grid
pX=bytearray(struct.pack('>d',60600.0)); pY=bytearray(struct.pack('>d',214300.0)); pZ=bytearray(struct.pack('>d',525.0))
hitsY=hitsX=hitsZ=tot=0; samples=[]
pos=START; cur=None
while pos<geo_end and tot<N:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pl=d[pos+1:pos+1+nb]; pos+=1+nb
        if cur==0xe0 and nb>=3:
            tot+=1
            y=be(pY[:8-nb]+pl); x=be(pX[:8-nb]+pl); z=be(pZ[:8-nb]+pl)
            fy=213900<y<214700 and near(y,1)
            fx=60300<x<60900 and near(x,0)
            fz=511<z<543 and near(z,2)
            hitsY+=fy; hitsX+=fx; hitsZ+=fz
            if fy: pY[:]=struct.pack('>d',y)
            if len(samples)<15: samples.append((pl.hex(),round(x,3),round(y,3),round(z,3),'Y' if fy else '',('X' if fx else '')+('Z' if fz else '')))
        cur=None
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG: cur=b; pos+=1
    else: pos+=1
print(f'0xE0 data-records sampled: {tot:,}')
print(f'  on Y-grid: {hitsY:,} ({100*hitsY/max(1,tot):.1f}%)')
print(f'  on X-grid: {hitsX:,} ({100*hitsX/max(1,tot):.1f}%)')
print(f'  on Z-grid: {hitsZ:,} ({100*hitsZ/max(1,tot):.1f}%)')
print('samples (payload, Xtry, Ytry, Ztry, Yhit, others):')
for s in samples: print('  ',s)
