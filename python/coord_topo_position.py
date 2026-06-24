#!/usr/bin/env python3
"""Are coord records and topology records interleaved or sectioned?
Bin the blob by offset; in each bin count records that hit the SPARSE X or Y
grid (definitely coords) vs hit nothing (topology/other) vs Z-range-only."""
import sys, struct
import numpy as np

oot = sys.argv[1]; cachedir = sys.argv[2]
gx = np.load(f'{cachedir}/gt_x.npy'); gy = np.load(f'{cachedir}/gt_y.npy')

def near(v, a, tol=0.006):
    i = np.searchsorted(a, v)
    if i <= 0: return abs(a[0]-v) < tol
    if i >= len(a): return abs(a[-1]-v) < tol
    return min(abs(a[i]-v), abs(a[i-1]-v)) < tol

def be(raw): return struct.unpack('>d', (raw + b'\x00'*8)[:8])[0]

d = open(oot, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
TAG_CLASSES = (0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b & 0x07)==0x07 and b>=0x07

prev = {0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
NBINS=20; start=8328+24; span=geo_end-start
bins=[[0,0,0,0] for _ in range(NBINS)]   # [xy_coord, z_range_only, none, topology_tag]
ZLO,ZHI=511.0,543.0
pos=start; last_tag=None
while pos<geo_end:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        bi=min(NBINS-1,int((pos-start)/span*NBINS))
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        topo = last_tag is not None and (last_tag & 0xF0) in (0xE0,0xF0)
        if near(cx,gx): prev[0]=(prev[0][:8-nb]+payload+b'\x00'*8)[:8]; bins[bi][0]+=1
        elif near(cy,gy): prev[1]=(prev[1][:8-nb]+payload+b'\x00'*8)[:8]; bins[bi][0]+=1
        elif ZLO<=cz<=ZHI:
            prev[2]=(prev[2][:8-nb]+payload+b'\x00'*8)[:8]
            bins[bi][3 if topo else 1]+=1
        else: bins[bi][2]+=1
    elif is_sep(b): pos+=1
    elif (b & 0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1

print(f"{'bin':>3} {'offset':>10}  {'XY-coord':>9} {'Z-only':>8} {'none':>7} {'Z+topoTag':>9}")
for i,(xy,z,no,zt) in enumerate(bins):
    off=int(start+span*i/NBINS)
    print(f"{i:3d} {off:>10}  {xy:>9,} {z:>8,} {no:>7,} {zt:>9,}")
