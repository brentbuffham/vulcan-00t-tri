#!/usr/bin/env python3
"""decode_v11: positional X,Y,Z cycle + FULL-RESYNC. The cycle drifts because some
vertices have !=3 coords (dedup/refine). FULLs (payload[0] in FULL_IND) carry full
high bytes -> their VALUE band reveals the axis (X~60k, Y~214k, Z~515). Use every
FULL to re-anchor the cycle, killing accumulated drift. KDTree scoring only."""
import sys, struct, pickle
import numpy as np
from scipy.spatial import cKDTree
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 26_222_853
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
gtv=np.array(list(GT),dtype=np.float64)/100.0; tree=cKDTree(gtv)
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    if 60200<v<60900: return 0
    if 213800<v<214800: return 1
    if 505<v<548: return 2
    return -1
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
triples=[tuple(cur)]; pos=8352; cyc=0; nfull=0; nbadfull=0; ndelta=0
def emit(): triples.append(tuple(cur))
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            if payload[0] in FULL_IND:
                v=be(payload+b'\x00'*(8-nb)); a=band(v)
                if a<0: a=cyc; nbadfull+=1
                else: nfull+=1
                prev[a][:]=payload+b'\x00'*(8-nb); cur[a]=be(prev[a])
                cyc=(a+1)%3
                if a==2: emit()
            else:
                a=cyc; prev[a][:]=bytes(prev[a][:8-nb])+payload; cur[a]=be(prev[a])
                cyc=(cyc+1)%3; ndelta+=1
                if a==2: emit()
        pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1
tr=np.array(triples,dtype=np.float64); tr=tr[np.isfinite(tr).all(1)]
print(f'deltas={ndelta:,} fulls={nfull:,} badfulls={nbadfull:,} emitted_verts={len(tr):,}')
for eps in (0.02,0.05,0.1,0.2):
    dd,idx=tree.query(tr,distance_upper_bound=eps); hit=np.isfinite(dd)
    print(f'  eps={eps}: within={hit.sum():,} uniqueGT={len(np.unique(idx[hit])):,} recall={len(np.unique(idx[hit]))/len(gtv)*100:.2f}%')
