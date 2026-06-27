#!/usr/bin/env python3
"""Score with 3D tolerance (KDTree) instead of exact round(*100) key — reveals the
TRUE recall of the current decode despite ~0.05 DELTA precision error. Assembly
model A: [0x20->X/Y toggle][0x60->Z+emit]. NO GT in decode; KDTree = scoring only."""
import sys, struct, pickle
import numpy as np
from scipy.spatial import cKDTree
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 26_222_853
MODEL=sys.argv[4] if len(sys.argv)>4 else 'A'
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
gtv=np.array(list(GT),dtype=np.float64)/100.0
print(f'GT verts {len(gtv):,}; building KDTree...'); tree=cKDTree(gtv)
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
def apply(ax,payload,nb):
    if payload[0] in FULL_IND: prev[ax][:]=payload+b'\x00'*(8-nb)
    else: prev[ax][:]=bytes(prev[ax][:8-nb])+payload
    cur[ax]=be(prev[ax])
triples=[tuple(cur)]
pos=8352; last_tag=0x20; slot=0; cyc=0
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            cls=last_tag&0xE0
            if MODEL=='A':
                if cls==0x60: apply(2,payload,nb); triples.append(tuple(cur)); slot=0
                else: apply(slot,payload,nb); slot=1-slot
            elif MODEL=='POS':   # pure X,Y,Z cycle over all records
                apply(cyc,payload,nb); cyc=(cyc+1)%3
                if cyc==0: triples.append(tuple(cur))
            elif MODEL=='B':     # 0x60->Z+emit ; non-60 -> X,Y,X,Y but emit per pair
                if cls==0x60: apply(2,payload,nb); triples.append(tuple(cur)); slot=0
                else:
                    apply(slot,payload,nb)
                    if slot==1: triples.append(tuple(cur))  # emit after each XY pair
                    slot=1-slot
        pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
tr=np.array(triples,dtype=np.float64)
print(f'model {MODEL}: emitted {len(tr):,} triples')
for eps in (0.02,0.05,0.1,0.2,0.5):
    dd,_=tree.query(tr, distance_upper_bound=eps)
    hit=np.isfinite(dd)
    # unique GT hit
    _,idx=tree.query(tr[hit]) if hit.any() else (None,np.array([],dtype=int))
    uniq=len(set(idx.tolist())) if hit.any() else 0
    print(f'  eps={eps}: triples_within={hit.sum():,}  uniqueGT={uniq:,}  recall={uniq/len(gtv)*100:.2f}%')
