#!/usr/bin/env python3
"""Pure 3-cycle decode; after each vertex check nearest-GT distance. Find the FIRST
drift (vertex that stops matching) and dump the records (tag/sep/nb/kind) around it.
The anomaly at the drift point = the vertex-boundary / dedup signal we need."""
import sys, struct, pickle
import numpy as np
from scipy.spatial import cKDTree
oot=sys.argv[1]; cachedir=sys.argv[2]
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
gtv=np.array(list(GT),dtype=np.float64)/100.0; tree=cKDTree(gtv)
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7
# collect coord records WITH their tag/sep
recs=[]; pos=8352; last_tag=0; last_sep=0
while pos<geo_end and len(recs)<2000:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            recs.append((last_tag,last_sep,nb,'FULL' if payload[0] in FULL_IND else 'DELTA',payload))
        pos+=1+nb
    elif is_sep(b): last_sep=b; pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
def apply(ax,payload,nb):
    if payload[0] in FULL_IND: prev[ax][:]=payload+b'\x00'*(8-nb)
    else: prev[ax][:]=bytes(prev[ax][:8-nb])+payload
    cur[ax]=be(prev[ax])
# decode 3 at a time, check vertex
i=0; vn=0; firstbad=None; dists=[]
while i+3<=len(recs):
    for k in range(3): apply(k,recs[i+k][4],recs[i+k][2])
    dd,_=tree.query(np.array(cur)); dists.append(dd); vn+=1
    if dd>0.15 and firstbad is None: firstbad=(vn,i)
    i+=3
ok=sum(1 for x in dists if x<0.15)
print(f'vertices checked={len(dists)}  matched(<0.15)={ok}  first {min(20,len(dists))} dists:',[round(x,2) for x in dists[:20]])
if firstbad:
    vn0,i0=firstbad
    print(f'\nFIRST DRIFT at vertex {vn0} (record idx {i0}). records {i0-3}..{i0+8}:')
    for j in range(max(0,i0-3), min(len(recs),i0+9)):
        t,s,nb,kind,pl=recs[j]
        mark=' <== drift vertex starts' if j==i0 else ''
        print(f'  rec[{j}] tag={t:02x} sep={s:02x} nb={nb} {kind} pl={pl.hex()}{mark}')
