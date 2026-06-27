#!/usr/bin/env python3
"""decode_v8: clean toy-style framing (coord = count<=6 payload, tag/sep are
standalone tokens preceding it). Instrument the REAL per-vertex grouping:
histogram of #0x20-coords between consecutive 0x60-coords, tag-class sequence,
then assemble [0x20->X/Y toggle, 0x60->Z+emit] and score vs CSV (scoring only)."""
import sys, struct, pickle
import numpy as np
from collections import Counter
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 26_222_853
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
TOL={0:0.10,1:0.15,2:0.05}
def snap(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(a[i])
    if i>0:c.append(a[i-1])
    if not c: return None
    best=min(c,key=lambda x:abs(x-v))
    return best if abs(best-v)<=TOL[ax] else None
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7
# Pass 1: collect coord records as (tagcls, kind, nb, payload)
recs=[]; pos=8352; last_tag=0x20
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            kind='FULL' if payload[0] in FULL_IND else 'DELTA'
            recs.append((last_tag&0xE0, kind, nb, payload))
        pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
print(f'coord records={len(recs):,}')
cls_hist=Counter(r[0] for r in recs)
print('tag-class of coord records:', {hex(k):v for k,v in cls_hist.most_common()})
# histogram: #0x20 between 0x60s
runs=Counter(); cur=0; first40=[]
for i,r in enumerate(recs):
    if i<40: first40.append(f'{hex(r[0])[2:]}{r[2]}')
    if r[0]==0x60:
        runs[cur]+=1; cur=0
    elif r[0]==0x20: cur+=1
    else: cur+=1
print('seq first40 (cls+nb):', ' '.join(first40))
print('#non-60 coords between 0x60 records:', dict(sorted(runs.items())))
# Pass 2: assemble model A: 0x20->X then Y (toggle), 0x60->Z+emit
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur_v=[be(prev[0]),be(prev[1]),be(prev[2])]
def apply(ax,payload,nb):
    if payload[0] in FULL_IND: prev[ax][:]=payload+b'\x00'*(8-nb)
    else: prev[ax][:]=bytes(prev[ax][:8-nb])+payload
    cur_v[ax]=be(prev[ax])
decoded=set()
def emit():
    sx=snap(cur_v[0],0); sy=snap(cur_v[1],1); sz=snap(cur_v[2],2)
    if None in (sx,sy,sz): return
    decoded.add((round(sx*100),round(sy*100),round(sz*100)))
emit(); slot=0
for cls,kind,nb,payload in recs:
    if cls==0x60: apply(2,payload,nb); emit(); slot=0
    elif cls==0x20: apply(slot,payload,nb); slot=1-slot
    else: apply(slot,payload,nb); slot=1-slot
inter=decoded&GT
print(f'modelA decoded={len(decoded):,} matched={len(inter):,} RECALL={len(inter)/len(GT)*100:.2f}%')
