#!/usr/bin/env python3
"""decode_v9: CLEAN framing [tag][sep][count][payload of count+1] (any count) +
PURE positional X,Y,Z cycle (tag class is NOT axis). Hypothesis: the only reason
the cycle desynced was the b<=6 gate misframing long records (count>6). Frame them
correctly so the cycle stays aligned. KDTree scoring only."""
import sys, struct, pickle
import numpy as np
from scipy.spatial import cKDTree
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 26_222_853
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
gtv=np.array(list(GT),dtype=np.float64)/100.0
tree=cKDTree(gtv)
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&7)==7
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
triples=[tuple(cur)]
pos=8352; cyc=0; nrec=0; nlong=0; nresync=0
while pos+3<=min(geo_end,BOUND):
    tag=d[pos]; sep=d[pos+1]; count=d[pos+2]
    if not is_sep(sep):
        pos+=1; nresync+=1; continue          # resync: not a record boundary
    nb=count+1; payload=bytes(d[pos+3:pos+3+nb]); pos=pos+3+nb
    if len(payload)!=nb: break
    ax=cyc
    if nb>8:
        nlong+=1
        # long/escape: take the 8 bytes following the first FULL indicator if any
        fi=next((i for i,b in enumerate(payload) if b in FULL_IND), None)
        if fi is not None: prev[ax][:]=(payload[fi:fi+8]+b'\x00'*8)[:8]
        else: prev[ax][:]=payload[:8]
    elif payload[0] in FULL_IND:
        prev[ax][:]=payload+b'\x00'*(8-nb)
    else:
        prev[ax][:]=bytes(prev[ax][:8-nb])+payload
    cur[ax]=be(prev[ax]); cyc=(cyc+1)%3; nrec+=1
    if cyc==0: triples.append(tuple(cur))
tr=np.array(triples,dtype=np.float64)
tr=tr[np.isfinite(tr).all(1)]
print(f'records={nrec:,} long(nb>8)={nlong:,} resyncs={nresync:,} emitted_verts={len(tr):,}')
for eps in (0.02,0.05,0.1,0.2):
    dd,idx=tree.query(tr, distance_upper_bound=eps)
    hit=np.isfinite(dd); uniq=len(np.unique(idx[hit]))
    print(f'  eps={eps}: within={hit.sum():,}  uniqueGT={uniq:,}  recall={uniq/len(gtv)*100:.2f}%')
