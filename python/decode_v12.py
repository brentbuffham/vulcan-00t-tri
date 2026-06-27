#!/usr/bin/env python3
"""decode_v12: XYZ cycle + ESCAPE-FULL resync. Drift starts at escape-prefixed FULLs
(tag c3, payload embeds 0x40.. = a band value). Scan each payload for a FULL_IND; if
it yields a valid X/Y/Z band value, it's a FULL for that axis -> resync the cycle to
that axis (catches deduped/skipped axes). Plain deltas follow the cycle. KDTree score."""
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
triples=[tuple(cur)]; pos=8352; cyc=0
nresync=0; nplain=0; nfull=0
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            # find an embedded FULL that yields a band value
            a=-1; fb=None
            for f in range(min(nb,3)):
                if payload[f] in FULL_IND:
                    v=be(payload[f:]+b'\x00'*8); bb=band(v)
                    if bb>=0: a=bb; fb=payload[f:f+8]; break
            if a>=0:   # FULL / escape-FULL -> resync to band axis
                prev[a][:]=(fb+b'\x00'*8)[:8]; cur[a]=be(prev[a])
                if a==cyc: nfull+=1
                else: nresync+=1
                cyc=(a+1)%3
                if a==2: triples.append(tuple(cur))
            else:      # plain delta on cycle axis
                ax=cyc; prev[ax][:]=bytes(prev[ax][:8-nb])+payload; cur[ax]=be(prev[ax])
                cyc=(cyc+1)%3; nplain+=1
                if ax==2: triples.append(tuple(cur))
        pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1
tr=np.array(triples,dtype=np.float64); tr=tr[np.isfinite(tr).all(1)]
print(f'plain={nplain:,} fulls={nfull:,} resyncs={nresync:,} emitted_verts={len(tr):,}')
for eps in (0.02,0.05,0.1,0.2,0.3,0.5,1.0,2.0):
    dd,idx=tree.query(tr,distance_upper_bound=eps); hit=np.isfinite(dd)
    print(f'  eps={eps}: within={hit.sum():,} uniqueGT={len(np.unique(idx[hit])):,} recall={len(np.unique(idx[hit]))/len(gtv)*100:.2f}%')
