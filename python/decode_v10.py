#!/usr/bin/env python3
"""decode_v10: reuse the AUTHORITATIVE toy framer parse_coord_elements (handles
tags/seps/escapes/full-runs/IDELTA) on a production coord slice, then apply the
PURE X,Y,Z positional cycle to the element values. KDTree score first verts.
Tests whether proven framing keeps the cycle aligned where my ad-hoc framing didn't."""
import sys, struct, pickle
sys.path.insert(0,'python')
import numpy as np
from scipy.spatial import cKDTree
from oot_parser_v2 import parse_coord_elements
oot=sys.argv[1]; cachedir=sys.argv[2]
SLICE=int(sys.argv[3]) if len(sys.argv)>3 else 300000
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
gtv=np.array(list(GT),dtype=np.float64)/100.0; tree=cKDTree(gtv)
d=open(oot,'rb').read()
region=d[8352:8352+SLICE]
els=parse_coord_elements(region, new_format=True)
print(f'parsed {len(els):,} coord elements from {SLICE:,} bytes')
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
# seed
cur=[be(d[8328:8336]),be(d[8336:8344]),be(d[8344:8352])]
triples=[tuple(cur)]; cyc=0
for el in els:
    cur[cyc]=el.value; cyc=(cyc+1)%3
    if cyc==0: triples.append(tuple(cur))
tr=np.array(triples,dtype=np.float64); tr=tr[np.isfinite(tr).all(1)]
print(f'emitted_verts={len(tr):,}')
for eps in (0.05,0.1,0.2,0.5):
    dd,idx=tree.query(tr,distance_upper_bound=eps); hit=np.isfinite(dd)
    print(f'  eps={eps}: within={hit.sum():,} uniqueGT={len(np.unique(idx[hit])):,} recall={len(np.unique(idx[hit]))/len(gtv)*100:.2f}%')
# also show first 6 emitted triples vs nearest GT
print('first 6 emitted triples & nearest GT dist:')
for t in tr[:6]:
    dd,_=tree.query(np.array(t)); print(f'   {t[0]:.3f} {t[1]:.3f} {t[2]:.3f}   dGT={dd:.4f}')
