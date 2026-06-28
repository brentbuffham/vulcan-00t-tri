#!/usr/bin/env python3
"""Test the spatial-sort hypothesis: if vertices are emitted in a spatial order, the
per-axis coordinate VALUES should progress monotonically/smoothly through the stream
(not jump). Use the exact FULL values (reliable). Report ordering structure per band."""
import sys, struct
import numpy as np
oot=sys.argv[1]
d=open(oot,'rb').read()
face_start=next((i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03), len(d))
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
seq={0:[],1:[],2:[]}
o=8326
while o<face_start-8:
    if full_here(o):
        v=be(d[o:o+8]); seq[band(v)].append(v); o+=8
    else: o+=1
for a in range(3):
    s=np.array(seq[a]);
    if len(s)<5: print(f'axis{a}: {len(s)} fulls'); continue
    # monotonic runs / sortedness
    asc=np.mean(np.diff(s)>0)*100; dsc=np.mean(np.diff(s)<0)*100
    # correlation with index
    idx=np.arange(len(s)); corr=np.corrcoef(idx,s)[0,1]
    # mean abs step vs total range
    step=np.mean(np.abs(np.diff(s))); rng=s.max()-s.min()
    print(f'axis{a} ({"XYZ"[a]}): n={len(s)}  asc%={asc:.0f} dsc%={dsc:.0f}  idx-corr={corr:.2f}  mean|step|={step:.1f}m range={rng:.1f}m')
    print(f'   first 12: {[round(x,1) for x in s[:12]]}')
