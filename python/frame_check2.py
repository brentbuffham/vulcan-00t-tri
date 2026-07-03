#!/usr/bin/env python3
"""Framing validation on another file: tokenize coord section with generalized
prefix rule; compare V+F token count vs 3*NV from its DXF. GT-free except count."""
import sys, struct
from collections import Counter
oot=sys.argv[1]; dxf=sys.argv[2] if len(sys.argv)>2 else None
d=open(oot,'rb').read()
hdr=struct.unpack('<15i',d[0:60])
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    import math
    a=abs(v); return math.isfinite(v) and (1e-3<a<1e7)
def looks_full(o):
    if d[o] not in (0x40,0x41,0xC0,0xC1) or o+8>face_start: return False
    return sane(be(d[o:o+8]))
pos=8350; c=Counter(); nv=0; nf=0; solo=0
# find seed end: 3 doubles from 8326
while pos<face_start:
    b=d[pos]
    if looks_full(pos): nf+=1; pos+=8; continue
    if b<0x20:
        nb=(b&7)+1
        if pos+1+nb<=face_start: nv+=1; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: c['E']+=1; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: c['T']+=1; pos+=2; continue
    solo+=1; pos+=1
print(f'{oot}')
print(f'  coord section 8326..{face_start}  V={nv} F={nf} (V+F+3seed={nv+nf+3})  T={c["T"]} E={c["E"]} solo={solo}')
if dxf:
    lines=open(dxf,'r',errors='ignore').read().split('\n')
    vs=set(); i=0; n=len(lines); cur={}; in3d=False
    def fnum(s):
        try: return float(s)
        except: return None
    while i<n-1:
        code=lines[i].strip(); val=lines[i+1].strip() if i+1<n else ''
        if code=='0':
            if in3d and len(cur)>=9:
                for k in range(3):
                    vs.add((round(cur[(k,0)],3),round(cur[(k,1)],3),round(cur[(k,2)],3)))
            in3d=(val.upper()=='3DFACE'); cur={}
        elif in3d:
            cc=fnum(code); f=fnum(val)
            if cc is not None and f is not None and abs(f)<1e8:
                ci=int(cc)
                for k in range(4):
                    if ci==10+k: cur[(k,0)]=f
                    elif ci==20+k: cur[(k,1)]=f
                    elif ci==30+k: cur[(k,2)]=f
        i+=2
    print(f'  DXF NV={len(vs)}  3*NV={3*len(vs)}')
