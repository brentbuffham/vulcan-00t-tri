#!/usr/bin/env python3
"""Crack the REAL delta encoding. Test models vs GT, comparing hit rate to the
coincidental floor (X 2%, Y 3%, Z 31%). A real model beats coincidental decisively.
Models: SPLICE (baseline, known coincidental) vs IDELTA = add signed int(payload) to
the double's 64-bit pattern (exact, cascades w/o drift). GT-assisted axis + cascade."""
import sys, struct
import numpy as np
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def near(v,a,tol=0.002):
    arr=gA[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return arr[j]
    return None
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def beu(b): return struct.unpack('>Q',(bytes(b)+b'\x00'*8)[:8])[0]
def u2d(u): return struct.unpack('>d',struct.pack('>Q',u&0xFFFFFFFFFFFFFFFF))[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def is_sep(b): return (b&7)==7
def is_tag(b): return 0x20<=b<=0x2f and not is_sep(b)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)

def run(model):
    prev=[d[8326:8334],d[8334:8342],d[8342:8350]]  # exact seed bytes per axis
    pos=8350; hits=[0,0,0]; nd=0
    while pos<face_start-1:
        if full_here(pos):
            v=be(d[pos:pos+8]); prev[band(v)]=d[pos:pos+8]; pos+=8; continue
        p=pos
        if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
        if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
            count=d[p+1]; nb=count+1; rec_end=p+2+count+1
            if rec_end<=face_start:
                nd+=1; payload=d[rec_end-nb:rec_end]
                best=None
                for a in range(3):
                    if model=='splice':
                        val=be(bytes(prev[a][:8-nb])+payload)
                    else:  # idelta
                        delta=int.from_bytes(payload,'big',signed=True)
                        val=u2d(beu(prev[a])+delta)
                    m=near(val,a)
                    if m is not None: best=(a,val,m); break
                if best:
                    a,val,m=best; hits[a]+=1
                    prev[a]=struct.pack('>d',m)  # cascade from exact (GT-snapped)
                pos=rec_end; continue
        pos+=1
    return nd,hits

for mdl in ('splice','idelta'):
    nd,h=run(mdl)
    print(f'{mdl:7s}: deltas={nd:,}  hits X={h[0]} Y={h[1]} Z={h[2]}  total={sum(h)} ({sum(h)/nd*100:.0f}%)  [coincidental X2% Y3% Z31%]')
