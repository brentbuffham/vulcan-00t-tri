#!/usr/bin/env python3
"""Is the failure VALUE-decode or AXIS-assembly? Decode first N coord records with
clean framing, assemble model A, and for each emitted vertex print decoded (X,Y,Z)
with the NEAREST GT grid value + distance per axis. Tiny distances => values right,
snap tol too tight / axis fine. Big distances => value-decode bug."""
import sys, struct
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]; N=int(sys.argv[3]) if len(sys.argv)>3 else 20
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
def nearest(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v)
    cands=[]
    if i<len(a): cands.append(a[i])
    if i>0: cands.append(a[i-1])
    b=min(cands,key=lambda x:abs(x-v)); return b, abs(b-v)
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7
# verify seed first
seed=[be(d[8328:8336]),be(d[8336:8344]),be(d[8344:8352])]
print('SEED:', [round(x,3) for x in seed])
for ax in range(3):
    nv,dd=nearest(seed[ax],ax); print(f'  seed axis{ax}={seed[ax]:.4f} nearestGT={nv:.4f} dist={dd:.5f}')
recs=[]; pos=8352; last_tag=0x20
while pos<geo_end and len(recs)<N*3:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            recs.append((last_tag&0xE0,'FULL' if payload[0] in FULL_IND else 'DELTA',nb,payload))
        pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
def apply(ax,payload,nb):
    if payload[0] in FULL_IND: prev[ax][:]=payload+b'\x00'*(8-nb)
    else: prev[ax][:]=bytes(prev[ax][:8-nb])+payload
    cur[ax]=be(prev[ax])
AX='XYZ'; slot=0; vn=0
def show():
    s=[]
    for ax in range(3):
        nv,dd=nearest(cur[ax],ax); s.append(f'{AX[ax]}={cur[ax]:.4f}(d{dd:.4f})')
    print('  V%2d '%vn + '  '.join(s))
for cls,kind,nb,payload in recs:
    if cls==0x60: apply(2,payload,nb); vn+=1; show(); slot=0
    elif cls==0x20: apply(slot,payload,nb); slot=1-slot
    else: apply(slot,payload,nb); slot=1-slot
    if vn>=N: break
