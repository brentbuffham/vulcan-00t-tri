#!/usr/bin/env python3
"""Anchor the delta model on real data. Print seed + the GT verts nearest it, then
the first records with candidate splices into X/Y/Z — so we can hand-match vertex1,2
and learn the true delta encoding + axis order. NO assumptions about axis/model."""
import sys, struct, pickle
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]; N=int(sys.argv[3]) if len(sys.argv)>3 else 12
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
gtv=np.array(list(GT),dtype=np.float64)/100.0
d=open(oot,'rb').read()
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
seed=np.array([be(d[8328:8336]),be(d[8336:8344]),be(d[8344:8352])])
dist=np.sqrt(((gtv-seed)**2).sum(1)); order=dist.argsort()
print('seed =',[round(x,4) for x in seed])
print('nearest GT verts to seed:')
for j in order[:20]:
    print(f'   {gtv[j][0]:.4f} {gtv[j][1]:.4f} {gtv[j][2]:.4f}   d={dist[j]:.4f}')
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
def splice(ax,payload,nb):
    if payload[0] in FULL_IND: return be(payload+b'\x00'*(8-nb))
    return be(bytes(prev[ax][:8-nb])+payload)
print('\nfirst records (tag sep nb payload | spliceX spliceY spliceZ):')
pos=8352; last_tag=0x20; cnt=0
while pos<len(d) and cnt<N:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        if len(payload)==nb:
            vx=splice(0,payload,nb); vy=splice(1,payload,nb); vz=splice(2,payload,nb)
            print(f'  [{cnt:2d}] tag={last_tag:02x} nb={nb} pl={payload.hex():12s} | X={vx:11.4f} Y={vy:12.4f} Z={vz:9.4f}')
            cnt+=1
        pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
