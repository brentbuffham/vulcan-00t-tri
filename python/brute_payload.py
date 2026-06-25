#!/usr/bin/env python3
"""Brute-force the within-column value model. Take a constant-X run of records
(payloads), and the matching GT column (sorted Y->Z). For each payload, try:
  (a) SPLICE: BE(prefix[:k] ++ payload) for prefix from prev X/Y/Z, k=8-nb
  (b) DELTA: prev_val + signed(payload) at various scales
and report which model + axis reproduces the GT column's Y or Z values."""
import sys, struct, pickle
import numpy as np
from collections import defaultdict
oot=sys.argv[1]; SP=sys.argv[2]
START=int(sys.argv[3]) if len(sys.argv)>3 else 8904
END=int(sys.argv[4]) if len(sys.argv)>4 else 8990
gt={0:np.load(f'{SP}/gt_x.npy'),1:np.load(f'{SP}/gt_y.npy'),2:np.load(f'{SP}/gt_z.npy')}
GT=pickle.load(open(f'{SP}/gt_keys.pkl','rb'))
cols=defaultdict(list)
for (xk,yk,zk) in GT: cols[xk].append((yk,zk))
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read()
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
# replay to START to get prev state
def near(v,a,t=0.006):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
pos=8328+24; last_tag=0x20; last_axis=0
while pos<START:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): pos=npos; continue
        hi=last_tag&0xE0
        if hi==0x60: ax=last_axis
        else:
            cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
            if near(cx,0): ax=0
            elif near(cy,1) and abs(cy-be(prev[1]))>0.1: ax=1
            elif 511<=cz<=543: ax=2
            else: pos=npos; continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]; last_axis=ax; pos=npos
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
print(f'prev at {START}: X={be(prev[0]):.3f} Y={be(prev[1]):.3f} Z={be(prev[2]):.3f}')
# GT column for current X
xk=round(be(prev[0])*100)
nearx=min(cols, key=lambda x:abs(x-xk))
col=sorted(cols[nearx])
print(f'GT column X={nearx/100:.3f}: {len(col)} pts')
print('  GT Y:', [f'{y/100:.2f}' for y,_ in col][:25])
print('  GT Z:', [f'{z/100:.3f}' for _,z in col][:25])
gtY=set(y for y,_ in col); gtZ=[z for _,z in col]
# collect run payloads
recs=[]
pos=START
while pos<END:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); recs.append((pos,nb,payload)); pos+=1+nb
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1
print(f'\n{len(recs)} records in run. Testing models:')
for (p,nb,pl) in recs:
    plh=pl.hex(' ')
    out=[]
    # splice with each axis prefix
    for axn,ax in (('X',0),('Y',1),('Z',2)):
        v=be(prev[ax][:8-nb]+pl)
        tag=''
        if axn=='Y' and any(abs(v-y/100)<0.02 for y,_ in col): tag='<=GTcolY'
        if axn=='Z' and any(abs(v-z/100)<0.03 for _,z in col): tag='<=GTcolZ'
        out.append(f'{axn}sp={v:.3f}{tag}')
    print(f'{p} nb={nb} [{plh:>17}]  '+'  '.join(out))
