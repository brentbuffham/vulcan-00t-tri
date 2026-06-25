#!/usr/bin/env python3
"""Test: does the SEP byte encode the implicit Y-step? Walk a constant-X run of
Z-records; align them with the GT column's Y-values descending from the entry Y;
print SEP byte vs the GT Y-step before each vertex."""
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
X0=be(prev[0]); Y0=be(prev[1]); Z0=be(prev[2])
xk=round(X0*100); nearx=min(cols,key=lambda x:abs(x-xk))
# GT column sorted by Y DESCENDING, find entry near Y0
col=sorted(cols[nearx], key=lambda t:-t[0])
yvals=[y/100 for y,_ in col]; zvals=[z/100 for _,z in col]
# entry index = first Y <= Y0
ei=0
while ei<len(yvals) and yvals[ei]>Y0+0.13: ei+=1
print(f'col X={nearx/100:.3f}, entry Y0={Y0:.3f} -> GT idx {ei}, GT Y[{ei}]={yvals[ei] if ei<len(yvals) else None}')
print(f"{'pos':>6} {'SEP':>4} {'SEPhi':>5} {'Zdec':>9}   {'GTy':>10} {'GTz':>8} {'Ystep':>7}")
# walk run, pairing each Z record to successive GT column entries
gi=ei; prevY=Y0; lastsep=0x17
pos=START
while pos<END:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        sep=lastsep
        zdec=be(prev[2][:8-nb]+payload)
        gy=yvals[gi] if gi<len(yvals) else None
        gz=zvals[gi] if gi<len(yvals) else None
        ystep=(prevY-gy) if gy is not None else None
        print(f'{pos:6d} {sep:4x} {sep>>3:5d} {zdec:9.3f}   '
              f'{gy if gy else 0:10.2f} {gz if gz else 0:8.3f} {ystep if ystep else 0:7.2f}')
        if gy is not None: prevY=gy
        gi+=1; pos=npos
    elif is_sep(b): lastsep=b; pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1
