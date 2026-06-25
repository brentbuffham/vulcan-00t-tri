#!/usr/bin/env python3
"""Decoder v4: Y is an explicit row-advance.
 - 0x60 refine -> bind to last primary axis.
 - primary: near X-grid -> X; near Y-grid AND |dY|>0.1 -> Y (row advance);
   else Z. (A Y-range value at ~current Y is a misclassified Z -> falls to Z.)
 - emit vertex on each Z primary using current (X,Y).
Measure 3D recall with grid snapping."""
import sys, struct, pickle
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
TOL={0:0.10,1:0.15,2:0.02}
def snap(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(a[i])
    if i>0:c.append(a[i-1])
    best=min(c,key=lambda x:abs(x-v))
    return best if abs(best-v)<=TOL[ax] else None
def near(v,a,t=0.006):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
decoded=set(); nrows=0
def emit():
    sx=snap(cur[0],0); sy=snap(cur[1],1); sz=snap(cur[2],2)
    if None in (sx,sy,sz): return
    decoded.add((round(sx*100),round(sy*100),round(sz*100)))
emit()
pos=8328+24; last_tag=0x20; last_axis=0
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): pos=npos; continue
        hi=last_tag&0xE0
        if hi==0x60: ax=last_axis
        else:
            cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
            if near(cx,0): ax=0
            elif near(cy,1) and abs(cy-cur[1])>0.1: ax=1
            elif 511<=cz<=543: ax=2
            else: pos=npos; continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]; cur[ax]=be(prev[ax]); last_axis=ax
        if ax==1: nrows+=1
        if hi!=0x60 and ax==2: emit()
        pos=npos
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
inter=decoded & GT
print(f'Y-advances: {nrows:,}  decoded={len(decoded):,}  GT={len(GT):,}  matched={len(inter):,}  '
      f'RECALL={len(inter)/len(GT)*100:.2f}%  PREC={len(inter)/max(1,len(decoded))*100:.2f}%')
