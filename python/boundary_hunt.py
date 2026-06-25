#!/usr/bin/env python3
"""Hunt the Y-row-advance marker. Decode with v3 grammar; for each emitted (X,Z)
vertex, look up candidate GT rows (ykeys) that contain that (X,Z). Print the
token stream annotated with the inferred row, and FLAG every raw byte that breaks
the clean TAG/SEP/count grammar (candidate markers). Goal: see what sits at the
transition where the inferred Y row changes."""
import sys, struct, pickle
import numpy as np
from collections import defaultdict
oot=sys.argv[1]; cachedir=sys.argv[2]
START=int(sys.argv[3]) if len(sys.argv)>3 else 8352
END=int(sys.argv[4]) if len(sys.argv)>4 else 9200
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
xz2y=defaultdict(set)
for (xk,yk,zk) in GT: xz2y[(xk,zk)].add(yk)
def snap(v,ax,tol):
    a=gt[ax]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(a[i])
    if i>0:c.append(a[i-1])
    best=min(c,key=lambda x:abs(x-v))
    return best if abs(best-v)<=tol else None
def near(v,a,t=0.006):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read()
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
# replay to START
pos=8328+24; last_tag=0x20; last_axis=0
def step(pos,last_tag,last_axis,verbose):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND):
            if verbose: print(f'{pos:7d}  CNT-SKIP nb={nb} [{payload.hex(" ")}]')
            return npos,last_tag,last_axis
        hi=last_tag&0xE0
        if hi==0x60: ax=last_axis
        else:
            cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
            if near(cx,0): ax=0
            elif near(cy,1): ax=1
            elif 511<=cz<=543: ax=2
            else:
                if verbose: print(f'{pos:7d}  CNT-NOAX nb={nb} [{payload.hex(" ")}]')
                return npos,last_tag,last_axis
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]; val=be(prev[ax])
        if verbose:
            lbl='XYZ'[ax]+('*' if hi==0x60 else '')
            extra=''
            if ax==2:  # emitted vertex -> show candidate rows
                sx=snap(be(prev[0]),0,0.10); sz=snap(val,2,0.02)
                if sx is not None and sz is not None:
                    ys=xz2y.get((round(sx*100),round(sz*100)),set())
                    extra=f'  EMIT (X={sx:.3f},Z={sz:.3f}) rows={sorted(round(y/100,2) for y in ys)[:6]}'
            print(f'{pos:7d}  TAG{last_tag:02x} CNT nb={nb} -> {lbl}={val:.3f}{extra}')
        return npos,last_tag,ax
    elif is_sep(b):
        if verbose: print(f'{pos:7d}  SEP {b:02x}')
        return pos+1,last_tag,last_axis
    elif (b&0xE0) in TAG_CLASSES:
        if verbose: print(f'{pos:7d}  TAG {b:02x}')
        return pos+1,b,last_axis
    else:
        if verbose: print(f'{pos:7d}  *** ANOMALY byte {b:02x} ***')
        return pos+1,last_tag,last_axis
while pos<START:
    pos,last_tag,last_axis=step(pos,last_tag,last_axis,False)
while pos<END:
    pos,last_tag,last_axis=step(pos,last_tag,last_axis,True)
