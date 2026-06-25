#!/usr/bin/env python3
"""Dump EVERY token (SEP, TAG, count-record) in a byte range with full hex, so
we can find the ROW MARKER that advances Y implicitly between scanlines."""
import sys, struct
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]
START=int(sys.argv[3]) if len(sys.argv)>3 else 8328
END=int(sys.argv[4]) if len(sys.argv)>4 else 8470
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read()
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
# fast-forward prev state up to START by replaying coord records from 8352
pos=8328+24
while pos<START:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        def near(v,a,t=0.006):
            arr=gt[a]; i=np.searchsorted(arr,v)
            if i<=0: return abs(arr[0]-v)<t
            if i>=len(arr): return abs(arr[-1]-v)<t
            return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
        if near(cx,0): ax=0
        elif near(cy,1): ax=1
        elif 511<=cz<=543: ax=2
        else: continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
    else: pos+=1
def near(v,a,t=0.006):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
print(f'tokens [{START}..{END}]   (X={be(prev[0]):.3f} Y={be(prev[1]):.3f} Z={be(prev[2]):.3f} at start)')
pos=START
while pos<END:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb])
        pl=' '.join(f'{x:02x}' for x in payload)
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        skip = (payload and payload[0] in FULL_IND)
        tags=[]
        if near(cx,0):tags.append(f'X={cx:.3f}')
        if near(cy,1):tags.append(f'Y={cy:.3f}')
        if 511<=cz<=543:tags.append(f'Z={cz:.3f}')
        mark='SKIP' if skip else ''
        print(f'{pos:7d}  CNT nb={nb} [{pl:>17}]  {" ".join(tags):42} {mark}')
        if not skip:
            if near(cx,0): ax=0
            elif near(cy,1): ax=1
            elif 511<=cz<=543: ax=2
            else: ax=-1
            if ax>=0: prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
        pos+=1+nb
    elif is_sep(b):
        print(f'{pos:7d}  SEP {b:02x}')
        pos+=1
    elif (b&0xE0) in TAG_CLASSES:
        print(f'{pos:7d}  TAG {b:02x}')
        pos+=1
    else:
        print(f'{pos:7d}  ??? {b:02x}')
        pos+=1
