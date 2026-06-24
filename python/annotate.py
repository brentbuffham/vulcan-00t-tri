#!/usr/bin/env python3
"""Annotated dump of the first N coord records: offset, tag, sep, count,
payload, and the three candidate reconstructions (X/Y/Z) with grid flags.
Goal: SEE the per-vertex grouping and the axis selector."""
import sys, struct
import numpy as np

oot=sys.argv[1]; cachedir=sys.argv[2]; N=int(sys.argv[3]) if len(sys.argv)>3 else 50
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
def near(v,ax,tol=0.006):
    a=gt[ax]; i=np.searchsorted(a,v)
    if i<=0: return abs(a[0]-v)<tol
    if i>=len(a): return abs(a[-1]-v)<tol
    return min(abs(a[i]-v),abs(a[i-1]-v))<tol
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07

prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
print('V0  X=%.3f Y=%.3f Z=%.3f'%(be(prev[0]),be(prev[1]),be(prev[2])))
print(f"{'off':>8} {'tag':>4} {'sep':>4} {'c':>2} {'payload':>16}   pick   value         X? Y? Z?")
pos=8328+24; n=0; last_tag=None; last_sep=None
while pos<geo_end and n<N:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); off=pos; pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        fx,fy,fz=near(cx,0),near(cy,1),near(cz,2)
        if fx: ax,val=0,cx
        elif fy: ax,val=1,cy
        elif 511<=cz<=543: ax,val=2,cz
        else: ax,val=-1,0.0
        if ax>=0: prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
        pl=' '.join(f'{x:02x}' for x in payload)
        tg=f'{last_tag:02x}' if last_tag is not None else '--'
        sp=f'{last_sep:02x}' if last_sep is not None else '--'
        pick='XYZ?'[ax] if ax>=0 else '?'
        print(f"{off:8d} {tg:>4} {sp:>4} {nb-1:2d} {pl:>16}   {pick:>3}   {val:11.3f}   "
              f"{'X' if fx else '.'}  {'Y' if fy else '.'}  {'Z' if fz else '.'}")
        n+=1
    elif is_sep(b): last_sep=b; pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
