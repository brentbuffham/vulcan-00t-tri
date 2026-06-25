#!/usr/bin/env python3
"""Settle row-major vs mesh-order. Parse coord groups; B-primary = X. Track the
ordered X sequence and mark explicit Y-change records. If X is ~monotonic between
Y-changes and resets at each, it's ROW-MAJOR (Y piecewise const). If X jumps
randomly, it's MESH-ORDER. Prints runs between Y-changes."""
import sys, struct
import numpy as np
oot=sys.argv[1]; SP=sys.argv[2]
NRUN=int(sys.argv[3]) if len(sys.argv)>3 else 25
gt={0:np.load(f'{SP}/gt_x.npy'),1:np.load(f'{SP}/gt_y.npy'),2:np.load(f'{SP}/gt_z.npy')}
def near(v,a,t=0.006):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
pos=8328+24; last_tag=0x20; last_axis=2
runX=[]; runs=0
def flush(why):
    global runX,runs
    if runX:
        xs=runX
        mono = all(xs[i]<=xs[i+1]+1e-6 for i in range(len(xs)-1)) or all(xs[i]>=xs[i+1]-1e-6 for i in range(len(xs)-1))
        print(f'Y={cur[1]:.3f} [{why}] {len(xs)} X: '+' '.join(f'{x-60600:.2f}' for x in xs[:18])+('...' if len(xs)>18 else '')+f'  {"MONO" if mono else "jumpy"}')
        runs+=1
    runX=[]
while pos<geo_end and runs<NRUN:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pl=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        if len(pl)!=nb or (pl and pl[0] in FULL_IND): pos=npos; continue
        hi=last_tag&0xE0
        if hi==0x60:
            ax=last_axis; prev[ax][8-nb:]=pl; cur[ax]=be(bytes(prev[ax]))
        else:
            cx=be(bytes(prev[0][:8-nb])+pl); cy=be(bytes(prev[1][:8-nb])+pl); cz=be(bytes(prev[2][:8-nb])+pl)
            if near(cx,0): ax=0
            elif near(cy,1) and abs(cy-cur[1])>0.1: ax=1
            elif 511<=cz<=543: ax=2
            else: pos=npos; continue
            prev[ax][:]= (bytes(prev[ax][:8-nb])+pl); cur[ax]=be(bytes(prev[ax])); last_axis=ax
            if ax==1: flush('Ychg')
            elif ax==0: runX.append(cur[0])
        pos=npos
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG: last_tag=b; pos+=1
    else: pos+=1
