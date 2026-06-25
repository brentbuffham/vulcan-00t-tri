#!/usr/bin/env python3
"""With refine-binding (v3 grammar), profile the Y signal: count Y-primary
records (TAG 0x20 classified Y), distinct snapped Y values produced, and the
gap (records between consecutive Y-primaries). GT has 2907 rows."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
def snapy(v):
    a=gt[1]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(a[i])
    if i>0:c.append(a[i-1])
    best=min(c,key=lambda x:abs(x-v))
    return best if abs(best-v)<=0.15 else None
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
ydist=set(); yprim=0; nrec=0; gaps=[]; lastY=0
ytag=Counter(); ysep=Counter()
pos=8328+24; last_tag=0x20; last_axis=0; last_sep=0x17
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        nrec+=1; hi=last_tag&0xE0
        if hi==0x60: ax=last_axis
        else:
            cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
            if near(cx,0): ax=0
            elif near(cy,1): ax=1
            elif 511<=cz<=543: ax=2
            else: continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]; last_axis=ax
        if hi!=0x60 and ax==1:
            yprim+=1; sy=snapy(be(prev[1]))
            if sy is not None: ydist.add(round(sy*100))
            gaps.append(nrec-lastY); lastY=nrec
            ytag[last_tag]+=1; ysep[last_sep]+=1
    elif is_sep(b): last_sep=b; pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
g=np.array(gaps[1:]) if len(gaps)>1 else np.array([0])
print(f'records: {nrec:,}   Y-primaries: {yprim:,}   distinct snapped Y: {len(ydist):,}  (GT rows=2907)')
print(f'gap between Y-primaries: min={g.min()} max={g.max()} mean={g.mean():.1f} median={np.median(g):.0f}')
print('TAG byte on Y-primaries:', ytag.most_common(8))
print('SEP byte before Y-primaries:', ysep.most_common(8))
