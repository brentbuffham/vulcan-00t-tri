#!/usr/bin/env python3
"""Supervised: label each coord record's TRUE axis by snapping its splice to the GT
grid (GT for LABELLING ONLY), then print tag/sep/nb so we can read the rule
tag/sep -> axis. The resulting rule must be GT-free to count as a decode."""
import sys, struct
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]; N=int(sys.argv[3]) if len(sys.argv)>3 else 60
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def dist(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v)
    cands=[]
    if i<len(a): cands.append(abs(a[i]-v))
    if i>0: cands.append(abs(a[i-1]-v))
    return min(cands) if cands else 9e9
d=open(oot,'rb').read()
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
pos=8328+24; last_tag=None; seps=[]; cnt=0
AX='XYZ'
hist={}  # (tag, sep)-> Counter of axis
from collections import Counter, defaultdict
rule=defaultdict(Counter)
out=[]
while pos<len(d) and cnt<N*40:   # scan more to build the rule table, print first N
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        if len(payload)!=nb: pos=npos; continue
        kind='FULL' if payload[0] in FULL_IND else 'DELTA'
        # splice into each axis, snap, pick nearest as TRUE axis
        ds=[]
        for ax in range(3):
            if kind=='FULL': v=be(payload+b'\x00'*(8-nb))
            else: v=be(bytes(prev[ax][:8-nb])+payload)
            ds.append(dist(v,ax))
        tru=int(np.argmin(ds))
        # commit the chosen axis to prev (so subsequent splices track)
        if kind=='FULL': prev[tru][:]=payload+b'\x00'*(8-nb)
        else: prev[tru][:]=bytes(prev[tru][:8-nb])+payload
        sep=seps[-1] if seps else -1
        tg=last_tag if last_tag is not None else -1
        rule[(tg,sep,nb)][tru]+=1
        if cnt<N:
            out.append(f'[{cnt:3d}] tag={tg if tg<0 else format(tg,"02x")} sep={sep if sep<0 else format(sep,"02x")} '
                       f'nb={nb} {kind:5s} dmin={ds[tru]:.3f} -> {AX[tru]}  (d={[round(x,2) for x in ds]})')
        seps=[]; cnt+=1; pos=npos
    elif is_sep(b): seps.append(b); pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
print('\n'.join(out))
print(f'\n=== RULE TABLE (tag,sep,nb) -> axis counts over {cnt} records ===')
for k in sorted(rule, key=lambda x:-sum(rule[x].values())):
    c=rule[k]; tot=sum(c.values()); top=c.most_common(1)[0]; pur=top[1]/tot*100
    tg,sep,nb=k
    print(f'  tag={tg if tg<0 else format(tg,"02x")} sep={sep if sep<0 else format(sep,"02x")} nb={nb}: '
          f'X={c[0]} Y={c[1]} Z={c[2]}  -> {AX[top[0]]} {pur:.0f}% (n={tot})')
