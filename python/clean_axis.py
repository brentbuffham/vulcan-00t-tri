#!/usr/bin/env python3
"""Re-run axis analysis on the CLEAN coordinate section only (before the
coord/topology boundary). Find the boundary where Z-emission collapses, then
tabulate TAG->axis and SEP->transition there to find the real axis selector."""
import sys, struct
from collections import defaultdict, Counter
import numpy as np

oot=sys.argv[1]; cachedir=sys.argv[2]
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

BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_000_000
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
ZLO,ZHI=511.0,543.0
tag_axis=defaultdict(Counter); sep_trans=defaultdict(Counter); axis_seq=Counter()
order_pairs=Counter()
prev_axis=2; last_sep=None; last_tag=None; pos=8328+24; n=0
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        if near(cx,0): ax=0
        elif near(cy,1): ax=1
        elif ZLO<=cz<=ZHI: ax=2
        else: continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
        if last_tag is not None: tag_axis[last_tag][ax]+=1
        if last_sep is not None: sep_trans[last_sep][(ax-prev_axis)%3]+=1
        order_pairs[(prev_axis,ax)]+=1
        axis_seq[ax]+=1; prev_axis=ax; n+=1
    elif is_sep(b): last_sep=b; pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1

print(f'clean coord records (< {BOUND:,}): {n:,}')
print('axis counts:', dict(axis_seq), ' -> implies verts ~', axis_seq[2])
print('\nconsecutive axis pairs (prev->cur):')
for (p,c),v in order_pairs.most_common(9):
    print(f'  {"XYZ"[p]}->{"XYZ"[c]}: {v:,}')
print('\nTAG -> axis (top tags, purity):')
NAMES={0:'X',1:'Y',2:'Z'}
for tag,c in sorted(tag_axis.items(),key=lambda kv:-sum(kv[1].values()))[:16]:
    tot=sum(c.values()); dom,dn=c.most_common(1)[0]
    print(f'  0x{tag:02x} n={tot:>9,}: X={c[0]/tot*100:4.0f}% Y={c[1]/tot*100:4.0f}% Z={c[2]/tot*100:4.0f}%  ->{NAMES[dom]} {dn/tot*100:4.0f}%')
print('\nSEP -> transition (top, purity):')
TN={0:'STAY',1:'FWD',2:'BACK'}
for sep,c in sorted(sep_trans.items(),key=lambda kv:-sum(kv[1].values()))[:12]:
    tot=sum(c.values()); dom,dn=c.most_common(1)[0]
    print(f'  0x{sep:02x} n={tot:>9,}: STAY={c[0]/tot*100:4.0f}% FWD={c[1]/tot*100:4.0f}% BACK={c[2]/tot*100:4.0f}%  ->{TN[dom]} {dn/tot*100:4.0f}%')
