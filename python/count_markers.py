#!/usr/bin/env python3
"""Count, over the coord section:
 - clean records (TAG 20/60 + SEP 17 + count + payload)
 - irregular 'escape' events (where after TAG+SEP the next byte is not a valid
   count <=6) -- candidate ROW MARKERS
 - SEP byte distribution
If escapes ~= 2907 they mark rows; if ~= vertex count they mark vertices."""
import sys, struct
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
from collections import Counter
sepc=Counter(); tagc=Counter(); escape=0; clean=0; cntc=Counter()
ylike=0  # records decoding into Y range
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
def near(v,a,t=0.006):
    arr=gt[a]; i=np.searchsorted(arr,v)
    if i<=0: return abs(arr[0]-v)<t
    if i>=len(arr): return abs(arr[-1]-v)<t
    return min(abs(arr[i]-v),abs(arr[i-1]-v))<t
pos=8328+24
last_was_tagsep=False
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); pos+=1+nb; cntc[b]+=1
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        if near(cx,0): ax=0
        elif near(cy,1): ax=1; ylike+=1
        elif 511<=cz<=543: ax=2
        else: ax=-1
        if ax>=0: prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
        clean+=1
    elif is_sep(b):
        sepc[b]+=1
        # peek: after SEP, do we get a valid count? if not -> escape
        nxt=d[pos+1] if pos+1<len(d) else 0
        if nxt>0x06: escape+=1
        pos+=1
    elif (b&0xE0) in TAG_CLASSES:
        tagc[b&0xff]+=1; pos+=1
    else:
        pos+=1
print(f'coord section [{8352}..{min(geo_end,BOUND)}]')
print(f'clean coord records: {clean:,}')
print(f'records decoding to Y-range: {ylike:,}')
print(f'escape events (SEP not followed by count): {escape:,}')
print(f'GT rows = 2907, GT verts ~1.21M')
print('count-byte dist:', dict(sorted(cntc.items())))
print('top SEP bytes:', sepc.most_common(10))
print('top TAG bytes:', tagc.most_common(15))
