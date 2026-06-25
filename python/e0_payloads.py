#!/usr/bin/env python3
"""Extract the sequence of 0xE0-tagged CNT4 payloads from the topology section.
Print as hex / big-endian int / delta-from-prev / per-byte, to decide whether
they're delta-coded vertex indices or packed coordinates/opcodes."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]
START=int(sys.argv[2]) if len(sys.argv)>2 else 35_000_000
N=int(sys.argv[3]) if len(sys.argv)>3 else 40
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
pos=START; cur_tag=None; vals=[]; nbs=Counter()
while pos<geo_end and len(vals)<N:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pl=d[pos+1:pos+1+nb]; pos+=1+nb
        if cur_tag==0xe0: vals.append((nb,pl)); nbs[nb]+=1
        cur_tag=None
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: cur_tag=b; pos+=1
    else: pos+=1
print(f'E0-record payload nb dist (this sample): {dict(nbs)}')
print(f"{'hex':>14} {'bigint':>12} {'b0':>4} {'b1':>4} {'b2':>4} {'b3':>4}")
prev=None
for nb,pl in vals:
    iv=int.from_bytes(pl,'big')
    bs=list(pl)+[None]*(4-len(pl))
    dl=(iv-prev) if prev is not None else 0
    print(f'{pl.hex():>14} {iv:12d} '+' '.join(f'{x:4d}' if x is not None else '   .' for x in bs)+f'   d={dl}')
    prev=iv
# byte-position histograms over a big sample
pos=START; cur_tag=None; bp=[Counter() for _ in range(4)]; cnt=0
while pos<geo_end and cnt<200000:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pl=d[pos+1:pos+1+nb]; pos+=1+nb
        if cur_tag==0xe0 and nb==4:
            for i in range(4): bp[i][pl[i]]+=1
            cnt+=1
        cur_tag=None
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: cur_tag=b; pos+=1
    else: pos+=1
print(f'\nE0-CNT4 byte-position top values over {cnt} records:')
for i in range(4):
    print(f'  byte{i}:', bp[i].most_common(8))
