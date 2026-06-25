#!/usr/bin/env python3
"""Characterize the geometry blob in windows to find the coord/topology boundary
and profile the topology section's byte structure (CLERS candidate)."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
print(f'geo_end (header[11]) = {geo_end:,}   filesize={len(d):,}')
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
def cls(b):
    if b<=0x06: return 'cnt'
    if is_sep(b): return 'sep'
    if (b&0xE0) in TAG_CLASSES: return 'tag'
    return 'oth'
# window scan across the whole geometry blob
W=2_000_000
print(f"\n{'win-start':>11} {'cnt%':>6} {'sep%':>6} {'tag%':>6} {'oth%':>6} {'meanByte':>9} {'entropy':>8}")
pos=8328
while pos<geo_end:
    end=min(pos+W,geo_end)
    seg=d[pos:end]
    c=Counter(cls(b) for b in seg)
    tot=len(seg)
    h=Counter(seg)
    ent=-sum((v/tot)*np.log2(v/tot) for v in h.values())
    print(f'{pos:11d} {100*c["cnt"]/tot:6.1f} {100*c["sep"]/tot:6.1f} {100*c["tag"]/tot:6.1f} '
          f'{100*c["oth"]/tot:6.1f} {np.mean(np.frombuffer(seg,dtype=np.uint8)):9.1f} {ent:8.2f}')
    pos=end
