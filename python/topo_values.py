#!/usr/bin/env python3
"""Probe the [25M..geo_end] section: splice each coord record onto X/Y/Z running
prefixes (seeded from a plausible mid value) and tally which axis-range the values
fall in. If dominated by Y (214xxx), this section is the Y axis; if it's index-like
small ints / opcodes, it's topology."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]
START=int(sys.argv[2]) if len(sys.argv)>2 else 25_300_000
NREC=int(sys.argv[3]) if len(sys.argv)>3 else 200000
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
# seed prefixes from typical mid values
import struct as st
def pref(v): return st.pack('>d',v)
pX=pref(60600.0); pY=pref(214300.0); pZ=pref(525.0)
rng=Counter(); nbc=Counter(); fb=Counter(); tagc=Counter()
pos=START; n=0
while pos<geo_end and n<NREC:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pl=d[pos+1:pos+1+nb]; pos+=1+nb; n+=1; nbc[nb]+=1
        if pl: fb[pl[0]]+=1
        x=be(pX[:8-nb]+pl); y=be(pY[:8-nb]+pl); z=be(pZ[:8-nb]+pl)
        hit=[]
        if 60300<x<60900: hit.append('X')
        if 213900<y<214700: hit.append('Y')
        if 511<z<543: hit.append('Z')
        rng['/'.join(hit) if hit else 'none']+=1
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: tagc[d[pos]]+=1; pos+=1
    else: pos+=1
print(f'section from {START:,}, {n:,} coord records')
print('axis-range hits:', rng.most_common())
print('nb dist:', dict(sorted(nbc.items())))
print('first-byte top15:', fb.most_common(15))
print('tag top15:', tagc.most_common(15))
