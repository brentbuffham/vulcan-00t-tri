#!/usr/bin/env python3
"""Topo file stores inline FULL doubles. Scan geometry for BE doubles in coord range,
histogram magnitudes to find X/Y/Z bands, and (if bands clear) extract the point set."""
import sys, struct
from collections import Counter
oot=sys.argv[1]
d=open(oot,'rb').read()
h=struct.unpack('<15i',d[0:60]); geo_end=h[11] if 8352<h[11]<=len(d) else len(d)
def be(o):
    try: return struct.unpack('>d',d[o:o+8])[0]
    except: return float('nan')
# find doubles: a byte 0x40/0x41/0xc0/0xc1 (typical exp for 1e2..1e6) starts a double
mags=Counter(); vals=[]
o=8300
while o<geo_end-8:
    b=d[o]
    if b in (0x40,0x41,0xc0,0xc1):
        v=be(o)
        if 100<abs(v)<1e7:
            mags[int(abs(v)//1000)*1000]+=1; vals.append((o,v))
            o+=8; continue
    o+=1
print(f'plausible doubles found={len(vals):,}')
print('magnitude bands (floor to 1000) -> count (top 15):')
for k,v in mags.most_common(15): print(f'  ~{k:,}: {v:,}')
print('\nfirst 18 doubles (offset,value):')
for o,v in vals[:18]: print(f'  @{o} {v:.4f}')
