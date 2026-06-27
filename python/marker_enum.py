#!/usr/bin/env python3
"""Enumerate all marker/record variants between FULL coordinates (the user's
recommended next step). Detect band-validated FULLs robustly; for each gap between
consecutive FULLs, catalog the leading bytes (the 'marker') and gap length. Reveals
the full set of delta/escape record types to handle. No ground truth needed."""
import sys, struct
from collections import Counter
f=sys.argv[1] if len(sys.argv)>1 else r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(f,'rb').read()
hdr=struct.unpack('<15i',d[0:60]); geo_end=hdr[11] if 8352<hdr[11]<=len(d) else len(d)
def be(o): return struct.unpack('>d',d[o:o+8])[0]
def is_full(o):
    if o+8>geo_end or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(o))
    return (500<v<800) or (54000<v<58000) or (158000<v<166000)
# collect full positions
fulls=[o for o in range(8326,geo_end-8) if is_full(o)]
print(f'band-validated FULLs={len(fulls):,}')
# gaps between consecutive fulls (after a full ends at o+8, until next full start)
mark1=Counter(); mark2=Counter(); gaplen=Counter()
samples={}
prev_end=None
for o in fulls:
    if prev_end is not None:
        gap=o-prev_end
        gaplen[gap]+=1
        if gap>0:
            b0=d[prev_end]; mark1[b0]+=1
            m2=(d[prev_end],d[prev_end+1]) if gap>=2 else (d[prev_end],)
            mark2[m2]+=1
            key=m2
            if key not in samples: samples[key]=d[prev_end:prev_end+min(gap,10)].hex()
    prev_end=o+8
print('\ngap length (bytes between fulls) histogram:')
for k,v in sorted(gaplen.items())[:20]: print(f'  gap={k}: {v:,}')
print('\nleading 1-byte of gap (marker0):')
for k,v in mark1.most_common(15): print(f'  {k:#04x}: {v:,}')
print('\nleading 2-byte of gap (marker) -> count [sample bytes]:')
for k,v in mark2.most_common(25):
    ks='-'.join(f'{x:02x}' for x in k)
    print(f'  {ks}: {v:,}   e.g. {samples.get(k,"")}')
