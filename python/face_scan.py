#!/usr/bin/env python3
"""Locate the face/topology block (e0 03 ...) and reconcile with vertex count.
Find where the coord stream gives way to e0 03 records; count them; dump samples."""
import sys, struct
from collections import Counter
f=sys.argv[1] if len(sys.argv)>1 else r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(f,'rb').read()
hdr=struct.unpack('<15i',d[0:60]); geo_end=hdr[11] if 8352<hdr[11]<=len(d) else len(d)
# all e0 03 occurrences
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
print(f'file={len(d):,} geo_end(hdr11)={hdr[11]}  e0 03 occurrences={len(occ):,}')
if occ:
    print(f'first e0 03 @{occ[0]}  last @{occ[-1]}')
    # cluster: where do they become dense? print gaps
    import numpy as np
    a=np.array(occ); gaps=np.diff(a)
    # find the start of the dense face region (where consecutive e0 03 are close)
    print(f'e0 03 spacing: median={np.median(gaps):.0f} min={gaps.min()} mode~{Counter(gaps.tolist()).most_common(5)}')
    # the face block likely = contiguous run with small spacing
    print('\nraw around first dense e0 03:')
    start=occ[0]
    for o in range(start, start+96, 16):
        print(f'  {o}: '+' '.join(f'{b:02x}' for b in d[o:o+16]))
    # count records in face block assuming [e0 03 XX ...] framing - sample lengths
    print('\nbytes between consecutive e0 03 (record length) histogram:')
    print('  ',dict(Counter(gaps.tolist()).most_common(12)))
