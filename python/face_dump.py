#!/usr/bin/env python3
"""Examine the e0 03 face/connectivity records in detail: positions, lengths, bytes,
value distributions. Compare structure to the DXF triangle connectivity (degrees,
first-appearance order) to figure out the encoding (indices? deltas? CLERS?)."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]; gtcsv=sys.argv[2] if len(sys.argv)>2 else None
d=open(oot,'rb').read()
hdr=struct.unpack('<15i',d[0:60]); end=len(d)
occ=[i for i in range(8326,end-2) if d[i]==0xE0 and d[i+1]==0x03]
print(f'e0 03 records: {len(occ):,}  span {occ[0]}..{occ[-1]}')
# record = bytes from one e0 03 to next
recs=[]
for k in range(len(occ)-1):
    recs.append(d[occ[k]:occ[k+1]])
lens=Counter(len(r) for r in recs)
print('record-length histogram:', dict(sorted(lens.items())[:14]))
print('\nfirst 24 records (hex, payload after e0 03):')
for r in recs[:24]:
    pl=r[2:]
    print(f'  len={len(r):2d}  e0 03 | {pl.hex()}')
# byte distribution in payloads (excluding e0 03)
allb=Counter()
for r in recs:
    for b in r[2:]: allb[b]+=1
print('\nmost common payload bytes:', [(hex(k),v) for k,v in allb.most_common(12)])
# look for repeating sub-structure: count of each byte that has (b&7)==7 (sep-like)
seps=sum(1 for r in recs for b in r[2:] if (b&7)==7)
tot=sum(len(r)-2 for r in recs)
print(f'sep-like bytes in payload: {seps:,}/{tot:,} ({seps/tot*100:.0f}%)')
