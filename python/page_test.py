#!/usr/bin/env python3
"""Test Brent's per-page-origin hypothesis. The .00t is a 2048-byte paged archive. If
each page carries a fresh origin (full coords) and deltas are page-relative, then (a)
full doubles should cluster at page boundaries (offset mod 2048 ~ constant), and (b)
page boundaries should show origin-like structure. Report full-offset distribution mod
2048, and dump bytes at the first few page boundaries inside the geometry."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(o): return struct.unpack('>d',d[o:o+8])[0]
def is_full(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(o)); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
fulls=[o for o in range(8326,face_start-8) if is_full(o)]
print(f'coord section 8326..{face_start} ({face_start-8326} bytes, {(face_start-8326)/2048:.1f} pages)')
print(f'full doubles: {len(fulls)}')
mod=Counter(o%2048 for o in fulls)
print('full-offset mod 2048 (top 12):', mod.most_common(12))
# gaps between fulls
g=np.diff(fulls)
print('full-to-full gap: median',int(np.median(g)),'  near-2048 gaps:',int(np.sum((g>1900)&(g<2200))))
# page boundaries inside geometry (pages of 2048 from file start)
print('\nbytes at page boundaries (mult of 2048) inside geometry:')
for pb in range(((8326//2048)+1)*2048, face_start, 2048):
    if pb+16<=len(d):
        print(f'  @{pb} (page {pb//2048}): '+' '.join(f'{b:02x}' for b in d[pb-4:pb+16]))
    if pb>8326+2048*6: break
