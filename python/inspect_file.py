#!/usr/bin/env python3
"""Structural inspection of any .00t: header, geo bounds, seed coords, framing
validity, first records, and a pure-XYZ-cycle decode sample (band self-check, no GT)."""
import sys, struct
from collections import Counter
oot=sys.argv[1]
d=open(oot,'rb').read()
print(f'size={len(d):,}')
print(f'magic={d[:4].hex()} {d[4:8]}')
h=struct.unpack('<15i',d[0:60]); print(f'header int32={h}')
print(f'header[11] (geo_end)={h[11]:,}')
def be(o): return struct.unpack('>d',d[o:o+8])[0]
# find seed: scan 8240..8400 for 3 consecutive in-range doubles
print('\nscan 8300..8400 for BE doubles |v|<1e7:')
for off in range(8300,8400,8):
    try: v=be(off)
    except: continue
    if 1<abs(v)<1e7: print(f'  @{off} = {v:.4f}')
# framing validity from 8352
def is_sep(b): return (b&7)==7
pos=8352; ok=bad=0; cnts=Counter(); tags=Counter()
geo_end=h[11] if h[11]>8352 else len(d)
while pos+3<min(geo_end,len(d)):
    tag=d[pos]; sep=d[pos+1]; cnt=d[pos+2]
    if is_sep(sep): ok+=1; cnts[cnt]+=1; tags[tag&0xE0]+=1; pos+=3+cnt+1
    else: bad+=1; pos+=1
print(f'\nframing(8352..geo): ok={ok:,} bad={bad:,} valid={ok/max(1,ok+bad)*100:.1f}%')
print('tag classes:',{hex(k):v for k,v in tags.most_common()})
print('counts<=8:',{k:cnts[k] for k in range(9)})
# raw hex
print('\nraw 8352..8432:')
for o in range(8352,8432,16):
    print(f'  {o}: '+' '.join(f'{b:02x}' for b in d[o:o+16]))
