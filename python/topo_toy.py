#!/usr/bin/env python3
"""Run the authoritative toy parser on the topo geometry (toy-format: E0 markers +
inline FULL doubles). Print first element values + kind, and a band histogram, to see
if it decodes sensibly. Then we can assemble + extract the whole cloud."""
import sys
sys.path.insert(0,'python')
import struct
from collections import Counter
from oot_parser_v2 import parse_coord_elements
oot=sys.argv[1]; START=int(sys.argv[2]) if len(sys.argv)>2 else 8318
SLICE=int(sys.argv[3]) if len(sys.argv)>3 else 120000
NF=sys.argv[4]=='new' if len(sys.argv)>4 else False
d=open(oot,'rb').read()
region=d[START:START+SLICE]
els=parse_coord_elements(region,new_format=NF)
print(f'parsed {len(els):,} elements (new_format={NF}) from {SLICE:,} bytes at {START}')
def bandname(v):
    a=abs(v)
    if 52000<a<58000: return 'X'
    if 218000<a<220000: return 'Y'
    if 400<a<700: return 'Z'
    return '.'
bands=Counter()
print('first 36 elements:')
for i,el in enumerate(els):
    bn=bandname(el.value); bands[bn]+=1 if True else 0
    if i<36: print(f'  [{i:2d}] {el.value:14.4f} {el.kind:6s} nb={el.n_bytes} band={bn}')
bands=Counter(bandname(el.value) for el in els)
print('band counts:',dict(bands))
