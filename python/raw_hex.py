#!/usr/bin/env python3
"""Raw annotated hex of the coord region start — no framing assumptions."""
import sys
oot=sys.argv[1]; start=int(sys.argv[2]) if len(sys.argv)>2 else 8352; n=int(sys.argv[3]) if len(sys.argv)>3 else 200
d=open(oot,'rb').read()
row=16
for off in range(start, start+n, row):
    chunk=d[off:off+row]
    hexs=' '.join(f'{b:02x}' for b in chunk)
    print(f'{off:6d}: {hexs}')
