#!/usr/bin/env python3
"""Decode the real vertex stream: dump bytes at geometry start and try to
read consecutive BE doubles as (X,Y,Z) triples in the CSV's coordinate range."""
import sys, struct

path = sys.argv[1]
d = open(path, 'rb').read()

XMIN, XMAX = 60347.0, 60820.0
YMIN, YMAX = 213957.0, 214685.0
ZMIN, ZMAX = 512.0, 542.0

def be(off):
    return struct.unpack('>d', d[off:off+8])[0]

print('=== hex dump 8320..8480 ===')
for o in range(8320, 8480, 16):
    print(f'  {o:6d}: ' + ' '.join(f'{b:02x}' for b in d[o:o+16]))

print('\n=== scan 8252..9200: every offset where a BE double is in-range for X, Y, or Z ===')
for o in range(8252, 9200):
    v = be(o)
    tag = ''
    if XMIN <= v <= XMAX: tag = 'X'
    elif YMIN <= v <= YMAX: tag = 'Y'
    elif ZMIN <= v <= ZMAX: tag = 'Z'
    if tag:
        print(f'  @{o:6d}  {tag}={v:.4f}   prevbyte=0x{d[o-1]:02x}')

print('\n=== assume tightly-packed BE-double triples: try strides 24 and 25 from 8328 ===')
for start, stride in [(8328, 24), (8328, 25), (8328, 26), (8328, 27), (8328, 28)]:
    ok = 0
    rows = []
    for k in range(6):
        o = start + k*stride
        x, y, z = be(o), be(o+8), be(o+16)
        good = (XMIN<=x<=XMAX) and (YMIN<=y<=YMAX) and (ZMIN<=z<=ZMAX)
        if good: ok += 1
        rows.append(f'({x:.1f},{y:.1f},{z:.1f}){"*" if good else ""}')
    print(f'  start={start} stride={stride}: {ok}/6 valid  ' + ' '.join(rows))
