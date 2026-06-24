#!/usr/bin/env python3
"""Decisive probe: is there a per-page header inside the geometry region,
or is the data contiguous after the page-4 start?"""
import struct, os

def dump(stem, offs):
    d = open(f'exampleFiles/{stem}.00t', 'rb').read()
    print(f'=== {stem}  size={len(d)}  ({len(d)/2048:.2f} pages) ===')
    hdr = struct.unpack('<15i', d[0:60])
    print('  header int32[0:15]:', hdr)
    for o in offs:
        chunk = d[o:o+32]
        print(f'  @{o}: ' + ' '.join(f'{b:02x}' for b in chunk))
    print()

dump('tri-crack-solid', [8252])
dump('tri-crack-SPHERE', [8252, 10300])

# Hex window straddling the page-5 boundary (10300) in SPHERE
d = open('exampleFiles/tri-crack-SPHERE.00t', 'rb').read()
print('SPHERE bytes 10288..10320 (boundary at 10300):')
print('  off : ' + ' '.join(f'{i:5d}' for i in range(10288, 10320, 4)))
print('  hex : ' + ' '.join(f'{b:02x}' for b in d[10288:10320]))

# For every file: walk page boundaries from 8252 in 2048 strides, print the
# 2 bytes that sit exactly on each boundary AND whether they look like a
# next-page pointer (== boundary_offset + 2048 - some base).
print('\n--- page-boundary 2-byte values within geometry region ---')
for stem in ['tri-crack-solid', 'tri-crack', 'tri-crack-SPHERE',
             'tri-crack-Hexhole', 'tri-crack-NonRound', 'cube']:
    p = f'exampleFiles/{stem}.00t'
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    vals = []
    off = 8252
    while off + 2 <= n:
        v = d[off] | (d[off+1] << 8)
        vals.append(f'@{off}={v}(0x{v:04x})')
        off += 2048
    print(f'  {stem:22s}: ' + '  '.join(vals))
