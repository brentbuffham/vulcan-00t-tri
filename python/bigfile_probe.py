#!/usr/bin/env python3
"""Structural probe for an arbitrary .00t (works on large production files).
Validates: page directory, geometry start, e0..40 17 record markers,
ASCII attribute-block boundary, embedded PNG tail."""
import sys, struct, re

path = sys.argv[1]
d = open(path, 'rb').read()
n = len(d)
print(f'size = {n:,} bytes  ({n/2048:.1f} pages)')

# 1) header
hdr = struct.unpack('<15i', d[0:60])
print('header int32[0:15]:', hdr)

# 2) front page directory: follow the 2-byte LE next-page links from offset 60
print('\n-- front page-directory links --')
off = 60
for _ in range(8):
    if off + 2 > n: break
    nxt = d[off] | (d[off+1] << 8)
    payload = d[off+2:off+2048]
    nz = payload.count(0) / max(len(payload), 1)
    print(f'  @{off:7d}  link2={nxt}(0x{nxt:04x})  zero={nz*100:4.1f}%')
    if nz < 0.99:  # first non-empty page = geometry start
        print(f'  -> geometry starts here (@{off})')
        break
    off += 2048

# 3) e0 ?? 14 20 00 40 17 record markers across whole file
marks = [m.start() for m in re.finditer(rb'\xe0.\x14\x20\x00\x40\x17', d)]
print(f'\n-- e0..40 17 record markers: count={len(marks):,} --')
if marks:
    print(f'  first={marks[0]}  last={marks[-1]}')
    gaps = [marks[i+1]-marks[i] for i in range(len(marks)-1)]
    if gaps:
        from collections import Counter
        top = Counter(gaps).most_common(8)
        print('  most common gaps (bytes between markers):', top)
        print(f'  gap min/median/max: {min(gaps)} / {sorted(gaps)[len(gaps)//2]} / {max(gaps)}')

# 4) ASCII attribute keywords + their first offsets (region boundary hints)
print('\n-- attribute / metadata keyword offsets --')
for kw in [b'Created External', b'colour_by', b'WIREFRAME', b'NAME',
           b'SHADED', b'UserAttributes', b'PATTERN', b'LAYER', b'DATABAS']:
    i = d.find(kw)
    print(f'  {kw.decode():16s}: {i}' + ('' if i < 0 else f'  (0x{i:x})'))

# 5) embedded PNG?
png = d.find(b'\x89PNG')
iend = d.rfind(b'IEND')
print(f'\n-- embedded PNG: start={png}  IEND={iend} --')

# 6) where does the bulk binary geometry live? scan for the largest run with
#    NO ascii keyword and high entropy-ish (non-zero, non-ascii density).
print('\n-- coarse 64KB block map (a=ascii%, z=zero%) --')
BLK = 65536
for b0 in range(0, n, BLK):
    blk = d[b0:b0+BLK]
    az = sum(1 for c in blk if 32 <= c < 127) / len(blk)
    zz = blk.count(0) / len(blk)
    bar = 'A' if az > 0.6 else ('.' if zz > 0.6 else '#')
    if b0 < 3*BLK or b0 > n - 3*BLK or bar != '#':
        print(f'  @{b0:9d}  {bar}  ascii={az*100:4.1f}%  zero={zz*100:4.1f}%')
