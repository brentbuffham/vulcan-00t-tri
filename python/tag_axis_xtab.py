#!/usr/bin/env python3
"""Cross-tabulate the TAG byte preceding each record against the axis the
grid-greedy model assigns it to. If tag -> axis is deterministic, we can
drop the ground-truth grid lookup and decode any file."""
import sys, struct
from collections import Counter, defaultdict
import numpy as np

oot = sys.argv[1]
cachedir = sys.argv[2]
gt = {ax: np.load(f'{cachedir}/gt_{ax}.npy') for ax in 'xyz'}

def on_grid(v, ax, tol):
    a = gt[ax]; i = np.searchsorted(a, v)
    if i <= 0: return abs(a[0]-v) < tol
    if i >= len(a): return abs(a[-1]-v) < tol
    return min(abs(a[i]-v), abs(a[i-1]-v)) < tol

def be(raw): return struct.unpack('>d', (raw + b'\x00'*8)[:8])[0]

d = open(oot, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
TAG_CLASSES = (0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
FULL_IND = (0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b & 0x07) == 0x07 and b >= 0x07

prev = {'x': bytes(d[8328:8336]), 'y': bytes(d[8336:8344]), 'z': bytes(d[8344:8352])}
TOL = 0.006; ZLO, ZHI = 511.0, 543.0
xtab = defaultdict(Counter)        # tag -> Counter(axis)
sep_xtab = defaultdict(Counter)    # sep byte -> Counter(axis)
taglo_xtab = defaultdict(Counter)  # tag low nibble -> axis
last_tag = None; last_sep = None
pos = 8328 + 24
while pos < geo_end:
    b = d[pos]
    if b <= 0x06:
        nb = b + 1
        payload = bytes(d[pos+1:pos+1+nb]); pos += 1 + nb
        if len(payload) != nb or (payload and payload[0] in FULL_IND):
            continue
        cx = be(prev['x'][:8-nb]+payload); cy = be(prev['y'][:8-nb]+payload); cz = be(prev['z'][:8-nb]+payload)
        if on_grid(cx,'x',TOL): ax = 'x'
        elif on_grid(cy,'y',TOL): ax = 'y'
        elif ZLO <= cz <= ZHI: ax = 'z'
        else: ax = 'none'
        if ax != 'none':
            prev[ax] = (prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
        xtab[last_tag][ax] += 1
        sep_xtab[last_sep][ax] += 1
        if last_tag is not None:
            taglo_xtab[last_tag & 0x0f][ax] += 1
    elif is_sep(b):
        last_sep = b; pos += 1
    elif (b & 0xE0) in TAG_CLASSES:
        last_tag = b; pos += 1
    else:
        pos += 1

print('=== TAG byte -> axis assignment ===')
for tag in sorted(xtab, key=lambda t: -sum(xtab[t].values())):
    c = xtab[tag]; tot = sum(c.values())
    if tot < 1000: continue
    th = f'0x{tag:02x}' if tag is not None else 'None'
    frac = '  '.join(f'{ax}={c[ax]/tot*100:4.0f}%' for ax in ('x','y','z','none'))
    print(f'  tag {th:>5} (n={tot:>9,}): {frac}')

print('\n=== TAG low-nibble -> axis ===')
for lo in sorted(taglo_xtab):
    c = taglo_xtab[lo]; tot = sum(c.values())
    if tot < 1000: continue
    frac = '  '.join(f'{ax}={c[ax]/tot*100:4.0f}%' for ax in ('x','y','z','none'))
    print(f'  lo 0x{lo:x} (n={tot:>9,}): {frac}')

print('\n=== SEP byte -> axis ===')
for sep in sorted(sep_xtab, key=lambda s: -sum(sep_xtab[s].values())):
    c = sep_xtab[sep]; tot = sum(c.values())
    if tot < 1000: continue
    sh = f'0x{sep:02x}' if sep is not None else 'None'
    frac = '  '.join(f'{ax}={c[ax]/tot*100:4.0f}%' for ax in ('x','y','z','none'))
    print(f'  sep {sh:>5} (n={tot:>9,}): {frac}')
