#!/usr/bin/env python3
"""Derive the axis-transition rule from production. For each coord record,
assign its axis via the GT grid (oracle), then tabulate the SEP byte that
precedes it against the transition (newaxis - prevaxis) mod 3.
If each SEP -> one dominant transition, the SEP is a deterministic axis selector
and we can decode WITHOUT ground truth (validates/generalises toy rule W2)."""
import sys, struct
from collections import defaultdict, Counter
import numpy as np

oot = sys.argv[1]; cachedir = sys.argv[2]
gt = {0: np.load(f'{cachedir}/gt_x.npy'), 1: np.load(f'{cachedir}/gt_y.npy'), 2: np.load(f'{cachedir}/gt_z.npy')}

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

prev = {0: bytes(d[8328:8336]), 1: bytes(d[8336:8344]), 2: bytes(d[8344:8352])}
TOL = 0.006; ZLO, ZHI = 511.0, 543.0
NAMES = {0:'STAY', 1:'FWD(+1)', 2:'BACK(-1)'}
sep_trans = defaultdict(Counter)   # sep -> Counter(transition)
prev_axis = 2                      # vertex 0 ended on Z
last_sep = None
pos = 8328 + 24
ncoord = 0
while pos < geo_end:
    b = d[pos]
    if b <= 0x06:
        nb = b + 1
        payload = bytes(d[pos+1:pos+1+nb]); pos += 1 + nb
        if len(payload) != nb or (payload and payload[0] in FULL_IND):
            continue
        cx = be(prev[0][:8-nb]+payload); cy = be(prev[1][:8-nb]+payload); cz = be(prev[2][:8-nb]+payload)
        if on_grid(cx,0,TOL): ax = 0
        elif on_grid(cy,1,TOL): ax = 1
        elif ZLO <= cz <= ZHI: ax = 2
        else:
            continue   # topology / non-coord — don't advance the axis cycle
        prev[ax] = (prev[ax][:8-nb]+payload+b'\x00'*8)[:8]
        trans = (ax - prev_axis) % 3
        if last_sep is not None:
            sep_trans[last_sep][trans] += 1
        prev_axis = ax
        ncoord += 1
    elif is_sep(b):
        last_sep = b; pos += 1
    elif (b & 0xE0) in TAG_CLASSES:
        pos += 1
    else:
        pos += 1

print(f'coord records scored: {ncoord:,}\n')
print(f"{'SEP':>5} {'n':>10}  {'STAY':>7} {'FWD+1':>7} {'BACK-1':>7}   dominant  purity")
rows = sorted(sep_trans.items(), key=lambda kv: -sum(kv[1].values()))
clean = 0; total = 0
for sep, c in rows:
    tot = sum(c.values())
    if tot < 2000: continue
    dom, dn = c.most_common(1)[0]
    purity = dn / tot
    total += tot
    if purity >= 0.9: clean += tot
    print(f"0x{sep:02x} {tot:>10,}  {c[0]/tot*100:6.1f}% {c[1]/tot*100:6.1f}% {c[2]/tot*100:6.1f}%   "
          f"{NAMES[dom]:>8}  {purity*100:5.1f}%")
print(f'\nrecords whose SEP predicts axis-transition at >=90% purity: {clean/total*100:.1f}%')
