#!/usr/bin/env python3
"""AUDIT: are the hardcoded axis ranges (500-1000, 50000-60000, 160000-166000)
derivable from the .00t ALONE, with no DXF/CSV? If the file's own FULL records
(self-contained 8-byte doubles) cluster into 3 ranges that match, then the ranges
are a property of the file, not answer-derived. Prints the evidence.
NO GT loaded anywhere in this script.
"""
import struct
import numpy as np

OOT = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(OOT, 'rb').read()
n = len(d)

# geometry section bounds (same GT-free framing the decoder uses)
occ = [i for i in range(8326, n - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = n
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break

def be(pos): return struct.unpack('>d', d[pos:pos + 8])[0]

# --- 1. header scan: any little/big-endian doubles that look like a bounding box? ---
print('=== header/prelude double scan (offsets 0..8350) ===')
hdr_hits = []
for pos in range(0, 8350 - 8):
    for tag, fmt in (('LE', '<d'), ('BE', '>d')):
        try:
            v = struct.unpack(fmt, d[pos:pos + 8])[0]
        except Exception:
            continue
        a = abs(v)
        if np.isfinite(v) and (100 < a < 200000) and a == a:
            # only report plausible coordinate-magnitude doubles
            if 400 < a < 200000:
                hdr_hits.append((pos, tag, v))
for pos, tag, v in hdr_hits[:60]:
    print(f'  @{pos:5d} {tag} {v: .4f}')
print(f'  ...{len(hdr_hits)} plausible header doubles total')

# --- 2. the 3 init registers (vertex 0) read straight from the file ---
print('\n=== init registers @8326 (vertex 0, GT-free) ===')
for i, off in enumerate((8326, 8334, 8342)):
    print(f'  reg{i} @{off}: {be(off): .4f}')

# --- 3. collect ALL self-contained FULL doubles in the coord section ---
# A FULL is an 8-byte IEEE double lead-tagged 0x40/41/C0/C1. Read them WITHOUT
# any range gate, then look at their natural distribution.
fulls = []
pos = 8350
while pos + 8 <= face_start:
    if d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(pos)
        if np.isfinite(v) and abs(v) < 1e12:
            fulls.append(abs(v))
    pos += 1
fulls = np.array(sorted(fulls))
print(f'\n=== {len(fulls)} candidate FULL doubles (|v|<1e12), no range gate ===')
# histogram on log10 to reveal natural clusters
finite = fulls[fulls > 1e-6]
lg = np.log10(finite)
hist, edges = np.histogram(lg, bins=np.arange(0, 7.1, 0.25))
for h, e in zip(hist, edges[:-1]):
    if h: print(f'  10^{e:.2f}..10^{e+0.25:.2f}  ({10**e:12.1f}): {"#"*min(h//20+1,50)} {h}')

# --- 4. cluster the plausible-coordinate FULLs into ranges, GT-free ---
# keep only magnitudes in a broad coordinate window, then find gaps
cand = finite[(finite > 100) & (finite < 500000)]
cand = np.array(sorted(cand))
if len(cand):
    gaps = np.diff(cand)
    # a "range boundary" = a gap much larger than typical spacing
    thr = np.percentile(gaps, 99) * 5 if len(gaps) else 0
    bounds = [cand[0]]
    ranges = []
    lo = cand[0]
    for i in range(1, len(cand)):
        if cand[i] - cand[i-1] > max(thr, 1000):
            ranges.append((lo, cand[i-1])); lo = cand[i]
    ranges.append((lo, cand[-1]))
    print('\n=== DERIVED axis ranges from FULL clustering (GT-FREE) ===')
    for lo, hi in ranges:
        cnt = ((cand >= lo) & (cand <= hi)).sum()
        print(f'  [{lo:12.2f} .. {hi:12.2f}]  n={cnt}')
    print('\nHardcoded ranges to compare:  500-1000, 50000-60000, 160000-166000')
