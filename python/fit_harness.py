#!/usr/bin/env python3
"""Fit the coord reconstruction against ground truth.
Hypothesis: each count-record's payload = significant bytes of a BE double with
a fixed per-axis 2-byte prefix and zero-filled tail.
Walk the stream, bucket records by payload length (nb), and measure how many
decode to a known X/Y/Z value. Brute-force the prefix per bucket if asked."""
import sys, struct
import numpy as np

oot = sys.argv[1]
cachedir = sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else 'test'   # 'test' | 'brute'

gt = {ax: np.load(f'{cachedir}/gt_{ax}.npy') for ax in 'xyz'}
TOL = 0.02

def hits(vals, ax):
    a = gt[ax]
    v = np.asarray(vals, dtype=np.float64)
    idx = np.searchsorted(a, v)
    idx = np.clip(idx, 1, len(a) - 1)
    d1 = np.abs(a[idx] - v)
    d0 = np.abs(a[idx - 1] - v)
    return np.minimum(d0, d1) < TOL

# ---- walk the stream, collect (nb, payload bytes) ----
d = open(oot, 'rb').read()
hdr = struct.unpack('<15i', d[0:60])
geo_end = hdr[11]
TAG_CLASSES = (0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0)
FULL_IND = (0x40, 0x41, 0xC0, 0xC1)
def is_sep(b): return (b & 0x07) == 0x07 and b >= 0x07

buckets = {}   # nb -> list of payloads (as tuples)
pos = 8328 + 24
nrec = 0
while pos < geo_end:
    b = d[pos]
    if b <= 0x06:
        nb = b + 1
        payload = d[pos + 1:pos + 1 + nb]
        if len(payload) == nb and not (payload and payload[0] in FULL_IND):
            buckets.setdefault(nb, []).append(payload)
            nrec += 1
        pos += 1 + nb
    elif is_sep(b):
        pos += 1
    elif (b & 0xE0) in TAG_CLASSES:
        pos += 1
    else:
        pos += 1

print(f'total coord-records: {nrec:,}')
for nb in sorted(buckets):
    print(f'  nb={nb}: {len(buckets[nb]):,} records')

def recon(payloads, prefix2, total=8):
    """double = prefix2(2 bytes) + payload + zero fill to `total` bytes."""
    out = np.empty(len(payloads), dtype=np.float64)
    pre = bytes([(prefix2 >> 8) & 0xff, prefix2 & 0xff])
    for i, p in enumerate(payloads):
        raw = pre + bytes(p)
        raw = raw + b'\x00' * (8 - len(raw))
        out[i] = struct.unpack('>d', raw[:8])[0]
    return out

PREFIX = {'x': 0x40ed, 'y': 0x410a, 'z': 0x4080}

if mode == 'test':
    print('\n=== hypothesis test (X=40ed Y=410a Z=4080) ===')
    for nb in sorted(buckets):
        pls = buckets[nb][:200000]
        for ax in 'xyz':
            vals = recon(pls, PREFIX[ax])
            h = hits(vals, ax)
            print(f'  nb={nb}  prefix {ax}=0x{PREFIX[ax]:04x}: '
                  f'{h.mean()*100:5.1f}% in gt_{ax}  ({h.sum():,}/{len(h):,})')
        # examples
        ax = 'z' if nb == 3 else 'x'
        vals = recon(pls[:5], PREFIX[ax])
        print(f'    e.g. nb={nb} as {ax}:', [f'{v:.3f}' for v in vals])

elif mode == 'brute':
    print('\n=== brute-force best 2-byte prefix per bucket ===')
    for nb in sorted(buckets):
        pls = buckets[nb][:4000]
        best = []
        for pre in range(0x4000, 0x4200):   # exponent band around 0x40xx/0x41xx
            vals = recon(pls, pre)
            for ax in 'xyz':
                hr = hits(vals, ax).mean()
                if hr > 0.5:
                    best.append((hr, pre, ax))
        best.sort(reverse=True)
        print(f'  nb={nb}: top prefixes ' +
              ', '.join(f'{ax}:0x{pre:04x}={hr*100:.0f}%' for hr, pre, ax in best[:5]))
