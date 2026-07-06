#!/usr/bin/env python3
"""Compare the loose sliding-window FULL harvest vs framed-tokenizer FULLs.
Question: can a TIGHT per-axis range be derived GT-free (framed FULLs +
robust outlier rejection)? GT printed for DIAGNOSTIC comparison only."""
import struct
import numpy as np

d = open(r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t', 'rb').read(); n = len(d)
occ = [i for i in range(8326, n - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = n
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90:
        face_start = occ[k]; break
def be(b): return struct.unpack('>d', bytes(b))[0]
RATIO = 1.15
SEED = [abs(be(d[8326:8334])), abs(be(d[8334:8342])), abs(be(d[8342:8350]))]

# --- pass 1: loose sliding-window harvest (current v6 behavior) ---
bk = {0: [], 1: [], 2: []}
pos = 8350
while pos + 8 <= face_start:
    if d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = abs(be(d[pos:pos + 8]))
        if np.isfinite(v) and v > 0:
            r = [max(v, s) / min(v, s) for s in SEED]
            a = int(np.argmin(r))
            if r[a] < RATIO: bk[a].append(v)
    pos += 1
print('LOOSE harvest (every byte offset):')
for a in range(3):
    b = np.sort(np.array(bk[a]))
    print(f'  axis{a}: n={len(b)} min={b.min():.2f} p1={np.percentile(b,1):.2f} '
          f'p5={np.percentile(b,5):.2f} med={np.median(b):.2f} '
          f'p95={np.percentile(b,95):.2f} p99={np.percentile(b,99):.2f} max={b.max():.2f}')

# --- pass 2: framed FULLs via the tokenizer (uses loose band for framing) ---
(XL, XH), (YL, YH), (ZL, ZH) = [(np.array(bk[a]).min(), np.array(bk[a]).max()) for a in range(3)]
def band(v):
    x = abs(v)
    if ZL <= x <= ZH: return 2
    if XL <= x <= XH: return 0
    if YL <= x <= YH: return 1
    return -1
def full_at(pos):
    if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[pos:pos + 8])
        if band(v) >= 0: return v
    return None
framed = {0: [], 1: [], 2: []}
pos = 8350; lastT = None
while pos < face_start:
    b = d[pos]
    if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
        while pos < face_start and d[pos] == 0: pos += 1
        continue
    v = full_at(pos)
    if v is not None:
        framed[band(v)].append((pos, v)); pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        v = full_at(pos + 1); framed[band(v)].append((pos + 1, v)); pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start: pos += 3; continue
    if pos + 2 <= face_start: pos += 2; continue
    pos += 1
print('\nFRAMED FULLs (tokenizer):')
for a in range(3):
    if not framed[a]:
        print(f'  axis{a}: none'); continue
    vals = np.sort(np.array([abs(v) for _, v in framed[a]]))
    print(f'  axis{a}: n={len(vals)} min={vals.min():.2f} p5={np.percentile(vals,5):.2f} '
          f'med={np.median(vals):.2f} p95={np.percentile(vals,95):.2f} max={vals.max():.2f}')
    # show the outliers vs the bulk
    lo = np.percentile(vals, 10); hi = np.percentile(vals, 90)
    out = [(p, v) for p, v in framed[a] if not (lo <= abs(v) <= hi)]
    print(f'    bulk10-90=[{lo:.1f}..{hi:.1f}]  n_outside={len(out)}')

# --- GT diagnostic only ---
gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
print('\n[DIAGNOSTIC ONLY] GT per-axis ranges:')
for a in range(3):
    print(f'  axis{a}: [{Gu[:, a].min():.3f} .. {Gu[:, a].max():.3f}]')
