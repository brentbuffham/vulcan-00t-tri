#!/usr/bin/env python3
"""Probe the Fe branch: what is the byte at pos+9 (the extra byte the 10-byte
Fe consumption swallows)? Is it the lead of a real next record (esp. a FULL)?
GT-free analysis (bands from file bytes only). Usage: python fe_probe.py <case>
"""
import struct, sys
from collections import Counter
import numpy as np

CASES = {
    'intercepts': r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t',
    'SYLVANIA':   r'C:/Users/brent/Downloads/eph_20170720_SYLVANIA_Surv_topo.00t',
    'OB34':       r'C:/Users/brent/Downloads/eph_20170820_OB34_Surv_Topo.00t',
}
case = sys.argv[1] if len(sys.argv) > 1 else 'intercepts'
d = open(CASES[case], 'rb').read(); n = len(d)
def be(b): return struct.unpack('>d', bytes(b))[0]
geo_end = struct.unpack('<15i', d[0:60])[11]
def coordlike(v): return np.isfinite(v) and 1 < abs(v) < 1e7
seed_off = None
for off in range(8240, 8400):
    vs = [be(d[off + 8 * k:off + 8 * k + 8]) for k in range(3) if off + 8 * k + 8 <= n]
    if len(vs) == 3 and all(coordlike(v) for v in vs):
        seed_off = off; break
coord_start = seed_off + 24
occ = [i for i in range(seed_off, min(n, geo_end) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = min(n, geo_end)
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break
SEED = [abs(be(d[seed_off + 8 * k:seed_off + 8 * k + 8])) for k in range(3)]
def make_band(rng):
    (a0, b0), (a1, b1), (a2, b2) = rng
    def band(v):
        x = abs(v)
        if a2 <= x <= b2: return 2
        if a0 <= x <= b0: return 0
        if a1 <= x <= b1: return 1
        return -1
    return band
RATIO = 1.15
bk = {0: [], 1: [], 2: []}
_pos = coord_start
while _pos + 8 <= face_start:
    if d[_pos] in (0x40, 0x41, 0xC0, 0xC1):
        _v = abs(be(d[_pos:_pos + 8]))
        if np.isfinite(_v) and _v > 0:
            _r = [max(_v, s) / min(_v, s) for s in SEED]
            _a = int(np.argmin(_r))
            if _r[_a] < RATIO: bk[_a].append(_v)
    _pos += 1
LOOSE = [(np.array(bk[a]).min(), np.array(bk[a]).max()) if len(bk[a]) >= 1 else (SEED[a] / 1.5, SEED[a] * 1.5) for a in range(3)]
def make_full_at(band):
    def full_at(pos):
        if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
            v = be(d[pos:pos + 8])
            if band(v) >= 0: return v
        return None
    return full_at
def tokenize(full_at):
    toks = []; pos = coord_start; lastT = None
    while pos < face_start:
        b = d[pos]
        if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
            while pos < face_start and d[pos] == 0: pos += 1
            continue
        if full_at(pos) is not None:
            toks.append(('F', d[pos:pos + 8], lastT, None, pos)); lastT = None; pos += 8; continue
        if b >= 0x20 and full_at(pos + 1) is not None:
            toks.append(('Fe', d[pos + 1:pos + 9], lastT, b, pos)); lastT = None; pos += 10; continue
        if b < 0x20:
            nb = (b & 7) + 1; end = pos + 1 + nb
            for j in range(pos + 1, min(end, face_start)):
                if full_at(j) is not None: end = j; break
            if end > face_start: end = face_start
            toks.append(('V', d[pos + 1:end], lastT, b, pos)); lastT = None; pos = end; continue
        if 0xe0 <= b <= 0xff and pos + 3 <= face_start: lastT = None; pos += 3; continue
        if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); pos += 2; continue
        pos += 1
    return toks
band1 = make_band(LOOSE); toks1 = tokenize(make_full_at(band1))
def shorth(vals, frac=0.5):
    v = np.sort(np.asarray(vals)); m = len(v)
    if m == 0: return (np.nan, np.nan)
    k = max(1, int(np.ceil(frac * m)))
    if k >= m: return (v[0], v[-1])
    w = v[k - 1:] - v[:m - k + 1]; i = int(np.argmin(w))
    return (v[i], v[i + k - 1])
fr = {0: [], 1: [], 2: []}
for t in toks1:
    if t[0] in ('F', 'Fe'):
        a = band1(be(t[1]))
        if a >= 0: fr[a].append(abs(be(t[1])))
TIGHT = []
for a in range(3):
    if len(fr[a]) >= 3:
        lo, hi = shorth(fr[a]); w = max(hi - lo, 1e-6); TIGHT.append((lo - 5 * w, hi + 5 * w))
    else:
        TIGHT.append(LOOSE[a])
band = make_band(TIGHT); full_at = make_full_at(band)
toks = tokenize(full_at)

fe = [t for t in toks if t[0] == 'Fe']
f_ = [t for t in toks if t[0] == 'F']
print(f'== {case} ==  tokens {len(toks)}  F {len(f_)}  Fe {len(fe)}')

# the swallowed byte d[pos+9]
sw = Counter(); swallow_full = 0; swallow_fullbyte = Counter()
for t in fe:
    p = t[4]; b9 = d[p + 9] if p + 9 < face_start else None
    sw[b9] += 1
    if p + 9 < face_start and full_at(p + 9) is not None:
        swallow_full += 1
    if b9 in (0x40, 0x41, 0xC0, 0xC1):
        swallow_fullbyte[b9] += 1
print(f'Fe swallowed-byte d[pos+9] histogram (top 20): {sw.most_common(20)}')
print(f'Fe where d[pos+9] is a FULL lead byte (40/41/C0/C1): {sum(swallow_fullbyte.values())}/{len(fe)}  {dict(swallow_fullbyte)}')
print(f'Fe where full_at(pos+9) fires (a real in-band FULL starts at the swallowed byte): {swallow_full}/{len(fe)}')

# compare: what does the byte at pos+9 vs pos+10 look like as a record lead
def leadclass(b):
    if b is None: return 'EOF'
    if b < 0x20: return 'V'
    if 0xe0 <= b: return 'e0'
    if b in (0x40, 0x41, 0xC0, 0xC1): return 'Flead'
    return 'T/esc'
c9 = Counter(leadclass(d[t[4] + 9]) if t[4] + 9 < face_start else 'EOF' for t in fe)
c10 = Counter(leadclass(d[t[4] + 10]) if t[4] + 10 < face_start else 'EOF' for t in fe)
print(f'lead-class of byte at pos+9  (first byte AFTER double if consumption were 9): {dict(c9)}')
print(f'lead-class of byte at pos+10 (first byte after 10-byte consumption):          {dict(c10)}')

# also: the escape byte itself and the byte BEFORE the Fe: is the escape byte
# really byte2 of a 2-byte T record whose byte1 was already consumed?
pre = Counter(leadclass(d[t[4] - 1]) for t in fe if t[4] - 1 >= coord_start)
print(f'lead-class of byte BEFORE Fe escape byte: {dict(pre)}')

# F branch: how many F tokens start at a position that is INSIDE the previous
# token's natural extent (i.e. V-truncation fired)?  count truncated V tokens
vt = [t for t in toks if t[0] == 'V' and len(t[1]) != ((t[3] & 7) + 1)]
print(f'V tokens truncated by an inner FULL: {len(vt)}/{sum(1 for t in toks if t[0]=="V")}')
# dump a few truncated V sites
for t in vt[:8]:
    p = t[4]; nb = (t[3] & 7) + 1
    print(f'  V@${p} lead {t[3]:02x} nb {nb} got {len(t[1])}  bytes {d[p:p+1+nb+8].hex()}')
