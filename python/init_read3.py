# init_read3.py — GT-FREE fold derivation test:
# Re-run the v5-P2 coord decode (rebuild_pipeline machinery) but record, per
# emitted slot, whether any contributing record was a FULL announcement
# ('F'/'Fe') and on which axis. Hypothesis: strip INIT fold slots n0 are
# FULL-announced slots (serpentine column boundaries visible in the coord
# stream itself) => n0 is DERIVED, encoder stores nothing.
import struct, re
import numpy as np
from collections import Counter

OOT = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(OOT, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
occ = [i for i in range(8326, len(d) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = len(d)
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break

def be(b): return struct.unpack('>d', bytes(b))[0]
def sane(v):
    a = abs(v); return (500 < a < 1000) or (50000 < a < 60000) or (160000 < a < 166000)
def band(v):
    x = abs(v)
    if 500 < x < 1000: return 2
    if 50000 < x < 60000: return 0
    if 160000 < x < 166000: return 1
    return -1
def full_at(pos):
    if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[pos:pos + 8])
        if sane(v): return v
    return None
toks = []; pos = 8350; lastT = None
while pos < face_start:
    b = d[pos]
    if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
        while pos < face_start and d[pos] == 0: pos += 1
        continue
    if full_at(pos) is not None:
        toks.append(('F', d[pos:pos + 8], lastT, None)); lastT = None; pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        toks.append(('Fe', d[pos + 1:pos + 9], lastT, None)); lastT = None; pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        toks.append(('V', d[pos + 1:end], lastT, b)); lastT = None; pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start: lastT = None; pos += 3; continue
    if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); pos += 2; continue
    pos += 1

def k0_rule(T, nb):
    if T is not None:
        T1, T2 = T
        if 0x21 <= T1 <= 0x3F: return 2
        if 0x40 <= T1 <= 0x5F: return 3
        if T1 == 0x20: return 3 if T2 < 0x60 else 2
    return {4: 3, 5: 3, 6: 2}.get(nb, max(0, 8 - nb))
def spl(R, payload, k0, c=0):
    nb = len(payload); end = k0 + nb
    if k0 < 0 or end > 8: return None
    bb = bytearray(R[:k0]) + bytearray(payload) + bytearray(R[end:])
    if c != 0:
        kk = k0 - 1
        if kk < 0: return None
        nv = bb[kk] + c
        if not (0 <= nv <= 255): return None
        bb[kk] = nv
    return bytes(bb)
def r2_value(R, payload, T, a):
    nb = len(payload)
    if nb == 0 or nb > 8: return None
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    vb = spl(R, payload, k0r)
    if vb is not None and band(be(vb)) == a: return vb
    for c in (-1, 1, -2, 2, -3, 3, -4, 4):
        vb = spl(R, payload, k0r, c)
        if vb is not None and band(be(vb)) == a: return vb
    pv = be(R); best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band(be(vb)) == a:
            dv = abs(be(vb) - pv)
            if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None

# instrumented run: per emitted slot, record FULL axes seen since last emit
regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
ph = 0
full_flags = [set()]   # slot 0: initial regs (treat as FULL-ish? keep empty)
pending = set()
npts = 1
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        regs[a][:] = t[1]
        pending.add(('F', a, t[0]))
        if a == 2 and ph == 2:
            full_flags.append(pending); pending = set(); npts += 1
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    vb = r2_value(bytes(regs[a]), payload, t[2], a)
    if vb is not None: regs[a][:] = vb
    if a == 2:
        full_flags.append(pending); pending = set(); npts += 1
    ph = (ph + 1) % 3

print(f'slots emitted: {npts}')
isfull = np.array([1 if f else 0 for f in full_flags])
print(f'FULL-announced slots: {isfull.sum()} / {len(isfull)} ({isfull.mean()*100:.1f}%)')
fx = np.array([1 if any(a == 0 for _, a, _ in f) else 0 for f in full_flags])
fy = np.array([1 if any(a == 1 for _, a, _ in f) else 0 for f in full_flags])
fz = np.array([1 if any(a == 2 for _, a, _ in f) else 0 for f in full_flags])
print(f'  by axis: X {fx.sum()}  Y {fy.sum()}  Z {fz.sum()}')

sites = []
for line in open('init_sites.txt'):
    m = re.match(r'gi=\s*(\d+) rid=\s*(\d+) n0=\s*(\d+) r=\s*(\d+)', line)
    if m: sites.append(tuple(map(int, m.groups())))

N = len(isfull)
def enrich(slots, name):
    slots = [s for s in slots if 0 <= s < N]
    h = sum(int(isfull[s]) for s in slots)
    hx = sum(int(isfull[max(s-1,0)] or isfull[s] or isfull[min(s+1,N-1)]) for s in slots)
    print(f'{name}: FULL@n {h}/{len(slots)} ({h/len(slots)*100:.0f}%)  FULL@n+-1 {hx}/{len(slots)} ({hx/len(slots)*100:.0f}%)  base {isfull.mean()*100:.1f}%')

enrich([n0 for _,_,n0,_ in sites], 'n0 slots ')
enrich([r  for _,_,_,r  in sites], 'r slots  (control)')
import random
random.seed(1)
enrich(random.sample(range(N), 57), 'random 57 (control)')

# distance from each n0 to nearest FULL slot
fs = np.where(isfull)[0]
dists = [int(np.min(np.abs(fs - n0))) for _,_,n0,_ in sites]
print('n0 -> nearest FULL slot distance census:', Counter(dists).most_common(12))
rd = [int(np.min(np.abs(fs - s))) for s in random.sample(range(N), 500)]
print('random -> nearest FULL distance census:', Counter(rd).most_common(12))
np.save('full_flags.npy', np.stack([isfull, fx, fy, fz]))
print('saved full_flags.npy')
