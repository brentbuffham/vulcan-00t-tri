#!/usr/bin/env python3
"""Phase 9: FINAL extraction + clean scoring.
Refined grammar (state-framed):
  delim 'e0/e1 xx' | marker 0x00 | first-op (2B) | body tokens:
    '01 hh ll'            -> ABSOLUTE ref (<=2974)
    '00 pp' with pp>=0x80 -> SHORT ref: low byte pp, high = nearest congruent
                             to prev ref (mod 256); reject if >2974
    '00 pp' pp<0x80       -> structural (NOT a ref) — undecoded field classes
    0x02-0x06             -> 1-byte unknown (old multibyte rule REJECTED:
                             it swallowed real refs and even delimiters)
    0x08-0x1f             -> pad
    else                  -> 2-byte op
Scoring (categories stated):
  A same-group ref-pair GT-edge rate (GT=labeling)  [primary; baseline 15%]
  B same-group |d|=1 rate (GT-free)
  C GT-edge rate split by |d|=1 vs |d|!=1
  D ref range sanity + boundary refs in (2963,2974]
Sweep: splice base = prev-any / prev-same-group / last-abs; congruent vs keep-high.
"""
import struct, pickle
import numpy as np
from collections import Counter, defaultdict

RAW = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(RAW, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
occ = [i for i in range(8326, len(d)-2) if d[i] == 0xE0 and d[i+1] == 0x03]
face_start = len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k] < 90: face_start = occ[k]; break

F = np.load('faces_gt.npy')
E = set()
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)): E.add((min(u, v), max(u, v)))
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))


def extract(base='prev', congruent=True, reject_zero=False, skip_01hdr=False):
    pos = face_start; groups = []; cur = None
    prev_ref = 0; last_abs = 0
    state = 'body'
    def ng(delim, p): return {'delim': delim, 'pos': p, 'refs': [], 'forms': []}
    while pos < geo_end:
        b = d[pos]
        if b in (0xE0, 0xE1):
            if cur: groups.append(cur)
            cur = ng(d[pos:pos+2].hex(), pos); pos += 2
            state = 'delim0'; continue
        if cur is None: cur = ng('HEAD', pos); state = 'body'
        if state == 'delim0':
            if b == 0x00: pos += 1
            state = 'firstop'; continue
        if state == 'firstop':
            if b >= 0x20:          # first-op only if op-range lead
                cur['fop'] = d[pos:pos+2].hex()
                pos += 2
            elif b == 0x01:        # header triple '01 hh ll' = NOT a ref
                cur['fop'] = d[pos:pos+3].hex()
                cur['is01'] = True
                pos += 3
            state = 'body'; continue
        if b == 0x00:
            p = d[pos+1] if pos+1 < geo_end else 0
            if p >= 0x80 and not (skip_01hdr and cur.get('is01')):
                if base == 'abs': bs = last_abs
                elif base == 'group': bs = cur['refs'][-1] if cur['refs'] else prev_ref
                else: bs = prev_ref
                if congruent:
                    r = p + 256*round((bs - p)/256)
                    if r < 0: r += 256
                else:
                    r = (bs & ~0xFF) | p
                if 0 <= r <= 2974:
                    cur['refs'].append(r); cur['forms'].append('S')
                    prev_ref = r
            pos += 2; state = 'body'; continue
        if b == 0x01:
            v = int.from_bytes(d[pos+1:pos+3], 'big')
            if v <= 2974 and not (reject_zero and v == 0) \
                    and not (skip_01hdr and cur.get('is01')):
                cur['refs'].append(v); cur['forms'].append('A')
                prev_ref = v; last_abs = v
            pos += 3; state = 'body'; continue
        if 0x02 <= b <= 0x06: pos += 1; state = 'body'; continue
        if 0x08 <= b < 0x20: pos += 1; state = 'body'; continue
        pos += 2; state = 'body'; continue
    if cur: groups.append(cur)
    return groups


def report(groups, label):
    allr = [r for g in groups for r in g['refs']]
    ar = np.array(allr)
    pairs = d1 = 0
    hit = tot = 0
    h1 = t1 = hx = tx = 0
    for g in groups:
        rs = g['refs']
        if len(rs) < 2 or len(rs) > 4: continue
        for i in range(1, len(rs)):
            r1, r2 = rs[i-1], rs[i]
            if r1 == r2: continue
            pairs += 1
            adj = abs(r2-r1) == 1
            if adj: d1 += 1
            a, b = map11.get(r1), map11.get(r2)
            if a is None or b is None or a == b: continue
            tot += 1
            ok = (min(a, b), max(a, b)) in E
            if ok: hit += 1
            if adj:
                t1 += 1; h1 += ok
            else:
                tx += 1; hx += ok
    bd = ((ar > 2963) & (ar <= 2974)).sum()
    print(f'{label}')
    print(f'  refs={len(allr)} range[{ar.min()},{ar.max()}] boundary(2963,2974]:{bd}')
    print(f'  same-group pairs={pairs}  |d|=1: {d1} ({100*d1/max(pairs,1):.1f}%)  [GT-free]')
    print(f'  GT-edge (mapped pairs): {hit}/{tot} = {100*hit/max(tot,1):.1f}%  [GT-labeled]')
    print(f'    |d|=1 pairs:  {h1}/{t1} = {100*h1/max(t1,1):.1f}%')
    print(f'    |d|!=1 pairs: {hx}/{tx} = {100*hx/max(tx,1):.1f}%')
    return groups


for label, kw in [
    ('FINAL base=prev congruent', dict()),
    ('base=prev keep-high', dict(congruent=False)),
    ('keep-high +reject0', dict(congruent=False, reject_zero=True)),
    ('keep-high +reject0 +skip01hdr', dict(congruent=False, reject_zero=True,
                                           skip_01hdr=True)),
    ('congruent +reject0 +skip01hdr', dict(reject_zero=True, skip_01hdr=True)),
]:
    g = report(extract(**kw), label)

groups = extract(congruent=False, reject_zero=True, skip_01hdr=True)
pickle.dump(groups, open('refs_v2.pkl', 'wb'))
print('\nsaved refs_v2.pkl (FINAL extraction)')

# dump the surviving fails for the record
print('\n--- FINAL fails (mapped, non-edge) ---')
for gi, g in enumerate(groups):
    rs = g['refs']
    if len(rs) < 2 or len(rs) > 4: continue
    for i in range(1, len(rs)):
        r1, r2 = rs[i-1], rs[i]
        if r1 == r2: continue
        a, b = map11.get(r1), map11.get(r2)
        if a is None or b is None or a == b: continue
        if (min(a, b), max(a, b)) not in E:
            print(f'  g{gi} fop={g.get("fop")} forms={g["forms"]} pair=({r1},{r2}) '
                  f'd={r2-r1:+d} GT({a},{b})')
