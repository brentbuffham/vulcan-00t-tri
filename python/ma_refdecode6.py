#!/usr/bin/env python3
"""Phase 6: with header/state framing fixed (marker00 + first-op + header
field), test whether BODY '00 xx' is a ref for the FULL payload range
(the old 0x20..0x7f 'skip00' rule may have been a hack around the missing
header framing). Sweep splice-base rules. Score: same-group GT-edge rate,
|d|=1 fraction, ref count (expect ~2800 R/L), range (must stay <=2974)."""
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
E = set(); nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        E.add((min(u, v), max(u, v))); nbr[u].add(v); nbr[v].add(u)
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))


def tokenize(bodyref='all', base='prev', congruent=True, mb_unknown=True,
             hdrfield=True):
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
            pos += 2; state = 'hdr'; continue
        if b == 0x00:
            nxt = d[pos+1] if pos+1 < geo_end else 0
            if state == 'hdr' and hdrfield and nxt < 0x20:
                pos += 2; state = 'body'; continue
            if bodyref == 'hi' and not (nxt >= 0x80 or nxt < 0x20):
                pos += 1; state = 'body'; continue   # old skip00
            ref_base = last_abs if base == 'abs' else prev_ref
            if congruent:
                r = nxt + 256*round((ref_base - nxt)/256)
                if r < 0: r += 256
            else:
                r = (ref_base & ~0xFF) | nxt
            cur['refs'].append(r); cur['forms'].append('s')
            prev_ref = r; pos += 2; state = 'body'; continue
        if b == 0x01:
            v = int.from_bytes(d[pos+1:pos+3], 'big')
            if v <= 2974:
                cur['refs'].append(v); cur['forms'].append('A')
                prev_ref = v; last_abs = v
            pos += 3; state = 'body'; continue
        if 0x02 <= b <= 0x06:
            pos += 1 if mb_unknown else 2+b
            state = 'body'; continue
        if 0x08 <= b < 0x20:
            pos += 1; state = 'body'; continue
        pos += 2; state = 'body'; continue
    if cur: groups.append(cur)
    return groups


def score(groups, label, dump=False):
    hit = tot = 0; d1 = pairs = 0
    allr = []
    for g in groups:
        rs = g['refs']
        allr += rs
        if len(rs) < 2 or len(rs) > 4: continue
        for i in range(1, len(rs)):
            r1, r2 = rs[i-1], rs[i]
            if r1 == r2: continue
            pairs += 1
            if abs(r2-r1) == 1: d1 += 1
            a, b = map11.get(r1), map11.get(r2)
            if a is None or b is None or a == b: continue
            tot += 1
            ok = (min(a, b), max(a, b)) in E
            if ok: hit += 1
            if dump:
                print(f'   pair ({r1},{r2}) d={r2-r1:+d} GT({a},{b}) edge={ok}')
    ar = np.array(allr) if allr else np.array([0])
    over = (ar > 2974).sum()
    print(f'{label:34s} refs={len(allr):5d} rng[{ar.min()},{ar.max()}] >2974:{over:3d} '
          f'pairs={pairs:4d} |d|=1:{d1:4d} ({100*d1/max(pairs,1):4.1f}%) '
          f'GT-edge {hit}/{tot} = {100*hit/max(tot,1):5.1f}%')
    return groups


for label, kw in [
    ('B0 bodyref=hi(old skip)', dict(bodyref='hi', congruent=False)),
    ('B1 bodyref=all, splice', dict(congruent=False)),
    ('B2 bodyref=all, congruent', dict()),
    ('B3 all+congruent+base=abs', dict(base='abs')),
    ('B4 all+splice+base=abs', dict(base='abs', congruent=False)),
    ('B5 B2 mb=multibyte(old)', dict(mb_unknown=False)),
    ('B6 B2 no hdrfield', dict(hdrfield=False)),
]:
    score(tokenize(**kw), label)

print('\n--- B2 pair dump ---')
score(tokenize(), 'B2', dump=True)
