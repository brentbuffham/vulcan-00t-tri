#!/usr/bin/env python3
"""Phase 2: characterize the 60 scored same-group pairs. For each: byte forms,
slot delta, pair sum, GT graph distance under map11. If distances cluster at
2-3, values are nearly right (alignment); if random, decode rule is wrong.
GT = labeling only."""
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

def tokenize():
    pos = face_start; groups = []; cur = None
    def ng(delim, p): return {'delim': delim, 'pos': p, 'ops': [], 'refs': [],
                              'events': []}
    prev_ref = 0
    while pos < geo_end:
        b = d[pos]
        if b in (0xE0, 0xE1):
            if cur: groups.append(cur)
            cur = ng(d[pos:pos+2].hex(), pos); pos += 2; continue
        if cur is None: cur = ng('HEAD', pos)
        if b == 0x00:
            nxt = d[pos+1] if pos+1 < geo_end else 0
            if 0x20 <= nxt < 0x80:
                cur['events'].append(('skip00', pos, d[pos:pos+1].hex()))
                pos += 1; continue
            r = (prev_ref & ~0xFF) | nxt
            cur['events'].append(('ref00', pos, d[pos:pos+2].hex(), nxt, prev_ref))
            cur['refs'].append(r); prev_ref = r; pos += 2; continue
        if 0x01 <= b <= 0x06:
            nb = b+1; v = int.from_bytes(d[pos+1:pos+1+nb], 'big')
            cur['events'].append(('mb', pos, d[pos:pos+1+nb].hex(), b, v, prev_ref))
            if nb == 2 and v <= 2974:
                cur['refs'].append(v); prev_ref = v
            pos += 1+nb; continue
        if 0x08 <= b < 0x20:
            cur['events'].append(('pad', pos, d[pos:pos+1].hex()))
            pos += 1; continue
        cur['ops'].append((b, d[pos+1] if pos+1 < geo_end else 0))
        cur['events'].append(('op', pos, d[pos:pos+2].hex()))
        pos += 2
    if cur: groups.append(cur)
    return groups

groups = tokenize()

F = np.load('faces_gt.npy')
E = set(); nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        E.add((min(u, v), max(u, v))); nbr[u].add(v); nbr[v].add(u)
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))

def gdist(a, b, maxd=6):
    if a == b: return 0
    seen = {a}; frontier = {a}
    for dd in range(1, maxd+1):
        nf = set()
        for x in frontier:
            for y in nbr[x]:
                if y == b: return dd
                if y not in seen: seen.add(y); nf.add(y)
        frontier = nf
    return maxd+1

# scored pairs only (both mapped, distinct), skipping junk groups (zero runs)
print('gi    delim  refs(pair)        d     sum   forms          GT(a,b)      gdist edge')
dcen = Counter()
rows = []
for gi, g in enumerate(groups):
    rs = g['refs']
    if len(rs) < 2 or len(rs) > 4: continue
    # per-ref byte form in order
    forms = [ev[0] for ev in g['events'] if ev[0] in ('ref00', 'mb') and
             not (ev[0] == 'mb' and ev[3] != 1)]
    for i in range(1, len(rs)):
        a, b = map11.get(rs[i-1]), map11.get(rs[i])
        if a is None or b is None or a == b: continue
        gd = gdist(a, b)
        edge = (min(a, b), max(a, b)) in E
        dcen[gd] += 1
        f = '+'.join(forms[i-1:i+1]) if len(forms) >= i+1 else '?'
        print(f'g{gi:<5d}{g["delim"]}  ({rs[i-1]:4d},{rs[i]:4d})  {rs[i]-rs[i-1]:+5d} '
              f'{rs[i-1]+rs[i]:6d}  {f:<14s} ({a:4d},{b:4d})  {gd}    {edge}')
        rows.append((gi, rs[i-1], rs[i], a, b, gd, edge))
print('\ngraph-distance census of scored pairs:', sorted(dcen.items()))
