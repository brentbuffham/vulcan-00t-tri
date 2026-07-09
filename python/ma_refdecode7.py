#!/usr/bin/env python3
"""Phase 7: payload-class ref decode. Evidence: '00 p' with p>=0x80 is a
low-byte splice (all |d|=1 pairs it makes are GT edges); with p<0x20 the
splice is wrong, but abs+p is CONSTANT across the g87/126/176 fan triple
(1549+18=1548+19=1547+20=1567) -> p may be an ADDITIVE DELTA. Sweep rules for
each payload class; score same-group GT-edge rate + |d|=1. GT=labeling."""
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


def tokenize(lorule='splice', midrule='splice', hdrfield=True, hdr_as_ref=False):
    """lorule/midrule in: splice, add, sub, zig  (for p<0x20 / 0x20<=p<0x80)"""
    pos = face_start; groups = []; cur = None
    prev_ref = 0
    state = 'body'
    def ng(delim, p): return {'delim': delim, 'pos': p, 'refs': [], 'ps': []}
    def dec(rule, p, base):
        if rule == 'splice':
            r = p + 256*round((base - p)/256)
            return r if r >= 0 else r+256
        if rule == 'add': return base + p
        if rule == 'sub': return base - p
        if rule == 'zig': return base + (p >> 1 if p % 2 == 0 else -((p+1) >> 1))
        raise ValueError
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
            p = d[pos+1] if pos+1 < geo_end else 0
            if state == 'hdr' and p < 0x20 and not hdr_as_ref:
                if hdrfield: pos += 2; state = 'body'; continue
            rule = 'splice' if p >= 0x80 else (lorule if p < 0x20 else midrule)
            r = dec(rule, p, prev_ref)
            cur['refs'].append(r); cur['ps'].append(p)
            prev_ref = r; pos += 2; state = 'body'; continue
        if b == 0x01:
            v = int.from_bytes(d[pos+1:pos+3], 'big')
            if v <= 2974:
                cur['refs'].append(v); cur['ps'].append(-1)
                prev_ref = v
            pos += 3; state = 'body'; continue
        if 0x02 <= b <= 0x06:
            pos += 1; state = 'body'; continue
        if 0x08 <= b < 0x20:
            pos += 1; state = 'body'; continue
        pos += 2; state = 'body'; continue
    if cur: groups.append(cur)
    return groups


def score(groups, label, dump=False):
    hit = tot = 0; d1 = pairs = 0
    cls = Counter()   # (payload class of 2nd ref, edge?) census
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
            p = g['ps'][i]
            k = 'abs' if p < 0 else ('lo' if p < 0x20 else ('mid' if p < 0x80 else 'hi'))
            cls[(k, ok)] += 1
            if ok: hit += 1
            if dump and not ok:
                print(f'   FAIL pair ({r1},{r2}) d={r2-r1:+d} p2={p:#x} GT({a},{b})')
    ar = np.array(allr) if allr else np.array([0])
    over = (ar > 2974).sum()
    print(f'{label:30s} refs={len(allr):5d} rng[{ar.min()},{ar.max()}] >2974:{over:3d} '
          f'pairs={pairs:4d} |d|=1:{d1:4d} ({100*d1/max(pairs,1):4.1f}%) '
          f'GT-edge {hit}/{tot} = {100*hit/max(tot,1):5.1f}%  cls={dict(cls)}')


for label, kw in [
    ('L=splice M=splice (B2)', dict()),
    ('L=add    M=splice', dict(lorule='add')),
    ('L=sub    M=splice', dict(lorule='sub')),
    ('L=zig    M=splice', dict(lorule='zig')),
    ('L=add    M=add', dict(lorule='add', midrule='add')),
    ('L=add    M=sub', dict(lorule='add', midrule='sub')),
    ('L=add    M=zig', dict(lorule='add', midrule='zig')),
    ('L=zig    M=zig', dict(lorule='zig', midrule='zig')),
    ('L=add M=splice hdr-as-ref', dict(lorule='add', hdr_as_ref=True)),
]:
    score(tokenize(**kw), label)

print('\n--- best-variant FAIL dump (L=add M=splice) ---')
score(tokenize(lorule='add'), 'L=add M=splice', dump=True)
