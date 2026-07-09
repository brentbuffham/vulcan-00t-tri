#!/usr/bin/env python3
"""Phase 5: MECHANICAL GRAMMAR SWEEP. Tokenizer variants differing in:
 - structural-00 handling at group start (marker skip)
 - '00 xx' xx<0x20 after first-op: structural field vs ref
 - '00 xx' ref gate: any / >=0x80 only
 - splice base: global prev_ref / last absolute / nearest-congruent
 - 0x02..0x06 lead: multibyte skip (current) vs 1-byte unknown
Scored by: same-group GT-edge rate (primary, GT=labeling), |d|=1 pair fraction
(GT-free), ref range sanity. Baseline V0 = topo_rails grammar = 15%.
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
E = set(); nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        E.add((min(u, v), max(u, v))); nbr[u].add(v); nbr[v].add(u)
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))


def tokenize(marker00=False, hdrfield=False, refgate='any', base='prev',
             mb_unknown=False, congruent=False):
    """returns list of groups: {'delim','pos','refs'} with per-variant rules."""
    pos = face_start; groups = []; cur = None
    prev_ref = 0; last_abs = 0
    state = 'body'   # 'delim0' right after delim (expect marker 00), 'hdr' after first-op
    def ng(delim, p): return {'delim': delim, 'pos': p, 'refs': [], 'nref00': 0}
    tokens_since_delim = 0
    while pos < geo_end:
        b = d[pos]
        if b in (0xE0, 0xE1):
            if cur: groups.append(cur)
            cur = ng(d[pos:pos+2].hex(), pos); pos += 2
            state = 'delim0'; tokens_since_delim = 0; continue
        if cur is None: cur = ng('HEAD', pos); state = 'body'
        if state == 'delim0' and marker00:
            if b == 0x00:
                pos += 1; state = 'firstop'; continue
            state = 'firstop'
        if state == 'firstop':
            # first-op: consume 2 bytes unconditionally
            pos += 2; state = 'hdr'; continue
        if b == 0x00:
            nxt = d[pos+1] if pos+1 < geo_end else 0
            if 0x20 <= nxt < 0x80:
                pos += 1; state = 'body'; continue
            if state == 'hdr' and hdrfield and nxt < 0x20:
                # structural header field, not a ref
                pos += 2; state = 'body'; continue
            if refgate == 'hi' and nxt < 0x80:
                pos += 2; state = 'body'; continue
            ref_base = last_abs if base == 'abs' else prev_ref
            if congruent:
                r = nxt + 256*round((ref_base - nxt)/256)
                if r < 0: r += 256
            else:
                r = (ref_base & ~0xFF) | nxt
            cur['refs'].append(r); cur['nref00'] += 1
            prev_ref = r; pos += 2; state = 'body'; continue
        if b == 0x01:
            v = int.from_bytes(d[pos+1:pos+3], 'big')
            if v <= 2974:
                cur['refs'].append(v); prev_ref = v; last_abs = v
            pos += 3; state = 'body'; continue
        if 0x02 <= b <= 0x06:
            if mb_unknown: pos += 1
            else: pos += 1 + (b+1)
            state = 'body'; continue
        if 0x08 <= b < 0x20:
            pos += 1; state = 'body'; continue
        pos += 2; state = 'body'; continue
    if cur: groups.append(cur)
    return groups


def score(groups, label):
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
            if (min(a, b), max(a, b)) in E: hit += 1
    ar = np.array(allr) if allr else np.array([0])
    print(f'{label:38s} groups={len(groups):5d} refs={len(allr):5d} '
          f'range[{ar.min()},{ar.max()}] pairs={pairs:4d} |d|=1: {d1:3d} '
          f'({100*d1/max(pairs,1):4.1f}%)  GT-edge {hit}/{tot} = {100*hit/max(tot,1):5.1f}%')
    return hit, tot


variants = [
    ('V0 current', dict()),
    ('V1 marker00', dict(marker00=True)),
    ('V2 marker+hdrfield', dict(marker00=True, hdrfield=True)),
    ('V3 V2+refgate hi', dict(marker00=True, hdrfield=True, refgate='hi')),
    ('V4 V2+base abs', dict(marker00=True, hdrfield=True, base='abs')),
    ('V5 V2+congruent', dict(marker00=True, hdrfield=True, congruent=True)),
    ('V6 V2+mb-unknown', dict(marker00=True, hdrfield=True, mb_unknown=True)),
    ('V7 V2+mbunk+baseabs', dict(marker00=True, hdrfield=True, mb_unknown=True, base='abs')),
    ('V8 V2+mbunk+congr', dict(marker00=True, hdrfield=True, mb_unknown=True, congruent=True)),
    ('V9 all: mbunk+congr+baseabs', dict(marker00=True, hdrfield=True, mb_unknown=True,
                                         base='abs', congruent=True)),
]
for label, kw in variants:
    score(tokenize(**kw), label)
