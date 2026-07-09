#!/usr/bin/env python3
"""REF-INDEX DECODE — FINAL (2026-07-09 Fable session, REF_INDEX_DECODE.md).

Fixes the ref-index extraction of topo_rails.py (same-group ref-pair GT-edge
rate 15% -> 72.7% on mapped pairs; |d|=1 subclass 8/8 = 100%).

GRAMMAR (byte roles, GT-free; supersedes topo_rails.py lines 20-37):
  'e0 xx' / 'e1 xx'   group delimiter.
  marker 0x00         first byte after delim, structural, skip 1.
  first token after marker:
      lead >= 0x20    first-op, 2 bytes (arg = phase-clock field).
      lead == 0x01    header triple '01 hh ll', 3 bytes, NOT a ref
                      (record subtype; treat group as non-face record).
      else            no first-op; fall through to body.
  body tokens:
      '01 hh ll'      ABSOLUTE ref, big-endian, accept 1..2974
                      ('01 00 00' = zero-fill junk, reject).
      '00 pp' pp>=80  SHORT ref: pp is the LOW byte; high byte = nearest
                      value congruent to pp (mod 256) to the previous ref
                      (same congruent-window trick as the coord codec v9).
                      Reject result >2974.
      '00 pp' pp<80   STRUCTURAL field (count/schedule channel) — NOT a ref.
                      This is the byte class the old grammar spliced into
                      ~1600 phantom refs (the 15% wall).
      0x02..0x06      1-byte unknown (old '(b+1)-byte payload' rule REJECTED:
                      it swallowed refs and even delimiters).
      0x08..0x1f      pad, skip 1.
      else            2-byte op.

Scoring below: categories stated per number. GT (faces_gt/map11) is used for
LABELING only; the extraction itself never sees it.
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


def extract():
    pos = face_start; groups = []; cur = None
    prev_ref = 0
    state = 'body'
    def ng(delim, p): return {'delim': delim, 'pos': p, 'refs': [], 'forms': [],
                              'fop': None, 'is01': False}
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
            if b >= 0x20:
                cur['fop'] = d[pos:pos+2].hex(); pos += 2
            elif b == 0x01:
                cur['fop'] = d[pos:pos+3].hex(); cur['is01'] = True; pos += 3
            state = 'body'; continue
        if b == 0x00:
            p = d[pos+1] if pos+1 < geo_end else 0
            if p >= 0x80 and not cur['is01']:
                r = p + 256*round((prev_ref - p)/256)
                if r < 0: r += 256
                if 0 <= r <= 2974:
                    cur['refs'].append(r); cur['forms'].append('S')
                    prev_ref = r
            pos += 2; state = 'body'; continue
        if b == 0x01:
            v = int.from_bytes(d[pos+1:pos+3], 'big')
            if 1 <= v <= 2974 and not cur['is01']:
                cur['refs'].append(v); cur['forms'].append('A')
                prev_ref = v
            pos += 3; state = 'body'; continue
        if 0x02 <= b <= 0x06: pos += 1; state = 'body'; continue
        if 0x08 <= b < 0x20: pos += 1; state = 'body'; continue
        pos += 2; state = 'body'; continue
    if cur: groups.append(cur)
    return groups


if __name__ == '__main__':
    groups = extract()
    print(f'groups {len(groups)} (GT faces: 5724 — one group ~ one face)')

    F = np.load('faces_gt.npy')
    E = set()
    for a, b, c in F:
        for u, v in ((a, b), (b, c), (c, a)): E.add((min(u, v), max(u, v)))
    map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))

    allr = [r for g in groups for r in g['refs']]
    ar = np.array(allr)
    print(f'refs {len(allr)}  range [{ar.min()},{ar.max()}]  >2974: {(ar>2974).sum()}'
          f'  boundary (2963,2974]: {((ar>2963)&(ar<=2974)).sum()}')

    pairs = d1 = hit = tot = h1 = t1 = hx = tx = 0
    for g in groups:
        rs = g['refs']
        if len(rs) < 2 or len(rs) > 4: continue
        for i in range(1, len(rs)):
            r1, r2 = rs[i-1], rs[i]
            if r1 == r2: continue
            pairs += 1
            adj = abs(r2-r1) == 1
            d1 += adj
            a, b = map11.get(r1), map11.get(r2)
            if a is None or b is None or a == b: continue
            tot += 1
            ok = (min(a, b), max(a, b)) in E
            hit += ok
            if adj: t1 += 1; h1 += ok
            else:   tx += 1; hx += ok
    print(f'same-group pairs {pairs}   |d|=1: {d1} ({100*d1/max(pairs,1):.1f}%) [GT-free]')
    print(f'same-group GT-edge rate (mapped): {hit}/{tot} = {100*hit/max(tot,1):.1f}% '
          f'[GT-labeled; was 15% (9/60) under old extraction]')
    print(f'  |d|=1 subclass:  {h1}/{t1} = {100*h1/max(t1,1):.1f}%')
    print(f'  |d|!=1 subclass: {hx}/{tx} = {100*hx/max(tx,1):.1f}%')

    ca = Counter()
    flat = [(r, f) for g in groups for r, f in zip(g['refs'], g['forms'])]
    for i in range(1, len(flat)):
        if flat[i][1] == 'A' and flat[i-1][1] == 'A':
            ca[flat[i][0]-flat[i-1][0]] += 1
    top = ca.most_common(8)
    print(f'A->A consecutive deltas (top): {top}  '
          f'(cluster ~ -95..-160 = per-fold anchors, NOT +-1 rails)')

    pickle.dump(groups, open('refs_v2.pkl', 'wb'))
    print('saved refs_v2.pkl')
