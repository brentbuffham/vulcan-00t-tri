#!/usr/bin/env python3
"""Phase 3 ORACLE: for same-group pairs where one ref is a trustworthy 2-byte
absolute (mb form '01 hh ll') and the other is a spliced ref00 ('00 ll'),
enumerate every slot x whose mapped GT vertex is a mesh neighbor of the
absolute ref's GT vertex. Compare candidates' low bytes to the actual payload
byte -> reveals the true high-byte/field rule. GT used to GENERATE the
hypothesis (labeling); any rule found must be mechanical (byte-only).
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
                cur['events'].append(('skip00', pos)); pos += 1; continue
            r = (prev_ref & ~0xFF) | nxt
            cur['events'].append(('ref00', pos, nxt, prev_ref))
            cur['refs'].append(r); prev_ref = r; pos += 2; continue
        if 0x01 <= b <= 0x06:
            nb = b+1; v = int.from_bytes(d[pos+1:pos+1+nb], 'big')
            cur['events'].append(('mb', pos, b, v, prev_ref))
            if nb == 2 and v <= 2974:
                cur['refs'].append(v); prev_ref = v
            pos += 1+nb; continue
        if 0x08 <= b < 0x20:
            cur['events'].append(('pad', pos)); pos += 1; continue
        cur['events'].append(('op', pos, b, d[pos+1] if pos+1 < geo_end else 0))
        pos += 2
    if cur: groups.append(cur)
    return groups

groups = tokenize()
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)): nbr[u].add(v); nbr[v].add(u)
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))

# collect (group, absolute_ref, ref00_event) pairs where refs are consecutive
cases = []
for gi, g in enumerate(groups):
    evs = [e for e in g['events'] if e[0] in ('ref00', 'mb')]
    refs = []
    for e in evs:
        if e[0] == 'ref00': refs.append(('ref00', (e[3] & ~0xFF) | e[2], e[2], e[3]))
        elif e[2] == 1 and e[3] <= 2974: refs.append(('mb', e[3], None, None))
    if len(refs) < 2 or len(refs) > 4: continue
    if all(r[1] == 0 for r in refs): continue
    for i in range(1, len(refs)):
        a, b = refs[i-1], refs[i]
        if a[0] == 'mb' and b[0] == 'ref00':
            cases.append((gi, 'mb->ref00', a[1], b[2], b[3], b[1]))
        elif a[0] == 'ref00' and b[0] == 'mb':
            cases.append((gi, 'ref00<-mb', b[1], a[2], a[3], a[1]))

print(f'{len(cases)} oracle cases (one absolute + one spliced ref00 in pair)\n')
print('gi     dirn        ABS   payload prevref  cursplice  ORACLE candidates x: (x, x&0xFF, x-ABS)')
for gi, dirn, A, L, prevref, cur in cases:
    ga = map11.get(A)
    cands = []
    if ga is not None:
        for gn in nbr[ga]:
            x = gt2slot11.get(gn)
            if x is not None: cands.append(x)
    cands.sort()
    cd = ', '.join(f'({x},{x & 0xFF:02x},{x-A:+d})' for x in cands)
    mark = ' <== lowbyte match' if any((x & 0xFF) == L for x in cands) else ''
    print(f'g{gi:<5d} {dirn:10s} {A:5d}  0x{L:02x}({L:3d}) {prevref:5d}  {cur:5d}  [{cd}]{mark}')

# census: among all oracle candidates, does ANY consistent transform of payload
# byte reproduce x?  test x == A + something(L), x == (A&~0xFF)|L variants,
# x == prev-in-group high, x == round-to-nearest congruent of A
print('\n--- rule fit census over oracle cases ---')
rules = {
    'cur (prev_ref hi | L)': lambda A, L, p: (p & ~0xFF) | L,
    'ABS hi | L': lambda A, L, p: (A & ~0xFF) | L,
    'nearest-congruent to ABS': lambda A, L, p: L + 256*round((A - L)/256),
    'nearest-congruent to prev_ref': lambda A, L, p: L + 256*round((p - L)/256),
    'ABS + L': lambda A, L, p: A + L,
    'ABS - L': lambda A, L, p: A - L,
    'ABS + signed8(L)': lambda A, L, p: A + (L - 256 if L >= 128 else L),
}
for name, fn in rules.items():
    hit = tot = 0
    for gi, dirn, A, L, prevref, cur in cases:
        ga = map11.get(A)
        if ga is None: continue
        x = fn(A, L, prevref)
        gx = map11.get(x)
        if gx is None: continue
        tot += 1
        if gx in nbr[ga]: hit += 1
    print(f'  {name:32s}: {hit}/{tot} edge')
