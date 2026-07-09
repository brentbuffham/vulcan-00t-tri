#!/usr/bin/env python3
"""Phase 8: OP-CONTEXT census for '00 p' events. Hypothesis: whether '00 p'
is a REF (and which form) is announced by the preceding op token (e.g. '20 03')
or the group's first-op lead nibble — not by the payload range hack.
Tabulate: preceding token x payload class; also expected ref count sanity
(R/L ~= 5724-2894 = 2830). GT not used here at all (pure structure census)."""
import struct
from collections import Counter, defaultdict

RAW = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(RAW, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
occ = [i for i in range(8326, len(d)-2) if d[i] == 0xE0 and d[i+1] == 0x03]
face_start = len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k] < 90: face_start = occ[k]; break

# neutral tokenizer: state framing (marker00 + first-op), '00 p' consumed as
# 2-byte candidate token for ALL p, '01 hh ll' absolute, 02-06 1-byte unknown,
# 08-1f pad, else 2-byte op.
pos = face_start
events = []   # (kind, pos, byte(s), group_index, idx_in_group, prev_token, delim, firstop)
gi = -1; idx = 0; state = 'body'; prevtok = None; delim = None; firstop = None
while pos < geo_end:
    b = d[pos]
    if b in (0xE0, 0xE1):
        gi += 1; idx = 0; delim = d[pos:pos+2].hex(); pos += 2
        state = 'delim0'; prevtok = ('delim', delim); firstop = None
        continue
    if state == 'delim0':
        if b == 0x00: pos += 1
        state = 'firstop'; continue
    if state == 'firstop':
        firstop = d[pos:pos+2].hex()
        prevtok = ('firstop', firstop)
        pos += 2; state = 'body'; continue
    if b == 0x00:
        p = d[pos+1] if pos+1 < geo_end else 0
        events.append(('00p', pos, p, gi, idx, prevtok, delim, firstop))
        prevtok = ('00p', p); idx += 1; pos += 2; continue
    if b == 0x01:
        v = int.from_bytes(d[pos+1:pos+3], 'big')
        events.append(('abs', pos, v, gi, idx, prevtok, delim, firstop))
        prevtok = ('abs', v); idx += 1; pos += 3; continue
    if 0x02 <= b <= 0x06:
        events.append(('smb', pos, b, gi, idx, prevtok, delim, firstop))
        prevtok = ('smb', b); idx += 1; pos += 1; continue
    if 0x08 <= b < 0x20:
        prevtok = ('pad', b); pos += 1; continue
    op = d[pos:pos+2].hex()
    events.append(('op', pos, op, gi, idx, prevtok, delim, firstop))
    prevtok = ('op', op); idx += 1; pos += 2; continue

print(f'{gi+1} groups, {len(events)} tokens')
cls = lambda p: 'lo' if p < 0x20 else ('mid' if p < 0x80 else 'hi')

# 1) census '00 p' payload class x preceding token kind (op lead byte grouped)
ct = Counter()
for e in events:
    if e[0] != '00p': continue
    p = e[2]; prev = e[5]
    if prev[0] == 'op': pk = 'op:' + prev[1][:2]
    elif prev[0] == 'firstop': pk = 'fop:' + prev[1][:2]
    else: pk = prev[0]
    ct[(cls(p), pk)] += 1
print('\n00p class x preceding-token census (top 40):')
for (c, pk), n in sorted(ct.items(), key=lambda x: -x[1])[:40]:
    print(f'   {c:3s} after {pk:8s}: {n}')

# 2) same for abs refs: what precedes them?
ca = Counter()
for e in events:
    if e[0] != 'abs': continue
    prev = e[5]
    pk = (prev[0] + ':' + (prev[1][:2] if isinstance(prev[1], str) else cls(prev[1]) if prev[0]=='00p' else str(prev[1])))
    ca[pk] += 1
print('\nabs-ref preceding-token census (top 20):')
for pk, n in sorted(ca.items(), key=lambda x: -x[1])[:20]:
    print(f'   after {pk:12s}: {n}')

# 3) counts: candidate ref populations
n_abs = sum(1 for e in events if e[0] == 'abs' and e[2] <= 2974)
n_abs_all = sum(1 for e in events if e[0] == 'abs')
n_hi = sum(1 for e in events if e[0] == '00p' and e[2] >= 0x80)
n_mid = sum(1 for e in events if e[0] == '00p' and 0x20 <= e[2] < 0x80)
n_lo = sum(1 for e in events if e[0] == '00p' and e[2] < 0x20)
print(f'\nabs<=2974: {n_abs} (all abs: {n_abs_all})  00p hi: {n_hi}  mid: {n_mid}  lo: {n_lo}')
print(f'target R/L ops ~ 5724-2894 = 2830')
print(f'abs+hi = {n_abs+n_hi}   abs+hi+lo = {n_abs+n_hi+n_lo}   abs+hi+mid = {n_abs+n_hi+n_mid}')

# 4) '00 p' after op 20xx: census of the op ARG for ref-ish vs not
c20 = Counter()
for e in events:
    if e[0] == '00p' and e[5][0] == 'op' and e[5][1][:2] == '20':
        c20[(e[5][1], cls(e[2]))] += 1
print('\n00p after specific 20xx op (top 25):')
for k, n in sorted(c20.items(), key=lambda x: -x[1])[:25]:
    print(f'   {k}: {n}')

# 5) first-op lead census x group-has-abs / has-00p-hi
gstat = defaultdict(lambda: [0, 0, 0])
gfop = {}
for e in events:
    gfop[e[3]] = e[7]
    if e[0] == 'abs': gstat[e[3]][0] += 1
    elif e[0] == '00p':
        if e[2] >= 0x80: gstat[e[3]][1] += 1
        else: gstat[e[3]][2] += 1
fopc = Counter()
for g, (na, nh, nl) in gstat.items():
    f = gfop.get(g)
    if f is None: continue
    fopc[(f[:2], 'abs' if na else ('hi' if nh else 'oth'))] += 1
print('\nfirst-op lead x group ref-content (top 30):')
for k, n in sorted(fopc.items(), key=lambda x: -x[1])[:30]:
    print(f'   {k}: {n}')
