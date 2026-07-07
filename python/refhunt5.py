#!/usr/bin/env python3
"""refhunt5 -- eyeball + arithmetic tests at pinned sites where no window
splice reconstructs the true value.

Tests per site:
  A. escape content in payload (0x00 / 0xFC-0xFF rate vs control)
  B. bit-delta: bits(true) - bits(R) == payload<<shift (signed), sweep shift
  C. bit-delta vs parallelogram pred, vs value 2 back
  D. hex dump 15 Z + 15 X sites (payload, R, true, prevs)
Usage: python refhunt5.py <case>
"""
import struct, sys
import numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
exec(open(__file__.replace('refhunt5', 'refhunt4')).read().split("# teacher-force")[0])

def bits(v): return struct.unpack('>q', struct.pack('>d', v))[0]
def hx(b): return b.hex()

# control: payload escape-byte rate at GOOD V sites
esc = set([0x00, 0xFC, 0xFD, 0xFE, 0xFF])
good_esc = bad_esc = good_n = bad_n = 0
pinset = {(i, wa) for (i, wa, tv) in pins}
pinmap = {(i, wa): tv for (i, wa, tv) in pins}
for i in range(1, len(P)):
    for a in range(3):
        rec = info[i].get(a)
        if rec is None or rec[0] != 'V': continue
        pay = rec[1]
        ne = sum(1 for b in pay if b in esc)
        if (i, a) in pinset: bad_esc += ne; bad_n += len(pay)
        elif dist[i] < 1e-3: good_esc += ne; good_n += len(pay)
print(f'escape-byte rate in payload: pinned {bad_esc}/{bad_n} = {bad_esc/max(1,bad_n):.3f}   '
      f'good {good_esc}/{good_n} = {good_esc/max(1,good_n):.3f}')

# arithmetic delta tests
from collections import Counter
hitcens = Counter(); nohit = Counter()
for (i, wa, tv) in pins:
    rec = info[i].get(wa)
    if rec is None or rec[0] != 'V': continue
    kind, pay, T, R = rec
    nb = len(pay)
    Rv = be(R)
    D = bits(tv) - bits(Rv)
    pu = int.from_bytes(pay, 'big')
    ps = pu - (1 << (8 * nb)) if pay[0] >= 0x80 else pu
    hit = None
    for shift in range(0, 41):
        for pv, tag in ((pu, 'u'), (ps, 's')):
            if pv << shift == D: hit = (shift, tag, '+'); break
            if -(pv << shift) == D: hit = (shift, tag, '-'); break
            if (pv << shift) - D != 0 and abs((pv << shift) - abs(D)) <= 1: pass
        if hit: break
    if hit: hitcens[(nb, hit)] += 1
    else: nohit[nb] += 1
print('bit-delta vs LAST hits:', dict(hitcens))
print('no bit-delta hit:', dict(nohit))

# hex dumps
print('\n--- Z sites ---')
cnt = 0
for (i, wa, tv) in pins:
    if wa != 2 or cnt >= 15: continue
    rec = info[i].get(wa)
    if rec is None or rec[0] != 'V': continue
    kind, pay, T, R = rec
    onset = dist[i - 1] < 1e-3
    print(f'i={i:5d} on={int(onset)} T={None if not T else (hex(T[0]),hex(T[1]))} pay={hx(pay)}  R={hx(bytes(R))} ({be(R):.4f})')
    print(f'        true={struct.pack(">d",tv).hex()} ({tv:.4f})  decoded={struct.pack(">d",P[i,wa]).hex()} ({P[i,wa]:.4f})')
    cnt += 1
print('\n--- X sites ---')
cnt = 0
for (i, wa, tv) in pins:
    if wa != 0 or cnt >= 15: continue
    rec = info[i].get(wa)
    if rec is None or rec[0] != 'V': continue
    kind, pay, T, R = rec
    onset = dist[i - 1] < 1e-3
    print(f'i={i:5d} on={int(onset)} T={None if not T else (hex(T[0]),hex(T[1]))} pay={hx(pay)}  R={hx(bytes(R))} ({be(R):.4f})')
    print(f'        true={struct.pack(">d",tv).hex()} ({tv:.4f})  decoded={struct.pack(">d",P[i,wa]).hex()} ({P[i,wa]:.4f})')
    cnt += 1
