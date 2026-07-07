#!/usr/bin/env python3
"""refhunt8 -- census the raw V-tag byte b (bits beyond nb=(b&7)+1) at
broken-onset vs clean records. LABELING ONLY.
Usage: python refhunt8.py <case>
"""
import struct, sys
import numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
exec(open(__file__.replace('refhunt8', 'refhunt4')).read().split("# teacher-force")[0])
# info[i][a] = (kind, payload, T, R); need raw b too -> re-derive from toks
# redo decode recording raw b
regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
ph = 0; k = 0
binfo = [ {} ]; cur = {}
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        cur[a] = None
        regs[a][:] = t[1]
        if a == 2 and ph == 2: binfo.append(cur); cur = {}
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    cur[a] = t[3]  # raw tag byte
    vb = r2_v9(bytes(regs[a]), payload, t[2], a, be(regs[a]))
    if vb is not None: regs[a][:] = vb
    if a == 2: binfo.append(cur); cur = {}
    ph = (ph + 1) % 3

from collections import Counter
TOL = 1e-3
onsets = [(i, wa) for (i, wa, tv) in pins if dist[i - 1] < TOL]
cb = Counter(); ob = Counter(); ab = Counter()
for (i, wa, tv) in pins:
    b = binfo[i].get(wa)
    if b is not None: ab[hex(b)] += 1
for (i, wa) in onsets:
    b = binfo[i].get(wa)
    if b is not None: ob[hex(b)] += 1
import random
random.seed(3)
clean = [i for i in np.where(dist < TOL)[0] if i > 0]
for i in random.sample(clean, min(1500, len(clean))):
    for a in range(3):
        b = binfo[i].get(a)
        if b is not None: cb[hex(b)] += 1
def norm(c):
    s = sum(c.values())
    return {k: f'{v} ({100*v/s:.0f}%)' for k, v in c.most_common(10)}
print('raw V-tag byte census:')
print('  BROKEN onsets:', norm(ob))
print('  BROKEN all   :', norm(ab))
print('  CLEAN        :', norm(cb))
