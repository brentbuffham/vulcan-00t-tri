#!/usr/bin/env python3
"""zhunt2 -- teacher-force yellow-Z sites: which (k0 placement, dh) makes
trueZ from (Rbefore, payload)? Split onset (prev Z clean) vs inherited.
Census dh; correlate far-dh with stream bytes (T2, E-tokens, prev record).
Usage: python zhunt2.py <case>
"""
import struct, sys, pickle, collections
import numpy as np
case = sys.argv[1] if len(sys.argv) > 1 else 'intercepts'
exec(open(__file__.replace('zhunt2', 'zhunt1')).read().split("# ---- k computation ----")[0])
# from zhunt1 we now have: allmeta, P, hist, ok, yel, mid, G, be, band, k0_rule

okset = {vi for (vi, tz, dz) in ok}
def be_(b): return struct.unpack('>d', bytes(b))[0]

def tf(R, payload, tv, span=300):
    """all (k0, dh, exactness) reconstructing tv: value |v-tv|<1e-6 (True)
    or <1e-2 (False)"""
    nb = len(payload); hits = []
    for k0 in range(0, 8 - nb + 1):
        hb = k0; tail = R[k0 + nb:]
        hi = int.from_bytes(R[:hb], 'big') if hb else 0
        for dh in range(-span, span + 1):
            h2 = hi + dh
            if hb and not (0 <= h2 < (1 << (8 * hb))): continue
            if not hb and dh != 0: continue
            vb = (h2.to_bytes(hb, 'big') if hb else b'') + bytes(payload) + bytes(tail)
            v = be_(vb)
            if not np.isfinite(v): continue
            e = abs(v - tv)
            if e < 1e-6: hits.append((k0, dh, True))
            elif e < 1e-2: hits.append((k0, dh, False))
    return hits

cens = {'onset': collections.Counter(), 'inh': collections.Counter()}
far = []
noex = collections.Counter()
for (vi, tz, dz) in yel:
    m = allmeta[2].get(vi)
    onset = 'onset' if (vi - 1) in okset else 'inh'
    if m is None or m['kind'] != 'V':
        noex[(onset, m['kind'] if m else 'NOREC')] += 1; continue
    R = m['Rbefore']; pay = m['payload']; nb = m['nb']; T = m['T']
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    hits = tf(R, pay, tz)
    exact = [h for h in hits if h[2]]
    if exact:
        k0, dh, _ = min(exact, key=lambda h: (abs(h[1]), abs(h[0] - k0r)))
        dhc = ('dh0' if dh == 0 else f'dh{dh:+d}' if abs(dh) <= 4 else 'dhFAR')
        cens[onset][(nb, f'k0={k0}' + ('=rule' if k0 == k0r else f'(rule{k0r})'), dhc)] += 1
        if abs(dh) > 4 and onset == 'onset':
            far.append((vi, nb, T, k0, dh, m))
    elif hits:
        k0, dh, _ = min(hits, key=lambda h: (abs(h[1]), abs(h[0] - k0r)))
        cens[onset][(nb, f'k0={k0}TAILDIFF', 'dh0' if dh == 0 else f'dh{dh:+d}' if abs(dh) <= 4 else 'dhFAR')] += 1
        if abs(dh) > 4 and onset == 'onset':
            far.append((vi, nb, T, k0, dh, m))
    else:
        noex[(onset, f'nb{nb}', 'nopaymatch')] += 1
print('=== teacher-force census (yellow-Z) ===')
for lab in ('onset', 'inh'):
    print(f'\n{lab} ({sum(cens[lab].values())}):')
    for k_, c in cens[lab].most_common(20): print(f'  {k_}: {c}')
print('\nno reconstruction:', dict(noex))

print(f'\n=== far-dh ONSETS ({len(far)}) -- correlate dh with stream bytes ===')
for (vi, nb, T, k0, dh, m) in far[:40]:
    E = ' '.join(b.hex() for (_, b) in m['E'][-3:])
    prevm = allmeta[1].get(vi)  # Y record same vertex
    pT = (f'{prevm["T"][0]:02x}{prevm["T"][1]:02x}' if prevm and prevm.get('T') else '--')
    Ts = f'{T[0]:02x}{T[1]:02x}' if T else '----'
    print(f'  vi{vi:5d} nb{nb} T{Ts} k0={k0} dh={dh:+4d}  b={m["b"]:02x} E[{E}] yT={pT} lastF_dist={vi - m["lastFi"] if m["lastFi"] is not None else -1}')
