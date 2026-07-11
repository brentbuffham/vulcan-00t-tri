"""SWEEP (Opus, RESUME-2026-07-12 step 1): find the exact rule for lo (v).

On mirror-VERIFIED events (map11[r]-map11[n] a GT edge; n=S-r trusted),
test v == highbyte(X) and v == f(bytes) for a broad candidate set. Also
test v against the group's OWN fop/payload/finalizer bytes (structural,
GT-free -- if lo is derivable from other bytes in the same record it's not
new info, but tells us the field's meaning). Win criterion >=90%.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# per-rail visit list + fitS
byrail = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        byrail[g2[gi][0]].append((gi, g2[gi][1]))
fitS = {}
for rid, ts in byrail.items():
    votes = Counter()
    for gi, r in ts:
        gt = map11.get(r)
        if gt is None:
            continue
        for vv in nbr[gt]:
            s = gt2slot11.get(vv)
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S

# build verified events with rich context
ev = []
cur = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = (g2[gi][0], g2[gi][1], gi)
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if not (1 <= v <= 11) or cur is None:
        continue
    rid, r, refgi = cur
    S = fitS.get(rid)
    if S is None:
        continue
    n = S - r
    if not (0 <= n <= 2974):
        continue
    a, b = map11.get(r), map11.get(n)
    verified = a is not None and b is not None and b in nbr[a]
    # rail neighbors (values)
    ts = byrail[rid]
    ks = [k for k, (ggi, rr) in enumerate(ts) if ggi == refgi]
    k = ks[0] if ks else None
    r_next = ts[k + 1][1] if (k is not None and k + 1 < len(ts)) else None
    r_prev = ts[k - 1][1] if (k is not None and k > 0) else None
    r0 = ts[0][1]
    # fop / payload / finalizer bytes
    fop = g['fop']
    fop_lead = int(fop[:2], 16) if fop else None
    fop_arg = int(fop[2:4], 16) if fop and len(fop) >= 4 else None
    pay = int(g['ops'][0], 16) if g['ops'] else None
    pay_lead = int(g['ops'][0][:2], 16) if g['ops'] else None
    pay_arg = int(g['ops'][0][2:], 16) if g['ops'] else None
    ev.append(dict(v=v, r=r, n=n, S=S, r_next=r_next, r_prev=r_prev, r0=r0,
                   verified=verified, fop_lead=fop_lead, fop_arg=fop_arg,
                   pay=pay, pay_lead=pay_lead, pay_arg=pay_arg))

EV = [e for e in ev if e['verified']]
print('verified events:', len(EV), ' (all events:', len(ev), ')')

def rate(fn, pool=EV):
    ok = t = 0
    for e in pool:
        val = fn(e)
        if val is None:
            continue
        t += 1
        ok += (e['v'] == val)
    return ok, t

hb = lambda x: (x >> 8) if x is not None else None
cands = {
    'n>>8': lambda e: hb(e['n']),
    '(n-128)>>8': lambda e: hb(e['n'] - 128),
    '(n+128)>>8': lambda e: hb(e['n'] + 128),
    'round(n/256)': lambda e: (e['n'] + 128) >> 8,
    'r>>8': lambda e: hb(e['r']),
    '(S-r_next)>>8': lambda e: hb(e['S'] - e['r_next']) if e['r_next'] else None,
    '(S-r_prev)>>8': lambda e: hb(e['S'] - e['r_prev']) if e['r_prev'] else None,
    'S>>9': lambda e: e['S'] >> 9,
    '(n)//256 fop_arg>>5': lambda e: (e['fop_arg'] >> 5) if e['fop_arg'] is not None else None,
    'fop_arg&7': lambda e: (e['fop_arg'] & 7) if e['fop_arg'] is not None else None,
    'fop_lead&7': lambda e: (e['fop_lead'] & 7) if e['fop_lead'] is not None else None,
    'pay_lead>>?': lambda e: (e['pay_lead'] >> 1) if e['pay_lead'] is not None else None,
    'n//250': lambda e: e['n'] // 250,
    'n//270': lambda e: e['n'] // 270,
    '(2974-n)>>8': lambda e: hb(2974 - e['n']),
    '(2974-r)>>8': lambda e: hb(2974 - e['r']),
}
res = []
for name, fn in cands.items():
    ok, t = rate(fn)
    res.append((100 * ok / max(t, 1), ok, t, name))
res.sort(reverse=True)
print('\n=== high-byte / structural candidate sweep (verified) ===')
for pct, ok, t, name in res:
    print('  %-22s %d/%d = %.1f%%' % (name, ok, t, pct))

# is lo determined by fop_arg? build the map and measure purity
m = defaultdict(Counter)
for e in EV:
    if e['fop_arg'] is not None:
        m[e['fop_arg']][e['v']] += 1
pure = sum(c.most_common(1)[0][1] for c in m.values())
tot = sum(sum(c.values()) for c in m.values())
print('\nlo | fop_arg best-guess purity: %d/%d = %.1f%% (%d distinct args)'
      % (pure, tot, 100 * pure / max(tot, 1), len(m)))

# fop_lead purity
m2 = defaultdict(Counter)
for e in EV:
    if e['fop_lead'] is not None:
        m2[e['fop_lead']][e['v']] += 1
pure2 = sum(c.most_common(1)[0][1] for c in m2.values())
tot2 = sum(sum(c.values()) for c in m2.values())
print('lo | fop_lead best-guess purity: %d/%d = %.1f%%   leads=%s'
      % (pure2, tot2, 100 * pure2 / max(tot2, 1),
         {k: dict(v) for k, v in sorted(m2.items())}))
