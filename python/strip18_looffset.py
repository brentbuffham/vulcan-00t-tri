"""v in {n>>8, (n>>8)-1}: find the exact rule.
  O1: v == (n - 128) >> 8
  O2: split v==hi vs v==hi-1 by n%256 (is there a threshold?)
  O3: per-strip constants: v == (S - r0)>>8, (S - rmax)>>8, S>>9, (S-230)>>9
  O4: v == (S - n)>>8 = r>>8 offset variants: (r-128)>>8
On verified-mirror events only (n trusted).
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

ev = []  # (v, n, r, rid)
cur = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = g2[gi]
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if not (0 <= v <= 13) or cur is None:
        continue
    rid, r = cur
    S = fitS.get(rid)
    if S is None:
        continue
    n = S - r
    if not (0 <= n <= 2974):
        continue
    a, b = map11.get(r), map11.get(n)
    if a is None or b is None or b not in nbr[a]:
        continue
    ev.append((v, n, r, rid))
print('verified events:', len(ev))

t = defaultdict(Counter)
for v, n, r, rid in ev:
    t['v==(n-128)>>8'][v == (n - 128) >> 8] += 1
    t['v==n>>8'][v == n >> 8] += 1
    r0 = byrail[rid][0][1]
    S = fitS[rid]
    t['v==(S-r0)>>8'][v == (S - r0) >> 8] += 1
    t['v==S>>9'][v == S >> 9] += 1
    t['v==(S-256)>>9'][v == (S - 256) >> 9] += 1
    t['v==(S-r0-128)>>8'][v == (S - r0 - 128) >> 8] += 1
    rmax = max(x[1] for x in byrail[rid])
    t['v==(S-rmax)>>8'][v == (S - rmax) >> 8] += 1
for name, c in sorted(t.items(), key=lambda kv: -kv[1][True]):
    tt = c[True] + c[False]
    print('%-20s %d/%d = %.1f%%' % (name, c[True], tt, 100 * c[True] / max(tt, 1)))

# O2: does n%256 decide hi vs hi-1?
lohalf = Counter(); hihalf = Counter()
for v, n, r, rid in ev:
    hi = n >> 8
    which = 'hi' if v == hi else ('hi-1' if v == hi - 1 else 'other')
    (lohalf if n % 256 < 128 else hihalf)[which] += 1
print('n%256<128:', dict(lohalf))
print('n%256>=128:', dict(hihalf))
# sweep threshold on n%256 for v==hi
sweep = []
for th in range(0, 257, 16):
    ok = sum(1 for v, n, r, rid in ev
             if v == (n >> 8) - (1 if n % 256 < th else 0))
    sweep.append((ok, th))
sweep.sort(reverse=True)
print('best n%%256 threshold for hi/hi-1 split:', sweep[:5], '/', len(ev))
