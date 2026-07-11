"""lo vs current ref value r: is lo a column/region coordinate?

For each single-lo idless e003 group (v in 1..13) with current turn ref r:
  scatter/census v vs r; test v == (r // W) mod M and v == C - (r // W)
  over W in 40..200, and v vs r-quantile bins.
GT-free.
"""
import pickle
from collections import Counter, defaultdict

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

ev = []
cur = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = g2[gi][1]
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if 1 <= v <= 13 and cur is not None:
        ev.append((gi, v, cur))
print('events:', len(ev))

# mean r per v
byv = defaultdict(list)
for gi, v, r in ev:
    byv[v].append(r)
for v in sorted(byv):
    rs = sorted(byv[v])
    print('v=%2d n=%3d  r: min %4d  q25 %4d  med %4d  q75 %4d  max %4d' % (
        v, len(rs), rs[0], rs[len(rs)//4], rs[len(rs)//2], rs[3*len(rs)//4], rs[-1]))

# best (W, offset, sign) for v == (C - r//W) or (r//W - C) mod nothing
best = []
for W in range(40, 201, 2):
    # sign -1: v = C - r//W
    offs = Counter(v + r // W for gi, v, r in ev)
    C, cnt = offs.most_common(1)[0]
    best.append((cnt, W, 'C-r//W', C))
    offs2 = Counter(v - r // W for gi, v, r in ev)
    C2, cnt2 = offs2.most_common(1)[0]
    best.append((cnt2, W, 'r//W+C', C2))
best.sort(reverse=True)
n = len(ev)
print('top-8 linear-in-column fits:')
for cnt, W, form, C in best[:8]:
    print('  %s  W=%d C=%d : %d/%d = %.1f%%' % (form, W, C, cnt, n, 100*cnt/n))
