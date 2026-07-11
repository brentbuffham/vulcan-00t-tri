"""lo (1..13) vs same-rail structural quantities (all GT-free, rails_v3):
  U1: turns since rail birth (age)
  U2: turns until rail death
  U3: turns until this rail's next dr sign-flip (fold) / dr==0 (fan)
  U4: |r - rail_start_value|
  U5: |r - rail_end_value|
  U6: alloc count within current turn position... (n/a, single allocs)
Also: is lo constant per rail? per rail+phase?
"""
import pickle
from collections import Counter, defaultdict

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# per-rail visit list: rid -> [(gi, r)]
visits = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        visits[g2[gi][0]].append((gi, g2[gi][1]))
vidx = {}
for rid, vs in visits.items():
    for k, (gi, r) in enumerate(vs):
        vidx[gi] = (rid, k)

hits = defaultdict(Counter)
per_rail_vals = defaultdict(list)
cur = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = gi
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if not (1 <= v <= 13) or cur is None:
        continue
    rid, k = vidx[cur]
    vs = visits[rid]
    r = vs[k][1]
    n = len(vs)
    hits['U1 age'][v == k] += 1
    hits['U1b age+1'][v == k + 1] += 1
    hits['U2 to-death'][v == n - 1 - k] += 1
    hits['U2b to-death+1'][v == n - k] += 1
    hits['U4 |r-r0|'][v == abs(r - vs[0][1])] += 1
    hits['U5 |r-rend|'][v == abs(r - vs[-1][1])] += 1
    # fold: next sign flip of dr on this rail
    if k + 1 < n:
        d0 = vs[k + 1][1] - r
        t = None
        for j in range(k + 1, n - 1):
            if (vs[j + 1][1] - vs[j][1]) != d0:
                t = j - k
                break
        if t is not None:
            hits['U3 to-fold'][v == t] += 1
            hits['U3b to-fold+1'][v == t + 1] += 1
    per_rail_vals[rid].append(v)

for name, c in sorted(hits.items()):
    t = c[True] + c[False]
    print('%-16s %d/%d = %.1f%%' % (name, c[True], t, 100 * c[True] / max(t, 1)))

# constancy per rail
const = sum(1 for vs in per_rail_vals.values() if len(vs) >= 3 and len(set(vs)) == 1)
tot3 = sum(1 for vs in per_rail_vals.values() if len(vs) >= 3)
print('rails (>=3 lo) with CONSTANT lo: %d/%d' % (const, tot3))
nuniq = Counter(len(set(vs)) for vs in per_rail_vals.values() if len(vs) >= 3)
print('distinct-lo-per-rail hist:', sorted(nuniq.items()))
# peek some rails' lo sequences
big = sorted(per_rail_vals.items(), key=lambda kv: -len(kv[1]))[:12]
for rid, vs in big:
    print('rail %d lo seq: %s' % (rid, vs))
