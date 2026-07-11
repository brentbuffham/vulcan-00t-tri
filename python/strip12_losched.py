"""Is the idless-group lo value (1..11) a SCHEDULE field?

For each idless e003 group with a single lo v in 1..13, following ref group
of rail R (current turn): test v against
  T1: # ref groups until rail R is revisited  (countdown-to-revisit)
  T2: # DISTINCT rails visited until R revisited
  T3: # ref groups since R's PREVIOUS visit
  T4: # distinct rails in the last v ref groups... (rank of R in recency)
  T5: rank of R's ref value among active rails (position in table)
All GT-free (rails_v3 clustering only).
"""
import pickle
from collections import Counter, defaultdict

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# stream of ref-group turns in order: (gi, rid)
turnseq = []
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        turnseq.append((gi, g2[gi][0]))
gi2turn = {gi: k for k, (gi, rid) in enumerate(turnseq)}

# next/prev revisit distance per turn index (in ref-group counts)
nxt = {}
last = {}
prv = {}
for k, (gi, rid) in enumerate(turnseq):
    if rid in last:
        nxt[last[rid]] = k - last[rid]
        prv[k] = k - last[rid]
    last[rid] = k

# distinct rails between visit and revisit
def distinct_until(k, gap):
    return len({rid for _, rid in turnseq[k + 1:k + gap]})

hits = defaultdict(Counter)
samples = []
cur_turn = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur_turn = gi2turn[gi]
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if not (1 <= v <= 13) or cur_turn is None:
        continue
    k = cur_turn
    t1 = nxt.get(k)
    t3 = prv.get(k)
    if t1 is not None:
        hits['T1 next-revisit-gap'][v == t1] += 1
        hits['T1d gap-1'][v == t1 - 1] += 1
        hits['T2 distinct-until'][v == distinct_until(k, t1)] += 1
    if t3 is not None:
        hits['T3 prev-visit-gap'][v == t3] += 1
        hits['T3d gap-1'][v == t3 - 1] += 1
    samples.append((v, t1, t3))

for name, c in sorted(hits.items()):
    t = c[True] + c[False]
    print('%-22s %d/%d = %.1f%%' % (name, c[True], t, 100 * c[True] / max(t, 1)))

# joint distribution peek: v vs t1
jd = Counter((v, t1) for v, t1, _ in samples if t1 is not None and t1 <= 15)
print('\n(v, next-gap) top25:', jd.most_common(25))
jd3 = Counter((v, t3) for v, _, t3 in samples if t3 is not None and t3 <= 15)
print('(v, prev-gap) top25:', jd3.most_common(25))

# marginal: v hist among tested
print('\nv hist:', Counter(v for v, _, _ in samples).most_common())
print('next-gap hist:', Counter(t1 for _, t1, _ in samples if t1).most_common(12))
