"""Test: lo = strip slot ID in the round-robin table?

A: temporally-overlapping rails should have DISTINCT modal lo.
B: slot reuse -- after a rail with modal lo=v dies, does a NEW rail with
   modal lo=v get born soon after?
C: the interlopers (non-modal lo within a rail) -- are they the modal lo of
   ANOTHER concurrently-active rail (=> turn-misassignment, fixable)?
GT-free (rails_v3 + lo channel only).
"""
import pickle
from collections import Counter, defaultdict

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

visits = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        visits[g2[gi][0]].append(gi)

# alloc lo events attributed to rails via cur-heuristic
rail_lo = defaultdict(list)   # rid -> [(gi, v)]
cur = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = g2[gi][0]
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if 1 <= v <= 13 and cur is not None:
        rail_lo[cur].append((gi, v))

modal = {}
span = {}
for rid, evs in rail_lo.items():
    if len(evs) < 4:
        continue
    c = Counter(v for _, v in evs)
    m, cnt = c.most_common(1)[0]
    if cnt / len(evs) >= 0.5:
        modal[rid] = m
    span[rid] = (visits[rid][0], visits[rid][-1])
print('rails with clear modal lo (>=4 events, >=50%%): %d' % len(modal))

# A: overlapping rails distinct modal?
ov_same = ov_diff = 0
clash = []
rids = sorted(modal, key=lambda r: span[r][0])
for i in range(len(rids)):
    for j in range(i + 1, len(rids)):
        a, b = rids[i], rids[j]
        if span[b][0] > span[a][1]:
            break
        # overlap
        if modal[a] == modal[b]:
            ov_same += 1
            clash.append((a, b, modal[a]))
        else:
            ov_diff += 1
print('A: overlapping rail pairs: same-modal %d vs diff-modal %d (%.1f%% distinct)'
      % (ov_same, ov_diff, 100 * ov_diff / max(ov_same + ov_diff, 1)))
if clash[:8]:
    print('   clashes:', clash[:8])

# B: slot reuse - for each dying rail with modal v, next-born rail with modal v
reuse_gap = []
births = sorted((span[r][0], r) for r in modal)
for rid in modal:
    d_gi = span[rid][1]
    v = modal[rid]
    nxt = [(bgi, r2) for bgi, r2 in births if bgi > d_gi and modal[r2] == v]
    if nxt:
        reuse_gap.append(nxt[0][0] - d_gi)
rg = Counter(min(g // 50 * 50, 500) for g in reuse_gap)
print('B: death->same-slot-rebirth gi-gap hist (bucket 50):', sorted(rg.items()))

# C: interlopers = another active rail's modal?
inter_hit = inter_tot = 0
active_at = lambda gi: [r for r in modal if span[r][0] <= gi <= span[r][1]]
for rid, evs in rail_lo.items():
    m = modal.get(rid)
    if m is None:
        continue
    for gi, v in evs:
        if v == m:
            continue
        inter_tot += 1
        others = {modal[r] for r in active_at(gi) if r != rid}
        inter_hit += v in others
print('C: interloper lo == another ACTIVE rail modal: %d/%d = %.1f%%'
      % (inter_hit, inter_tot, 100 * inter_hit / max(inter_tot, 1)))

# global sanity: how many distinct modal values at once?
import bisect
gis = [gi for gi, g in enumerate(groups)]
probe = range(0, len(groups), 200)
for gi in probe:
    act = active_at(gi)
    vals = sorted(modal[r] for r in act)
    dup = len(vals) - len(set(vals))
    print('  gi=%d active=%d slots=%s dup=%d' % (gi, len(act), vals, dup))
