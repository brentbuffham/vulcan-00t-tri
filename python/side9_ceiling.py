"""Emission ceiling of the current per-quad machine: it emits ~2 tris per
CONSECUTIVE-TURN PAIR within a rail => sum(turns-1) pairs. Compare to the
5724-face mesh. Shows whether coverage is S-limited or rail-fragmentation
limited. Also: distribution of groups across rail sizes.
"""
import pickle
from collections import Counter, defaultdict

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# turns per rail (ref group + following idless count as the turn)
turns_per_rail = Counter()
cur = None
tot_idless = 0
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        cur = g2[gi][0] if gi in g2 else None
        if cur is not None:
            turns_per_rail[cur] += 1
        continue
    if g['delim'] == 'e003':
        tot_idless += 1

NF = 5724
# each consecutive-turn pair emits ~1 quad = up to 2 tris (but ~1 GT face net)
pairs = sum(max(t - 1, 0) for t in turns_per_rail.values())
print('rails with >=1 turn:', len(turns_per_rail))
print('total ref-turns:', sum(turns_per_rail.values()))
print('consecutive-turn PAIRS (quad emissions):', pairs)
print('  -> ~%d faces max from quads (2/pair) = %.0f%% of mesh CEILING'
      % (2*pairs, 100*2*pairs/NF))
print('  -> but each quad ~= 1-2 GT faces; realistic ceiling ~%.0f-%.0f%%'
      % (100*pairs/NF, 100*2*pairs/NF))

# how many turns are in rails of size 1 (emit ZERO quads)?
size1_turns = sum(t for t in turns_per_rail.values() if t == 1)
print('\nturns stranded in size-1 rails (emit nothing):', size1_turns)
byturns = Counter(turns_per_rail.values())
print('rail turn-count dist:', sorted(byturns.items())[:15])
frag = sum(1 for t in turns_per_rail.values() if t <= 2)
print('rails with <=2 turns:', frag, 'of', len(turns_per_rail),
      '(these are strip FRAGMENTS -- the coverage wall)')

# if strips were stitched: total emittable = (ref groups) + (idless groups)
# each emits one last-3 face => ceiling ~ n_groups ~ full mesh
nref = sum(1 for g in groups if g['refs'] and not g['is01'])
print('\nIF stitched to full strips (each group emits 1 last-3 face):')
print('  ref groups %d + idless %d = %d ~= %d mesh faces (full coverage)'
      % (nref, tot_idless, nref + tot_idless, NF))
