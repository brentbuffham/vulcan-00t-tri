"""Cluster refs_v2 refs into VALUE-CONTINUITY rails (interleaved strips).

Hypothesis from strip3 eyeball: refs form ~10 concurrent +/-1 walks spaced
~column-pitch apart; A->A -95..-160 steps are round-robin switches between
strips, not per-fold anchors. GT-free clustering; GT used only to score at
the end (not in this script).

Greedy: active rails keep (last_value, last_gi, dir). A ref joins the rail
minimizing |r - expected_next| if within TOL; else births a new rail.
"""
import pickle, collections

TOL = 2          # max |r - (last+dir)| to join a rail
RETIRE_GI = 400  # rails untouched this long are retired (safety, generous)

groups = pickle.load(open('refs_v2.pkl', 'rb'))

refs = []  # (gi, r, form, delim)
for i, g in enumerate(groups):
    if g['is01']:
        continue
    for r, f in zip(g['refs'], g['forms']):
        refs.append((i, r, f, g['delim']))

rails = []          # each: dict(id, vals=[(gi,r,form)], dir)
active = []         # indices into rails
assign = []         # per ref: rail id

for gi, r, f, dl in refs:
    # retire stale
    active = [ri for ri in active if gi - rails[ri]['vals'][-1][0] <= RETIRE_GI]
    best, bestcost = None, None
    for ri in active:
        rl = rails[ri]
        last = rl['vals'][-1][1]
        d = rl['dir']
        exp = last + (d if d else 0)
        cost = min(abs(r - exp), abs(r - last))
        if cost <= TOL and (bestcost is None or cost < bestcost):
            best, bestcost = ri, cost
    if best is None:
        rails.append({'id': len(rails), 'vals': [(gi, r, f)], 'dir': 0})
        active.append(len(rails) - 1)
        assign.append(len(rails) - 1)
    else:
        rl = rails[best]
        step = r - rl['vals'][-1][1]
        if step in (1, -1):
            rl['dir'] = step
        rl['vals'].append((gi, r, f))
        assign.append(best)

sizes = collections.Counter(len(rl['vals']) for rl in rails)
print('rails:', len(rails), ' size dist:', sorted(sizes.items()))
big = [rl for rl in rails if len(rl['vals']) >= 3]
print('rails >=3 refs:', len(big), ' covering',
      sum(len(rl['vals']) for rl in big), '/', len(refs), 'refs')

# step purity within rails
stepc = collections.Counter()
for rl in rails:
    for a, b in zip(rl['vals'], rl['vals'][1:]):
        stepc[b[1] - a[1]] += 1
print('within-rail step census:', stepc.most_common(10))

# concurrency trace: how many rails alive (born, not yet dead) at each ref
births = {rl['id']: rl['vals'][0][0] for rl in rails}
deaths = {rl['id']: rl['vals'][-1][0] for rl in rails}
alive_counts = []
for gi, r, f, dl in refs:
    alive = sum(1 for rid in births if births[rid] <= gi <= deaths[rid])
    alive_counts.append(alive)
print('concurrency: median %d  max %d' % (
    sorted(alive_counts)[len(alive_counts)//2], max(alive_counts)))

# rail start-value spacing (should be ~column pitch)
starts = sorted(rl['vals'][0][1] for rl in big)
gaps = collections.Counter(b - a for a, b in zip(starts, starts[1:]))
print('big-rail start-value gaps top15:', gaps.most_common(15))

# round-robin: rail-id sequence pattern (first 60 assignments)
print('assign seq (first 80):', assign[:80])

# rail lifetimes in gi
lifes = [(rl['id'], rl['vals'][0][0], rl['vals'][-1][0], len(rl['vals']),
          rl['dir']) for rl in big[:20]]
print('first 20 big rails (id, gi0, gi1, n, dir):')
for x in lifes:
    print('  ', x)

pickle.dump({'rails': rails, 'assign': assign, 'refs': refs},
            open('rails_v2.pkl', 'wb'))
print('wrote rails_v2.pkl')
