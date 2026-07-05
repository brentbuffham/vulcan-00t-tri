# init_read7.py — pin e002/e004 as strip push/pop:
#  (1) for each e002 group: does a NEW rail (first event of some rid) appear
#      within the next K groups? control: random gi. Same for e004 (rail death).
#  (2) dump ops/refs of e002 and e004 groups — do they carry values?
#  (3) count: rails born near e002, rails dying near e004.
import pickle, random
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))

# rail birth/death gi (only rails with >=3 events to skip clutter)
birth = {}; death = {}
for rr in rails:
    if len(rr['vals']) >= 3:
        birth[rr['id']] = rr['vals'][0][0]
        death[rr['id']] = rr['vals'][-1][0]
births = sorted(birth.values()); deaths = sorted(death.values())
print(f'rails >=3 events: {len(birth)}')

import bisect
def near(sorted_list, gi, K):
    i = bisect.bisect_left(sorted_list, gi)
    best = 10**9
    for j in (i - 1, i, i + 1):
        if 0 <= j < len(sorted_list): best = min(best, abs(sorted_list[j] - gi))
    return best

K = 6
for delim, evs in (('e002', births), ('e004', deaths), ('e002', deaths), ('e004', births)):
    gis = [gi for gi, g in enumerate(groups) if g['delim'] == delim]
    hits = sum(1 for gi in gis if near(evs, gi, K) <= K)
    random.seed(4)
    ctl = sum(1 for _ in range(1000) if near(evs, random.randrange(len(groups)), K) <= K) / 1000
    which = 'births' if evs is births else 'deaths'
    print(f'{delim} within {K} of a rail {which}: {hits}/{len(gis)} ({hits/len(gis)*100:.0f}%)  control {ctl*100:.0f}%')

print()
print('=== e002 group contents (first 12) ===')
n = 0
for gi, g in enumerate(groups):
    if g['delim'] == 'e002' and n < 12:
        ops = ' '.join(f'{a:02x}:{b:02x}' for a, b in g['ops'][:8])
        print(f'g{gi}: refs={g["refs"][:8]} ops=[{ops}]')
        n += 1
print()
print('=== e004 group contents (first 12) ===')
n = 0
for gi, g in enumerate(groups):
    if g['delim'] == 'e004' and n < 12:
        ops = ' '.join(f'{a:02x}:{b:02x}' for a, b in g['ops'][:8])
        print(f'g{gi}: refs={g["refs"][:8]} ops=[{ops}]')
        n += 1

# ref-count / op-count profile per delim class
print()
prof = defaultdict(Counter)
for g in groups:
    prof[g['delim']]['refs%d' % min(len(g['refs']), 3)] += 1
for dl in ('e003', 'e002', 'e004', 'e0ff'):
    print(dl, dict(prof[dl]))
