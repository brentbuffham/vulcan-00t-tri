# init_read10.py — BOUNDED PROBE: learn the channel step law from RAILS.
# Same rail (rid) = same strip's successive turns. For consecutive ref-groups
# on the same rail, census the 6-bit channel step (mod 64) and lead-byte
# behavior. KILL: top-3 steps <50% coverage => channel is not a strip counter.
import pickle
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))

# per-group stamp
stamp = {}
for gi, g in enumerate(groups):
    if g['refs'] and g['ops']:
        lead, arg = g['ops'][0]
        if (arg & 3) == 3 and 0x20 <= lead < 0x80:
            stamp[gi] = (lead, arg >> 2)

steps = Counter(); lead_same = Counter(); pairs = 0
gap_census = Counter()
for rr in rails:
    if len(rr['vals']) < 3: continue
    gis = sorted({gi for gi, r in rr['vals']})
    prev = None
    for gi in gis:
        if gi not in stamp: continue
        if prev is not None:
            (l0, c0), (l1, c1) = stamp[prev], stamp[gi]
            d = (c1 - c0) % 64
            if d != 0 or gi - prev > 2:   # skip same-turn continuation
                steps[d] += 1; pairs += 1
                lead_same[l0 == l1] += 1
                gap_census[min(gi - prev, 30)] += 1
        prev = gi

print(f'same-rail consecutive turn pairs: {pairs}')
print('channel step census (mod 64):', steps.most_common(12))
top3 = sum(v for _, v in steps.most_common(3))
print(f'top-3 coverage: {top3}/{pairs} ({top3/max(pairs,1)*100:.0f}%)  KILL if <50%')
print('lead byte same across turn:', dict(lead_same))
print('gi-gap census:', gap_census.most_common(8))
