# init_read4.py — tiling-in-ref-space tests for n0:
#  T4: at INIT gi, how close is n0 to territory ALREADY REFERENCED (min |n0-r'|
#      over ref events with gi' < gi)?  Tiling predicts 0/1. Control: random slots.
#  T5: does n0 appear as a ref at some LATER gi (allocated leg becomes a rail)?
#  T6: does n0 relate to the last ref/allocation of the PREVIOUS group (gi-1,-2)?
import pickle, re, random
import numpy as np
from collections import Counter

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))
sites = []
for line in open('init_sites.txt'):
    m = re.match(r'gi=\s*(\d+) rid=\s*(\d+) n0=\s*(\d+) r=\s*(\d+)', line)
    if m: sites.append(tuple(map(int, m.groups())))

# ref events sorted by gi
ev = sorted(ref_events)  # (gi, r, rid)
ev_gi = np.array([e[0] for e in ev])
ev_r = np.array([e[1] for e in ev])

def min_dist_before(gi, s):
    mask = ev_gi < gi
    if not mask.any(): return None
    return int(np.min(np.abs(ev_r[mask] - s)))

def seen_after(gi, s):
    mask = ev_gi > gi
    return bool(np.any(ev_r[mask] == s))

def seen_before(gi, s):
    mask = ev_gi < gi
    return bool(np.any(ev_r[mask] == s))

print('=== T4/T5: n0 vs already-referenced territory ===')
d4 = []; t5 = 0; t5b = 0
rows = []
for gi, rid, n0, r in sites:
    md = min_dist_before(gi, n0)
    d4.append(md)
    sa = seen_after(gi, n0); sb = seen_before(gi, n0)
    t5 += sa; t5b += sb
    rows.append((gi, n0, md, sb, sa))
print('T4 min|n0 - earlier ref| census:', Counter(d4).most_common(12))
print(f'T5 n0 seen as ref AFTER gi: {t5}/57;  n0 already seen BEFORE gi: {t5b}/57')

random.seed(2)
ctl = []
for gi, rid, n0, r in sites:
    s = random.randrange(2937)
    ctl.append(min_dist_before(gi, s))
print('T4 control (random slot, same gi):', Counter(ctl).most_common(12))

print()
print('=== per-site detail (gi, n0, mindist_before, seen_before, seen_after) ===')
for row in rows: print(row)

# T6: relation to previous groups' last values
print()
print('=== T6: n0 - (last ref of groups gi-1..gi-3) ===')
diffs = Counter()
for gi, rid, n0, r in sites:
    for back in (1, 2, 3):
        g = groups[gi - back]
        if g['refs']:
            diffs[(back, n0 - g['refs'][-1])] += 1
            break
print(diffs.most_common(15))
