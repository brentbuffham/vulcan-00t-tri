# init_read5.py — T7: n0 vs the ref rail's own slot extent (GT-free candidate law).
# Serpentine + descending sweeps predict the new column abuts the ref rail's
# extent: n0 = rail_lo - 1 (or rail_hi + 1), where [lo,hi] = full lifetime
# value range of the rail. Also report n0 - rail_end (last value) and whether
# the site looks like a TRUE strip start (n0 never referenced before gi).
import pickle, re
import numpy as np
from collections import Counter

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))
rail_by_id = {rr['id']: rr for rr in rails}
ev = sorted(ref_events)
ev_gi = np.array([e[0] for e in ev]); ev_r = np.array([e[1] for e in ev])

sites = []
for line in open('init_sites.txt'):
    m = re.match(r'gi=\s*(\d+) rid=\s*(\d+) n0=\s*(\d+) r=\s*(\d+)', line)
    if m: sites.append(tuple(map(int, m.groups())))

print('gi     rid   n0    r0    rail[lo,hi] len  r_end  n0-lo n0-hi n0-rend  clean')
c_lo = Counter(); c_hi = Counter(); c_end = Counter()
for gi, rid, n0, r in sites:
    rr = rail_by_id.get(rid)
    vals = [v for g, v in rr['vals']]
    lo, hi = min(vals), max(vals)
    rend = vals[-1]
    clean = not bool(np.any(ev_r[ev_gi < gi] == n0))
    c_lo[n0 - lo] += 1; c_hi[n0 - hi] += 1; c_end[n0 - rend] += 1
    print(f'{gi:5d} {rid:5d} {n0:5d} {r:5d}  [{lo:5d},{hi:5d}] {len(vals):4d} {rend:6d} {n0-lo:6d} {n0-hi:5d} {n0-rend:7d}  {"*" if clean else ""}')
print()
print('n0-lo census :', c_lo.most_common(10))
print('n0-hi census :', c_hi.most_common(10))
print('n0-rend census:', c_end.most_common(10))
