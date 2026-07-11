"""Strict rail clustering: a ref joins a rail ONLY if r == last+dir, or
r == last (fan), or (dir unknown and |r-last| == 1). No +/-2 tolerance.
Then re-run the strip8 hybrid scoring. Expectation from strip9: |dr|=1
pairs 84%, pure rails 90% -> overall mapped rate should jump.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

RETIRE_GI = 400

groups = pickle.load(open('refs_v2.pkl', 'rb'))
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
faceset = set(tuple(sorted(f)) for f in F)
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)

refs = []
for i, g in enumerate(groups):
    if g['is01']:
        continue
    for r, f in zip(g['refs'], g['forms']):
        refs.append((i, r, f, g['delim']))

rails = []
active = []
assign = []
for gi, r, f, dl in refs:
    active = [ri for ri in active if gi - rails[ri]['vals'][-1][0] <= RETIRE_GI]
    best = None
    for ri in active:
        rl = rails[ri]
        last = rl['vals'][-1][1]
        d = rl['dir']
        ok = (d and r == last + d) or r == last or (not d and abs(r - last) == 1)
        if ok:
            best = ri
            break
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

sizes = Counter(len(rl['vals']) for rl in rails)
big = [rl for rl in rails if len(rl['vals']) >= 3]
print('strict rails:', len(rails), ' >=3:', len(big), ' covering',
      sum(len(rl['vals']) for rl in big), '/', len(refs))
stepc = Counter()
for rl in rails:
    for a, b in zip(rl['vals'], rl['vals'][1:]):
        stepc[b[1] - a[1]] += 1
print('within-rail steps:', stepc.most_common(6))

g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

turns = []
cur = None
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        if gi in g2:
            cur = len(turns)
            turns.append([g2[gi][0], gi, g2[gi][1], 0])
        else:
            cur = None
        continue
    if g['delim'] == 'e003' and cur is not None:
        turns[cur][3] += 1

byrail = defaultdict(list)
for t in turns:
    byrail[t[0]].append(t)
fitS = {}
for rid, ts in byrail.items():
    votes = Counter()
    for _, gi, r, na in ts:
        gt = map11.get(r)
        if gt is None:
            continue
        for v in nbr[gt]:
            s = gt2slot11.get(v)
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S

def isface(*tri):
    return len(set(tri)) == 3 and tuple(sorted(tri)) in faceset

ok = bad = 0
fan_ok = fan_tot = 0
per_rail = defaultdict(lambda: [0, 0])
for rid, ts in byrail.items():
    S = fitS.get(rid)
    if S is None:
        continue
    dn = -(rails[rid]['dir'] or -1)
    prev = None
    last_n = None
    for _, gi, r, na in ts:
        if na == 0:
            continue
        n0 = S - r
        if prev is not None:
            rp, np1 = prev
            dr = r - rp
            mp = [map11.get(x) for x in (rp, np1, r, n0)]
            if dr == 0:
                # fan: n advances by dn from last_n
                nf = last_n + dn
                mpf = [map11.get(x) for x in (r, last_n, nf)]
                if all(x is not None for x in mpf):
                    fan_tot += 1
                    fan_ok += isface(*mpf)
                n0 = nf
            elif all(x is not None for x in mp):
                grp, gnp, grk, gnk = mp
                A = isface(grp, grk, gnp) and isface(grk, gnp, gnk)
                B = isface(grp, grk, gnk) and isface(grp, gnp, gnk)
                hit = A or B
                ok += hit; bad += (not hit)
                per_rail[rid][0] += hit; per_rail[rid][1] += 1
        prev = (r, n0)
        last_n = n0

tot = ok + bad
print('quad rate (mapped, |dr| any within strict rails): %d/%d = %.1f%%'
      % (ok, tot, 100 * ok / max(tot, 1)))
print('fan rate (counter-step): %d/%d = %.1f%%'
      % (fan_ok, fan_tot, 100 * fan_ok / max(fan_tot, 1)))
qual = sorted((100 * g / t, t, rid) for rid, (g, t) in per_rail.items() if t >= 6)
hist = Counter(int(q // 10) * 10 for q, t, _ in qual)
print('per-rail decile hist (>=6):', sorted(hist.items()))

pickle.dump({'rails': rails, 'assign': assign, 'refs': refs},
            open('rails_v3.pkl', 'wb'))
print('wrote rails_v3.pkl')
