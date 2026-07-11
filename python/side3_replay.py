"""L3: strip machine with GT-FREE S (side_rule.pkl), GT-scored quad rate.
Compare against the same machine with teacher fitS (upper bound). This is
the actual GT-free faces number -- the input to the 'show faces?' decision.
Category labels stated per number.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
sr = pickle.load(open('side_rule.pkl', 'rb'))
F = np.load('faces_gt.npy')
faceset = set(tuple(sorted(f)) for f in F)
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)
byrail = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        byrail[g2[gi][0]].append((gi, g2[gi][1]))
fitS = {}
for rid, ts in byrail.items():
    votes = Counter()
    for gi, r in ts:
        gt = map11.get(r)
        if gt is None: continue
        for vv in nbr[gt]:
            s = gt2slot11.get(vv)
            if s is not None and abs(s - r) > 3: votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2: fitS[rid] = S
Sgt = {rid: v[1] for rid, v in sr.items()}   # GT-free S

# turns per rail (ref group + following idless count)
turns = []
cur = None
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        cur = len(turns) if gi in g2 else None
        if gi in g2:
            turns.append([g2[gi][0], gi, g2[gi][1], 0])
        continue
    if g['delim'] == 'e003' and cur is not None:
        turns[cur][3] += 1
byrailturns = defaultdict(list)
for t in turns:
    byrailturns[t[0]].append(t)

def isface(*tri):
    return len(set(tri)) == 3 and tuple(sorted(tri)) in faceset

def replay(Smap, label):
    ok = bad = 0
    per_rail = defaultdict(lambda: [0, 0])
    for rid, ts in byrailturns.items():
        S = Smap.get(rid)
        if S is None:
            continue
        dn = -(rails[rid]['dir'] or -1)
        prev = None
        last_n = None
        for _, gi, r, na in ts:
            n0 = S - r
            if prev is not None and na:
                rp, np1 = prev
                dr = r - rp
                if dr == 0:
                    nf = last_n + dn
                    mpf = [map11.get(x) for x in (r, last_n, nf)]
                    if all(x is not None for x in mpf):
                        h = isface(*mpf); ok += h; bad += (not h)
                        per_rail[rid][0] += h; per_rail[rid][1] += 1
                    n0 = nf
                else:
                    mp = [map11.get(x) for x in (rp, np1, r, n0)]
                    if all(x is not None for x in mp):
                        grp, gnp, grk, gnk = mp
                        A = isface(grp, grk, gnp) and isface(grk, gnp, gnk)
                        B = isface(grp, grk, gnk) and isface(grp, gnp, gnk)
                        h = A or B; ok += h; bad += (not h)
                        per_rail[rid][0] += h; per_rail[rid][1] += 1
            prev = (r, n0); last_n = n0
    tot = ok + bad
    print('%-22s quad rate: %d/%d = %.1f%%  (rails scored %d)' %
          (label, ok, tot, 100 * ok / max(tot, 1),
           sum(1 for v in per_rail.values() if v[1] > 0)))
    return per_rail

print('=== strip machine face rate (mapped pairs; GT-scored) ===')
replay(fitS, 'teacher fitS S [t-forced]')
pr = replay(Sgt, 'GT-FREE S (side_rule)')

# firm-band-only: rails where GT-free S agrees best (proxy: |Sgt-fitS|<=2)
firm = {rid: Sgt[rid] for rid in Sgt if rid in fitS and abs(Sgt[rid]-fitS[rid]) <= 2}
replay(firm, 'GT-free S, firm band')
print('\nfirm-band rails:', len(firm), 'of', len(Sgt), 'GT-free-S rails')
