"""ma_final.py census re-run on CORRECTED rails (rails_v2 from refs_v2.pkl).

Baseline (contaminated rails.pkl): complete-quad 56.3%, fan 100% curated.
Teacher-forced: S fitted per rail by GT votes (stated). GT = scoring only.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v2.pkl', 'rb'))
rv = pickle.load(open('rails_v2.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
faceset = set(tuple(sorted(f)) for f in F)
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)

# per-ref rail id, in stream order; map gi -> (rid, r) using LAST ref in group
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# motif pairs per rail: ref group -> following idless e003 groups
pairs = defaultdict(list)
last = None
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        last = (gi, g2[gi][0], g2[gi][1]) if gi in g2 else None
        continue
    if g['delim'] == 'e003' and last is not None:
        pairs[last[1]].append((last[0], gi, last[2]))

# fit S per rail (teacher-forced vote)
fitS = {}
for rid, lst in pairs.items():
    votes = Counter()
    for gr_gi, gi, r in lst:
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
print('rails with fitted S: %d / %d' % (len(fitS), len(pairs)))

lab = Counter(); phase_dir = Counter()
mirror_hit = mirror_chk = 0
per_rail = defaultdict(lambda: [0, 0])  # rid -> [good, tot]
for rid, lst in pairs.items():
    S = fitS.get(rid)
    if S is None:
        continue
    for i in range(len(lst)):
        gr_gi, gi, r = lst[i]
        n = S - r
        a = map11.get(r); b = map11.get(n)
        if a is not None and b is not None:
            mirror_chk += 1
            mirror_hit += b in nbr[a]
        if i == 0:
            continue
        gr_gi0, gi0, rp = lst[i - 1]
        if gi - gi0 > 60:
            continue
        np_ = S - rp
        ids = [map11.get(x) for x in (rp, np_, r, n)]
        if any(x is None for x in ids):
            lab['unmapped'] += 1
            continue
        grp, gnp, grk, gnk = ids
        dr = r - rp
        if dr == 0:
            ok = tuple(sorted((grk, gnp, gnk))) in faceset if gnp != gnk else False
            lab['fan_ok' if ok else 'fan_bad'] += 1
            per_rail[rid][0] += ok; per_rail[rid][1] += 1
            continue
        A = (tuple(sorted((grp, grk, gnp))) in faceset) and \
            (tuple(sorted((grk, gnp, gnk))) in faceset)
        B = (tuple(sorted((grp, grk, gnk))) in faceset) and \
            (tuple(sorted((grp, gnp, gnk))) in faceset)
        cls = 'A' if (A and not B) else 'B' if (B and not A) else \
              'AB' if (A and B) else 'none'
        lab[cls] += 1
        good = cls in ('A', 'B', 'AB')
        per_rail[rid][0] += good; per_rail[rid][1] += 1
        if cls in ('A', 'B'):
            phase_dir[(cls, 1 if dr > 0 else -1)] += 1

print('S-mirror edge rate (map11): %d/%d = %.1f%%' % (
    mirror_hit, mirror_chk, 100 * mirror_hit / max(mirror_chk, 1)))
print('pair labels:', lab.most_common())
tot = sum(v for k, v in lab.items() if k in ('A', 'B', 'AB', 'none'))
good = lab['A'] + lab['B'] + lab['AB']
print('complete-quad rate: %d/%d = %.1f%%' % (good, tot, 100 * good / max(tot, 1)))
fs, fb = lab['fan_ok'], lab['fan_bad']
print('fan law: %d/%d = %.1f%%' % (fs, fs + fb, 100 * fs / max(fs + fb, 1)))
print('phase vs dr sign:', dict(phase_dir))

# per-rail quality distribution (rails with >=4 scored pairs)
qual = sorted((100 * g / t, t, rid) for rid, (g, t) in per_rail.items() if t >= 4)
print('per-rail rates (>=4 scored):', ['%d%%(n=%d)' % (q, t) for q, t, _ in qual])
