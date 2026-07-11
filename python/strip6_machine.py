"""Full strip-machine replay on corrected rails (rails_v2).

Model (MYSTERY_A state machine + counter fix):
  per rail(strip): seq=[], counter n (n0 = S - r_first, dn = -rail_dir)
  ref group   -> seq.append(r)
  idless e003 -> n += dn (after first); seq.append(n)
  every e003 group with len(seq)>=3 emits face (seq[-3],seq[-2],seq[-1])
Turn assignment: idless groups belong to the rail of the last ref group.
Teacher-forced: S per rail fitted by GT votes (stated). GT scoring only.
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

g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# build per-rail event streams: (gi, 'ref'/'alloc', value_or_None)
events = defaultdict(list)
cur = None
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        if gi in g2:
            cur = g2[gi][0]
            events[cur].append((gi, 'ref', g2[gi][1]))
        else:
            cur = None
        continue
    if g['delim'] == 'e003' and cur is not None:
        events[cur].append((gi, 'alloc', None))

# fit S per rail by mirror votes (same as strip5)
fitS = {}
for rid, ev in events.items():
    votes = Counter()
    for gi, k, r in ev:
        if k != 'ref':
            continue
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

# replay
tot_face = ok_face = unmapped = 0
per_rail = defaultdict(lambda: [0, 0])
for rid, ev in events.items():
    S = fitS.get(rid)
    if S is None:
        continue
    dirs = rails[rid]['dir'] or -1
    dn = -dirs
    seq = []
    n = None
    for gi, k, r in ev:
        if k == 'ref':
            seq.append(r)
        else:
            n = (S - seq[-1]) if n is None and seq else \
                (n + dn if n is not None else None)
            if n is None:
                continue
            seq.append(n)
        if len(seq) >= 3:
            tri = [map11.get(x) for x in seq[-3:]]
            if any(t is None for t in tri):
                unmapped += 1
                continue
            if len(set(tri)) < 3:
                per_rail[rid][1] += 1; tot_face += 1
                continue
            hit = tuple(sorted(tri)) in faceset
            tot_face += 1; ok_face += hit
            per_rail[rid][0] += hit; per_rail[rid][1] += 1

print('teacher-forced face rate: %d/%d = %.1f%%  (unmapped %d)' % (
    ok_face, tot_face, 100 * ok_face / max(tot_face, 1), unmapped))
qual = sorted((100 * g / t, t, rid) for rid, (g, t) in per_rail.items() if t >= 5)
print('per-rail (>=5 scored):')
hist = Counter(int(q // 10) * 10 for q, t, _ in qual)
print('  decile hist:', sorted(hist.items()))
print('  best:', ['r%d:%d%%(n=%d)' % (rid, q, t) for q, t, rid in qual[-15:]])
print('  worst:', ['r%d:%d%%(n=%d)' % (rid, q, t) for q, t, rid in qual[:15]])
