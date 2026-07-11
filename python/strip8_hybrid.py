"""Hybrid strip-machine replay: mirror-resync allocation + counter fans.

Per rail: turn = ref group + following idless e003 groups.
  alloc n: n_mirror = S - r_cur ; if n_mirror != last_n use it (resync),
           else n = last_n + dn (fan/multi-alloc step), dn = -rail_dir.
Faces scored per turn against GT (teacher-forced S; category stated):
  vs prev turn on same rail (rp, np) -> quad A or B or fan(r==rp).
  multi-alloc turns: extra faces (r, n_{j-1}, n_j).
Counts EVERY e003 face group in the denominator (honest rate), splitting
out unmapped separately.
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

# turns: (rid, gi_ref, r, n_allocs)
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

# fit S per rail (mirror votes)
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

ok = bad = unmapped = nofit = 0
per_rail = defaultdict(lambda: [0, 0])
for rid, ts in byrail.items():
    S = fitS.get(rid)
    dn = -(rails[rid]['dir'] or -1)
    if S is None:
        nofit += sum(1 + t[3] for t in ts)
        continue
    last_n = None
    prev = None  # (r, first_n_of_turn, last_n_of_turn)
    for _, gi, r, na in ts:
        ns = []
        for j in range(na):
            nm = S - r
            if nm != last_n or j > 0:
                n = nm if j == 0 else ns[-1] + dn
            else:
                n = last_n + dn
            ns.append(n)
            last_n = n
        # score faces for this turn (1 + na groups -> 1 + na faces)
        scored = []
        if prev is not None and ns:
            rp, np0, np1 = prev
            n0 = ns[0]
            dr = r - rp
            if dr == 0:
                scored.append(isface(*(map11.get(x) for x in (r, np1, n0)))
                              if all(map11.get(x) is not None for x in (r, np1, n0)) else None)
                # ref-group face for fan turn = same fan face; count once more
                scored.append(scored[-1])
            else:
                mp = [map11.get(x) for x in (rp, np1, r, n0)]
                if any(x is None for x in mp):
                    scored += [None, None]
                else:
                    grp, gnp, grk, gnk = mp
                    A = isface(grp, grk, gnp) and isface(grk, gnp, gnk)
                    B = isface(grp, grk, gnk) and isface(grp, gnp, gnk)
                    scored += [A or B, A or B]
        elif ns:
            scored += [None, None]
        for j in range(1, len(ns)):
            t3 = [map11.get(x) for x in (r, ns[j - 1], ns[j])]
            scored.append(None if any(x is None for x in t3) else isface(*t3))
        for s in scored:
            if s is None:
                unmapped += 1
            else:
                ok += s; bad += (not s)
                per_rail[rid][0] += s; per_rail[rid][1] += 1
        if ns:
            prev = (r, ns[0], ns[-1])

tot = ok + bad
print('teacher-forced face rate (mapped): %d/%d = %.1f%%   unmapped=%d nofitS=%d'
      % (ok, tot, 100 * ok / max(tot, 1), unmapped, nofit))
qual = sorted((100 * g / t, t, rid) for rid, (g, t) in per_rail.items() if t >= 6)
hist = Counter(int(q // 10) * 10 for q, t, _ in qual)
print('per-rail decile hist (>=6 scored):', sorted(hist.items()))
print('best:', ['r%d:%d%%(n=%d)' % (rid, q, t) for q, t, rid in qual[-12:]])
