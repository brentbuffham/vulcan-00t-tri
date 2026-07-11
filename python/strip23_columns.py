"""Step 2 core: is S = r + n a BOUSTROPHEDON column-pair constant?

Physical model: the coord emission order is a column-major serpentine. A
rail's ref r ascends column c while its mirror n descends the adjacent
column, so S = r + n is fixed by the two columns' [base,len].
  If columns alternate direction, a horizontal edge at height h joins
  slot (base_c + h) to slot (base_c' + len_c' - 1 - h)  =>
  S = base_c + base_c' + len_c' - 1  (constant per column pair).

Derive columns from slot ADJACENCY breaks (consecutive slots that are NOT
GT-mesh-adjacent = column boundary; emission is a 92% mesh walk). Then for
each verified rail, check S=fitS against the column-pair formula. map11/GT
used as MECHANISM answer key (teacher-forced, stated) -- to be replaced by
the GT-free coord-decode column boundaries if the mechanism holds.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
P = np.loadtxt('intercepts_gt.csv', delimiter=',')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# slot -> GT vertex  (map11 is slot->gtvert)
slot2gt = map11
maxslot = max(slot2gt)
# column boundaries: consecutive slots s,s+1 both mapped and NOT mesh-adjacent
bnds = [0]
for s in range(maxslot):
    a, b = slot2gt.get(s), slot2gt.get(s + 1)
    if a is None or b is None:
        continue
    if b not in nbr[a]:
        bnds.append(s + 1)
bnds = sorted(set(bnds))
# build column index per slot: col k covers [bnds[k], bnds[k+1])
colof = {}
for k in range(len(bnds)):
    lo = bnds[k]
    hi = bnds[k + 1] if k + 1 < len(bnds) else maxslot + 1
    for s in range(lo, hi):
        colof[s] = k
lens = {k: (bnds[k+1] if k+1 < len(bnds) else maxslot+1) - bnds[k]
        for k in range(len(bnds))}
print('columns:', len(bnds), ' median len', int(np.median(list(lens.values()))),
      ' len dist', sorted(Counter(min(v,60) for v in lens.values()).items())[:12])

# fitS per rail
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

# For each rail: r-values in column c_r; mirror n=S-r in column c_n.
# Test the boustrophedon identity per verified event:
#   S ?= base(c_r) + base(c_n) + len(c_n) - 1     (opposite dirs)
#   S ?= base(c_r) + base(c_n)                     (same dir, +offset)
hit_op = hit_sm = tot = 0
col_pairs = Counter()
Serr = Counter()
for rid, ts in byrail.items():
    S = fitS.get(rid)
    if S is None: continue
    for gi, r in ts:
        n = S - r
        if not (0 <= n <= maxslot): continue
        cr, cn = colof.get(r), colof.get(n)
        if cr is None or cn is None: continue
        tot += 1
        col_pairs[(cr, cn)] += 1
        base_r, base_n = bnds[cr], bnds[cn]
        S_op = base_r + base_n + lens[cn] - 1
        S_sm = base_r + base_n
        hit_op += (abs(S - S_op) <= 1)
        hit_sm += (abs(S - S_sm) <= 1)
        Serr[S - S_op] += 1
print('verified col-mapped events:', tot)
print('  S == base_r+base_n+len_n-1 (+-1): %d = %.1f%%' % (hit_op, 100*hit_op/max(tot,1)))
print('  S == base_r+base_n         (+-1): %d = %.1f%%' % (hit_sm, 100*hit_sm/max(tot,1)))
print('  S - S_op residual top12:', Serr.most_common(12))

# are r-col and n-col ADJACENT column indices? (|cr-cn|==1 expected)
dcol = Counter(abs(a-b) for (a,b),c in col_pairs.items() for _ in range(c))
print('|col_r - col_n| census:', sorted(dcol.items())[:8])
