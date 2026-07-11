"""Step 2: does emission ORDER pin the mirror slot n (hence S) GT-free?

Two emission clocks, both GT-free:
  E_all  = running count of idless e003 groups (alloc frontier)
  E_map  = running count of DISTINCT slots referenced/allocated
On verified events (n=S-r trusted GT-edge), test n vs E_all and n vs the
coord emission index of r's mesh position. Also: is n MONOTONE in gi within
a rail? Is S = n + r locally predictable from neighbouring rails' S?
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
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

# walk stream, maintain E_all; record verified (gi, rid, r, n, E_all)
E = 0
cur = None
rows = []
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = g2[gi]
    if g['delim'] == 'e003' and not g['is01'] and not g['refs']:
        E += 1
        if cur is not None:
            rid, r = cur
            S = fitS.get(rid)
            if S is not None:
                n = S - r
                if 0 <= n <= 2974:
                    a, b = map11.get(r), map11.get(n)
                    ver = a is not None and b is not None and b in nbr[a]
                    rows.append((gi, rid, r, n, E, ver))
V = [x for x in rows if x[5]]
print('verified alloc rows:', len(V))

# n vs E_all: correlation + best affine
ns = np.array([n for _,_,_,n,_,_ in V], float)
Es = np.array([E for _,_,_,_,E,_ in V], float)
if len(ns) > 2:
    cc = np.corrcoef(ns, Es)[0,1]
    A = np.vstack([Es, np.ones_like(Es)]).T
    (m, c), *_ = np.linalg.lstsq(A, ns, rcond=None)
    resid = ns - (m*Es + c)
    print('corr(n, E_all) = %.3f   fit n = %.3f*E + %.1f   |resid|<128: %.1f%%'
          % (cc, m, c, 100*np.mean(np.abs(resid) < 128)))

# Is n monotone within a rail (vs gi)?
mono = 0; tot = 0
for rid, ts in byrail.items():
    S = fitS.get(rid)
    if S is None: continue
    seq = [(gi, S - r) for gi, r in ts if 0 <= S - r <= 2974]
    if len(seq) < 3: continue
    tot += 1
    dirs = [np.sign(b[1]-a[1]) for a,b in zip(seq, seq[1:]) if b[1]!=a[1]]
    if dirs and all(x==dirs[0] for x in dirs): mono += 1
print('rails with MONOTONE n(gi): %d/%d' % (mono, tot))

# S = n + r constant per rail? spread of (S-r+r)=S trivially const by fitS.
# Instead: is fitS[rid] predictable from ADJACENT rails (born near same gi)?
births = sorted((byrail[rid][0][0], rid) for rid in fitS)
Svals = {rid: fitS[rid] for rid in fitS}
close_dS = []
for i in range(1, len(births)):
    (g0, r0), (g1, r1) = births[i-1], births[i]
    if g1 - g0 < 30:
        close_dS.append(Svals[r1] - Svals[r0])
cd = Counter(close_dS)
print('adjacent-birth (dgi<30) dS census top15:', cd.most_common(15))
print('  |dS|<=2:', sum(1 for x in close_dS if abs(x)<=2), '/', len(close_dS))
