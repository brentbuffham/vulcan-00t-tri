"""GT-FREE slot -> column partition of the coord emission order (intercepts).

Signal: P_v11_intercepts.npy (the decoder's OWN GT-free positions; 52% xyz,
XY substantially better). Geometry of the emission (established GT-free,
col_probe2..5):
  - boustrophedon over parallel scan LINES (columns): within a column the
    point steps ~4 m along the line, at a fold it hops laterally ~3-4 m to
    the next line and REVERSES -> w = XY . u_perp is a staircase;
  - some folds return on (nearly) the SAME w (reversal only), and some
    regions have different line orientation -> a second, direction-reversal
    detector is needed on top of the w staircase;
  - sparse interloper slots (concurrent threads / decode errors) sprinkle
    inside columns and inherit the enclosing column (slot arithmetic).

Method (all GT-free):
 A. global sweep axis u = modal sane-step direction; w staircase:
    sliding median (win 9) -> level runs -> cleanup (merge same level,
    delete interloper bursts, absorb orphans) -> boundaries refined by
    optimal split of raw-w labels (interlopers don't vote).
 B. reversal post-pass: per column, robust line fit of its own points;
    inliers projected on the line; a persistent monotonicity REVERSAL
    (best split reducing violations, margin >= 3) adds a boundary;
    applied recursively.
 S formula downstream: S = base(col_r) + top(col_n).

Validation (categories stated in output):
 L1: fold recall/precision vs fitS-implied folds (teacher key, odd-S rule).
 L2: S_pred = base(col_r)+top(col_n) vs fitS per verified event, +-2
     (teacher-forced check of the partition; baseline 21.2% = strip26).

Writes columns_v1.pkl: {'colof', 'bounds', 'u'}.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

WIN = 9
TOL = 1.2
MINRUN = 4

P = np.load('P_v11_intercepts.npy')
N = len(P)
XY = P[:, :2].astype(float)
V = XY[1:] - XY[:-1]
L = np.hypot(V[:, 0], V[:, 1])
sane = (L > 1.0) & (L < 8.0)
ang = np.mod(np.arctan2(V[:, 1], V[:, 0])[sane], np.pi)
hist, edges = np.histogram(ang, bins=180)
k = hist.argmax()
theta = (edges[k] + edges[k + 1]) / 2
u = np.array([np.cos(theta), np.sin(theta)])
up = np.array([-u[1], u[0]])
w = XY @ up

H = WIN // 2
m = np.empty(N)
for s in range(N):
    lo, hi = max(0, s - H), min(N, s + H + 1)
    m[s] = np.median(w[lo:hi])

runs = [[0, 0]]
for s in range(1, N):
    if abs(m[s] - m[runs[-1][1]]) > 1.0:
        runs.append([s, s])
    else:
        runs[-1][1] = s
lev = lambda r: float(np.median(m[r[0]:r[1] + 1]))
runs = [[a, b, lev([a, b])] for a, b in runs]

changed = True
while changed:
    changed = False
    i = 0
    while i + 1 < len(runs):
        if abs(runs[i][2] - runs[i + 1][2]) < TOL:
            runs[i] = [runs[i][0], runs[i + 1][1], lev([runs[i][0], runs[i + 1][1]])]
            del runs[i + 1]
            changed = True
        else:
            i += 1
    i = 1
    while i + 1 < len(runs):
        ln = runs[i][1] - runs[i][0] + 1
        if ln < MINRUN and abs(runs[i - 1][2] - runs[i + 1][2]) < TOL:
            runs[i - 1] = [runs[i - 1][0], runs[i + 1][1],
                           lev([runs[i - 1][0], runs[i + 1][1]])]
            del runs[i:i + 2]
            changed = True
        else:
            i += 1
    i = 0
    while i < len(runs):
        ln = runs[i][1] - runs[i][0] + 1
        if ln < MINRUN and len(runs) > 1:
            dl = abs(runs[i][2] - runs[i - 1][2]) if i > 0 else np.inf
            dr = abs(runs[i][2] - runs[i + 1][2]) if i + 1 < len(runs) else np.inf
            j = i - 1 if dl <= dr else i + 1
            a, b = min(runs[i][0], runs[j][0]), max(runs[i][1], runs[j][1])
            keeplev = runs[j][2]
            runs[min(i, j)] = [a, b, keeplev]
            del runs[max(i, j)]
            changed = True
        else:
            i += 1

# boundary refinement: optimal split of raw-w labels around each junction
bounds = [0]
for r1, r2 in zip(runs[:-1], runs[1:]):
    wA, wB = r1[2], r2[2]
    j = r2[0]
    lo = max(j - H - 2, bounds[-1] + 1)
    hi = min(j + H + 3, N)
    votes = []
    for s in range(lo, hi):
        dA, dB = abs(w[s] - wA), abs(w[s] - wB)
        if dA < TOL and dB > TOL:
            votes.append((s, 0))
        elif dB < TOL and dA > TOL:
            votes.append((s, 1))
    b = j
    if votes:
        bestmis = None
        for bc in range(lo, hi + 1):
            mis = sum(1 for s, lab in votes
                      if (lab == 0 and s >= bc) or (lab == 1 and s < bc))
            if bestmis is None or mis < bestmis:
                bestmis, b = mis, bc
    if b > bounds[-1]:
        bounds.append(b)
bounds.append(N)
bounds = sorted(set(bounds))
print('staircase pass: %d columns' % (len(bounds) - 1))

# ---- B. reversal post-pass (recursive)
def seg_line(a, b):
    """robust local line: modal SANE-STEP direction + median offset.
    Immune to interlopers (steps to/from them are not sane)."""
    idx = [s for s in range(a, min(b, N - 1)) if sane[s]]
    if len(idx) < 3:
        return None, None
    aa = np.mod(np.arctan2(V[idx, 1], V[idx, 0]), np.pi)
    hh, ee = np.histogram(aa, bins=36)
    kk = hh.argmax()
    th = (ee[kk] + ee[kk + 1]) / 2
    d = np.array([np.cos(th), np.sin(th)])
    npv = np.array([-d[1], d[0]])
    offs = np.median([XY[s] @ npv for s in idx])
    c0 = offs * npv          # a point on the line (projection form)
    return d, offs

def reversal_split(a, b):
    """return interior split slot or None."""
    n = b - a
    if n < 8:
        return None
    d, offs = seg_line(a, b)
    if d is None:
        return None
    npv = np.array([-d[1], d[0]])
    inl = [s for s in range(a, b) if abs(XY[s] @ npv - offs) < 1.8]
    if len(inl) < 8:
        return None
    q = [(s, XY[s] @ d) for s in inl]
    # violations for monotone-asc and monotone-desc over consecutive inliers
    def viol(seq):
        va = sum(1 for i in range(1, len(seq)) if seq[i][1] < seq[i - 1][1] - 0.5)
        vd = sum(1 for i in range(1, len(seq)) if seq[i][1] > seq[i - 1][1] + 0.5)
        return min(va, vd)
    v0 = viol(q)
    bestc, bestv = None, v0
    for ci in range(4, len(q) - 3):
        v = viol(q[:ci]) + viol(q[ci:])
        if v < bestv:
            bestv, bestc = v, ci
    if bestc is not None and v0 - bestv >= 3:
        return q[bestc][0]          # first slot of the new column
    return None

changed = True
while changed:
    changed = False
    nb = [bounds[0]]
    for a, b in zip(bounds[:-1], bounds[1:]):
        sp = reversal_split(a, b)
        if sp is not None and a < sp < b:
            nb.extend([sp, b])
            changed = True
        else:
            nb.append(b)
    bounds = sorted(set(nb))
print('after reversal pass: %d columns' % (len(bounds) - 1))

ncol = len(bounds) - 1
colof = np.zeros(N, int)
for k2 in range(ncol):
    colof[bounds[k2]:bounds[k2 + 1]] = k2
clen = np.diff(bounds)
print('GT-FREE partition: %d columns, len median %d, p10/p90 %d/%d' %
      (ncol, int(np.median(clen)), int(np.percentile(clen, 10)),
       int(np.percentile(clen, 90))))
base = {k2: bounds[k2] for k2 in range(ncol)}
top = {k2: bounds[k2 + 1] - 1 for k2 in range(ncol)}

pickle.dump({'colof': colof, 'bounds': bounds, 'u': u},
            open('columns_v1.pkl', 'wb'))
print('wrote columns_v1.pkl')

# ---------------- VALIDATION (answer keys, scoring only) ----------------
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for x, y in ((a, b), (b, c), (c, a)):
        nbr[x].add(y); nbr[y].add(x)
g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
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
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S

implied = sorted({(S - 1) // 2 for S in fitS.values() if S % 2 == 1})
folds = [b - 1 for b in bounds[1:-1]]
myf = np.array(folds)
tolr = 2
hitP = sum(1 for s in folds if implied and min(abs(s - kf) for kf in implied) <= tolr)
hitR = sum(1 for kf in implied if len(myf) and np.min(np.abs(myf - kf)) <= tolr)
print('\nL1 [GT-free folds vs fitS-implied odd-S folds (teacher key)]:')
print('  teacher folds:', len(implied), ' my folds:', len(folds))
print('  recall: %d/%d = %.1f%%   precision: %d/%d = %.1f%%' %
      (hitR, len(implied), 100 * hitR / max(len(implied), 1),
       hitP, len(folds), 100 * hitP / max(len(folds), 1)))

resid = Counter()
hit = hitE = tot = 0
railstat = defaultdict(lambda: [0, 0])
for rid, S in sorted(fitS.items()):
    for gi, r in byrail[rid]:
        n = S - r
        if not (0 <= n < N): continue
        a, b = map11.get(r), map11.get(n)
        if a is None or b is None or b not in nbr[a]: continue
        cr, cn = colof[r], colof[n]
        tot += 1
        S_pred = base[cr] + top[cn]
        d = S - S_pred
        resid[max(-15, min(15, d))] += 1
        ok = abs(d) <= 2
        hit += ok
        hitE += (ok or abs(S - (top[cr] + base[cn])) <= 2)
        railstat[rid][0] += ok; railstat[rid][1] += 1
print('\nL2 [teacher-forced check: fitS-verified events, +-2] events:', tot)
print('  S == base(c_r)+top(c_n): %d = %.1f%%' % (hit, 100 * hit / max(tot, 1)))
print('  either-form (diagnostic): %d = %.1f%%' % (hitE, 100 * hitE / max(tot, 1)))
rails_all = sum(1 for h, tt in railstat.values() if h == tt)
rails_any = sum(1 for h, tt in railstat.values() if h > 0)
print('  rails: all-hit %d / any-hit %d / scored %d' %
      (rails_all, rails_any, len(railstat)))
print('  resid histogram:', sorted(resid.items()))
