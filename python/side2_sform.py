"""SIDE-BIT HUNT 2, probe 10: do S-form refs announce the strip constant?
205 S-form refs vs 1489 A-form. If an S-form ref at/near rail birth carries
the OTHER line's slot (the first mirror partner), then S = r_A + r_S is
read STRAIGHT off the stream -> side falls out. Test vs T1 fitS.
Also dump group context around rail births to see the pattern.
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P)
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']

# forms census
fc = Counter()
for g in groups:
    for i, r in enumerate(g['refs']):
        f = g['forms'][i] if i < len(g['forms']) else '?'
        fc[f] += 1
print('ref forms census:', dict(fc))

g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)
byrail = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        byrail[g2[gi][0]].append((gi, g2[gi][1]))

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for x, y in ((a, b), (b, c), (c, a)):
        nbr[x].add(y); nbr[y].add(x)
fitS = {}; margin1 = {}
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
        mc = votes.most_common()
        S, c = mc[0]
        if c >= 2:
            fitS[rid] = S
            margin1[rid] = c - (mc[1][1] if len(mc) > 1 else 0)

# S-form refs: where are they relative to rails?
sform = []
for gi, g in enumerate(groups):
    for i, r in enumerate(g['refs']):
        f = g['forms'][i] if i < len(g['forms']) else '?'
        if f == 'S':
            sform.append((gi, r))
print('S-form refs:', len(sform))

# for each rail, S-form refs in gi window [birth-6, birth+6]
hit2 = 0; hit_any = 0; tot = 0
det = Counter()
for rid, S in fitS.items():
    ts = byrail[rid]
    g0 = ts[0][0]
    r0 = ts[0][1]
    near = [(gi, r) for gi, r in sform if g0 - 8 <= gi <= g0 + 8]
    if not near:
        det['no_sform_near'] += 1
        continue
    tot += 1
    best = min(abs(r0 + r - S) for gi, r in near)
    hit2 += (best <= 2)
    # also test r_S alone vs mirror n0 = S - r0
    bestn = min(abs(r - (S - r0)) for gi, r in near)
    hit_any += (bestn <= 2)
print('rails with S-form near birth: %d/%d' % (tot, len(fitS)))
print('  r_A + r_S == S (+-2): %d/%d' % (hit2, tot))
print('  r_S == mirror n0 (+-2): %d/%d' % (hit_any, tot))

# where do S-form refs sit inside rails generally?
inrail = Counter()
allgi = {gi: rid for rid, ts in byrail.items() for gi, r in ts}
for gi, r in sform:
    if gi in allgi:
        rid = allgi[gi]
        ts = byrail[rid]
        idx = [i for i, (g, _) in enumerate(ts) if g == gi][0]
        inrail['birth' if idx == 0 else 'mid' if idx < len(ts)-1 else 'last'] += 1
    else:
        inrail['outside_rails'] += 1
print('S-form position within rails:', dict(inrail))

# does the S-FORM ref's own value + NEAREST A-ref in SAME group give S?
same_group = 0; sg_hit = 0
for gi, g in enumerate(groups):
    fs = g['forms']; rs = g['refs']
    if len(rs) >= 2 and 'S' in fs and 'A' in fs:
        same_group += 1
        rA = [r for r, f in zip(rs, fs) if f == 'A'][0]
        rS = [r for r, f in zip(rs, fs) if f == 'S'][0]
        # which rail is this group in?
        rid = allgi.get(gi)
        if rid is not None and rid in fitS:
            sg_hit += (abs(rA + rS - fitS[rid]) <= 2)
print('multi-ref groups with A+S: %d, of which rA+rS==fitS(+-2): %d'
      % (same_group, sg_hit))

# dump context around 8 rail births (T1-firm rails)
firm = [rid for rid in fitS if margin1[rid] >= 2][:8]
for rid in firm:
    ts = byrail[rid]
    g0 = ts[0][0]
    rs = [r for _, r in ts]
    rmed = int(np.median(rs))
    print('\nrail %d birth gi=%d refs %d..%d  fitS=%d (n0 should be %d)'
          % (rid, g0, min(rs), max(rs), fitS[rid], fitS[rid] - ts[0][1]))
    for gi in range(max(0, g0 - 4), g0 + 5):
        g = groups[gi]
        print('  gi=%5d %s%s delim=%s fop=%-6s lo=%-10s refs=%s forms=%s' %
              (gi, '*' if gi == g0 else ' ',
               'R' if g['refs'] else ('0' if g['is01'] else 'i'),
               g['delim'], g['fop'], g['lo'], g['refs'], g['forms']))
