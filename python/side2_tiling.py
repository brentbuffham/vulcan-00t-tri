"""SIDE-BIT HUNT 2, probe 1: GLOBAL structure of the per-rail side bit.
Setup copied from side1_sweep.py / col_probe9.py (fitS teacher key = SCORING ONLY).

Tests (all features GT-free, scored vs teacher side):
 A. TEMPORAL COHERENCE: side sequence in rail-birth (gi) order. Run lengths,
    lag-1 agreement. If side is a band/sweep state it should run in blocks.
 B. LIVE-RANK (round-robin tiling): at each rail's birth, order the live
    rails by r_med; test side vs rank%2, rank position, r_med vs live median.
 C. FRONTIER DIRECTION: local drift of r_med among recently-born rails
    (is the pack of rails moving to higher or lower slots?); side vs drift.
 D. COLUMN RELATION: side vs (col of r_med) relative to live pack's columns.
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
cv = pickle.load(open('columns_v1.pkl', 'rb'))
colof = cv['colof']

# ---- teacher key (SCORING ONLY) — exact copy of side1_sweep construction
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
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
side = {}
for rid, S in fitS.items():
    rs = [r for gi, r in byrail[rid]]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side[rid] = 1 if (S - rmed) > rmed else -1
print('labelled rails:', len(side), 'balance:', Counter(side.values()))

# ---- GT-free per-rail summary (ALL rails, incl. unlabelled, for live sets)
info = {}
for rid, ts in byrail.items():
    gis = [gi for gi, r in ts]
    rs = [r for gi, r in ts]
    rmed = int(np.median(rs))
    info[rid] = dict(g0=min(gis), g1=max(gis), rmed=rmed,
                     col=int(colof[rmed]) if 0 <= rmed < N else -1,
                     n=len(ts))
rids_all = sorted(info, key=lambda r: info[r]['g0'])
lab = [rid for rid in rids_all if rid in side]
print('rails total:', len(rids_all), ' labelled in birth order:', len(lab))

# ---- A. temporal coherence
seq = [side[rid] for rid in lab]
runs = 1 + sum(1 for i in range(1, len(seq)) if seq[i] != seq[i-1])
lag1 = sum(1 for i in range(1, len(seq)) if seq[i] == seq[i-1])
print('\nA. side in birth order: runs=%d (of %d), lag-1 same = %d/%d = %.1f%%'
      % (runs, len(seq), lag1, len(seq)-1, 100*lag1/(len(seq)-1)))
print('   first 60:', ''.join('+' if s > 0 else '-' for s in seq[:60]))
print('   next  60:', ''.join('+' if s > 0 else '-' for s in seq[60:120]))
print('   next  60:', ''.join('+' if s > 0 else '-' for s in seq[120:180]))
print('   rest    :', ''.join('+' if s > 0 else '-' for s in seq[180:]))

# ---- B. live-rank at birth
def live_at(g, exclude=None, min_refs=2):
    out = []
    for rid in rids_all:
        i = info[rid]
        if i['n'] >= min_refs and i['g0'] <= g <= i['g1'] and rid != exclude:
            out.append(rid)
    return out

tabs = defaultdict(Counter)
for rid in lab:
    i = info[rid]
    lv = live_at(i['g0'], exclude=rid)
    if not lv:
        continue
    order = sorted(lv + [rid], key=lambda r: info[r]['rmed'])
    rank = order.index(rid)
    m = len(order)
    s = side[rid]
    tabs['rank%2'][(rank % 2, s)] += 1
    tabs['rank_top_bot'][('bot' if rank == 0 else 'top' if rank == m-1 else 'mid', s)] += 1
    med_live = np.median([info[r]['rmed'] for r in lv])
    tabs['above_live_med'][(int(i['rmed'] > med_live), s)] += 1
    # rank by column
    orderc = sorted(lv + [rid], key=lambda r: info[r]['col'])
    tabs['crank%2'][(orderc.index(rid) % 2, s)] += 1

# ---- C. frontier drift: slope of rmed vs birth order among last K births
K = 8
births = [(info[rid]['g0'], info[rid]['rmed']) for rid in rids_all]
for rid in lab:
    i = info[rid]
    prev = [(g, rm) for g, rm in births if g < i['g0']][-K:]
    if len(prev) >= 3:
        xs = np.arange(len(prev)); ys = np.array([rm for g, rm in prev], float)
        slope = np.polyfit(xs, ys, 1)[0]
        tabs['drift_sign'][(int(np.sign(slope)), side[rid])] += 1
        tabs['rmed_vs_prev'][(int(i['rmed'] > prev[-1][1]), side[rid])] += 1

# ---- D. column relative to live pack
for rid in lab:
    i = info[rid]
    lv = live_at(i['g0'], exclude=rid)
    if not lv:
        continue
    cols = [info[r]['col'] for r in lv]
    tabs['col_vs_livemax'][(int(i['col'] >= max(cols)), side[rid])] += 1
    tabs['col_vs_livemin'][(int(i['col'] <= min(cols)), side[rid])] += 1

print('\n=== contingency (feature value -> side counts, purity) ===')
for fname, tab in tabs.items():
    vals = sorted(set(k[0] for k in tab))
    tot = ok = 0
    parts = []
    for v in vals:
        a, b = tab[(v, 1)], tab[(v, -1)]
        tot += a + b; ok += max(a, b)
        parts.append('%s:+%d/-%d' % (v, a, b))
    print('  %-16s purity %d/%d = %.1f%%   [%s]'
          % (fname, ok, tot, 100*ok/max(tot, 1), '  '.join(parts)))
