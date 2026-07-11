"""SIDE-BIT SWEEP (Opus, spec: RESUME-07-12 / STRIP_SCHEDULE §COLUMN PARTITION).

Target: per-rail side bit = sign((S - r_med) - r_med) from fitS teacher key.
col_probe9 washed sweep-dir/r-trend/parity (~50-56%). Now test FACE-SIDE
BYTE channels for a >=90% predictor:
  - ref-group fop lead/arg (birth + modal)
  - idless-group payload lead nibble (2X vs 4X) and finalizer (40:1b/20:1b)
    -- the MYSTERY_A candidate bit-flips
  - delim class of the ref group (e002/e003/e004)
  - ref FORM (A vs S)
  - lo value at birth (esp v>=9 birth markers)
  - insertion order: idless BEFORE or AFTER its ref within the turn (A/B phase)
All GT-free features; teacher key used ONLY to score. Report purity per
feature (best-guess side | feature value).
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

P = np.load('P_v11_intercepts.npy')
N = len(P)
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for x, y in ((a, b), (b, c), (c, a)):
        nbr[x].add(y); nbr[y].add(x)
g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)
byrail = defaultdict(list)      # rid -> [(gi, r)] ref groups in stream order
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

# per-rail teacher side bit
side = {}
for rid, S in fitS.items():
    rs = [r for gi, r in byrail[rid]]
    rmed = int(np.median(rs))
    if not (0 <= rmed < N):
        continue
    side[rid] = 1 if (S - rmed) > rmed else -1
print('rails with side label:', len(side), ' balance:',
      Counter(side.values()))

# collect per-rail byte features. For each ref group, find the FOLLOWING
# idless e003 group(s) in the same turn (up to next ref/delim change).
def idless_after(gi):
    outs = []
    j = gi + 1
    while j < len(groups):
        g = groups[j]
        if g['refs']:
            break
        if g['delim'] == 'e003' and not g['is01'] and not g['refs']:
            outs.append(j)
        elif g['delim'] not in ('e003',):
            break
        j += 1
    return outs

feat = defaultdict(lambda: defaultdict(Counter))   # fname -> value -> side Counter
for rid in side:
    s = side[rid]
    fop_leads = Counter(); fop_args = Counter()
    pay_nib = Counter(); fin = Counter(); dlm = Counter()
    forms = Counter(); los = Counter(); ins_before = Counter()
    for gi, r in byrail[rid]:
        g = groups[gi]
        dlm[g['delim']] += 1
        if g['fop']:
            fop_leads[int(g['fop'][:2], 16)] += 1
            if len(g['fop']) >= 4:
                fop_args[int(g['fop'][2:4], 16)] += 1
        forms[g['forms'][0] if g['forms'] else '?'] += 1
        ids = idless_after(gi)
        for j in ids:
            ig = groups[j]
            if ig['ops']:
                pay_nib[ig['ops'][0][0]] += 1        # first hex nibble of payload lead
                fin[ig['ops'][-1]] += 1               # finalizer op
            if ig['lo']:
                los[ig['lo'][0]] += 1
    # modal features -> vote
    def modal(c):
        return c.most_common(1)[0][0] if c else None
    for fname, c in (('fop_lead', fop_leads), ('fop_arg', fop_args),
                     ('pay_nib', pay_nib), ('finalizer', fin),
                     ('delim', dlm), ('form', forms), ('lo_modal', los)):
        m = modal(c)
        if m is not None:
            feat[fname][m][s] += 1
    # birth lo
    bgi = byrail[rid][0][0]
    bids = idless_after(bgi)
    if bids and groups[bids[0]]['lo']:
        feat['lo_birth'][groups[bids[0]]['lo'][0]][s] += 1
    # birth lo >=9 flag
    blo9 = 1 if (bids and groups[bids[0]]['lo'] and groups[bids[0]]['lo'][0] >= 9) else 0
    feat['lo_birth>=9'][blo9][s] += 1

print('\n=== side-bit purity by feature (best-guess side | value) ===')
for fname, vals in feat.items():
    tot = ok = 0
    nval = len(vals)
    for v, sc in vals.items():
        tot += sc[1] + sc[-1]
        ok += max(sc[1], sc[-1])
    print('  %-14s purity %d/%d = %.1f%%  (%d distinct values)'
          % (fname, ok, tot, 100 * ok / max(tot, 1), nval))

# detail for the most promising
print('\ndetail finalizer:', {k: dict(v) for k, v in
      sorted(feat['finalizer'].items(), key=lambda kv:-(kv[1][1]+kv[1][-1]))[:8]})
print('detail pay_nib:', {k: dict(v) for k, v in feat['pay_nib'].items()})
print('detail form:', {k: dict(v) for k, v in feat['form'].items()})
print('detail delim:', {k: dict(v) for k, v in feat['delim'].items()})
