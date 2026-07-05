#!/usr/bin/env python3
"""NEXT STEP 1 (RESUME-2026-07-08): densify the slot<->GT answer key by pure
propagation, so per-strip INIT sites become exact.

Constraints per UNMAPPED slot s (GT used only as the answer key for map
construction, per established practice -- no value is invented, every accepted
slot is forced by a SINGLE GT row):
  (A) emission adjacency: mapped slots in {s-1, s+1}  (40% of GT edges are
      slot-offset-1, proven in alloc6).
  (B) fitted-S mirror: any mapped REF slot r on a rail with fitted S such that
      S - r == s  (serpentine-mirror partners are GT neighbours).
Candidate GT rows for s = INTERSECTION of the GT-neighbour sets of all its
constraints' GT rows. Accept iff that intersection is a SINGLE unclaimed row.
Collisions (one row proposed by >1 slot in a pass) are rejected and counted;
>2% collision rate => stop and report (spec halt condition).

Outputs (python/ cwd): updated thread.pkl (dense slot2gt/gt2slot + recomputed
rows), strip_table.npy, and a short report.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl', 'rb'))
F = np.load('faces_gt.npy')

# GT edge set + neighbour map (GT-index space)
E = set(); nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        E.add((min(u, v), max(u, v))); nbr[u].add(v); nbr[v].add(u)

# ---- fit S per rail (alloc7 logic) ----
g2rail = {}
for gi, r, rid in ref_events:
    g2rail[gi] = (rid, r)
items = []          # (k, gi, r, rid, cands) -- rid = rail of the preceding ref group
for k, gi, r, cands in rows:
    rid = None
    for gj in range(gi - 1, max(gi - 5, -1), -1):
        if gj in g2rail and g2rail[gj][1] == r:
            rid = g2rail[gj][0]; break
    items.append((k, gi, r, rid, cands))
rail_sums = defaultdict(Counter)
for k, gi, r, rid, cands in items:
    if rid is None: continue
    for n in cands:
        if abs(n - r) > 3:
            rail_sums[rid][n + r] += 1
fitS = {}
for rid, cnt in rail_sums.items():
    S, c = cnt.most_common(1)[0]
    if c >= 2: fitS[rid] = S
print(f'rails with fitted S (>=2 votes): {len(fitS)}')

# ref slots that live on a fitted-S rail  ->  list of (S, ref_slot)
rail_of_slot = defaultdict(set)   # slot -> {rid,...} it is a ref on
for rid, r in [(rid, r) for rid, vlist in [(rr['id'], rr['vals']) for rr in rails] for gi, r in vlist]:
    rail_of_slot[r].add(rid)
fitted_refslots = [(fitS[rid], r) for r in rail_of_slot for rid in rail_of_slot[r] if rid in fitS]

N_TOTAL = 2975
print(f'start: {len(slot2gt)} mapped slots')

# ------------------- propagation to fixpoint -------------------
def constraints_for(s):
    """Return list of GT-neighbour sets (one per constraint) for unmapped slot s."""
    cons = []
    # (A) emission adjacency
    for c in (s - 1, s + 1):
        if c in slot2gt:
            cons.append(nbr[slot2gt[c]])
    # (B) fitted-S mirror: mapped ref r with S - r == s
    for S, r in mirror_index.get(s, ()):
        if r in slot2gt:
            cons.append(nbr[slot2gt[r]])
    return cons

growth = [len(slot2gt)]
collisions_total = 0
passno = 0
while True:
    passno += 1
    # mirror index rebuilt each pass (mapped set changes): s -> list of (S, r) with S-r==s and r mapped
    mirror_index = defaultdict(list)
    for S, r in fitted_refslots:
        if r in slot2gt:
            mirror_index[S - r].append((S, r))
    proposals = {}          # slot -> proposed GT row
    row_claims = defaultdict(list)
    for s in range(N_TOTAL):
        if s in slot2gt: continue
        cons = constraints_for(s)
        if not cons: continue
        inter = set.intersection(*cons) if len(cons) > 1 else set(cons[0])
        inter = {g for g in inter if g not in gt2slot}   # unclaimed only
        if len(inter) == 1:
            g = next(iter(inter))
            proposals[s] = g
            row_claims[g].append(s)
    # reject collisions (same GT row proposed by >1 slot)
    accepted = 0; coll = 0
    for g, ss in row_claims.items():
        if len(ss) == 1:
            s = ss[0]
            slot2gt[s] = g; gt2slot[g] = s; accepted += 1
        else:
            coll += len(ss)
    collisions_total += coll
    growth.append(len(slot2gt))
    rate = coll / max(accepted + coll, 1)
    print(f'pass {passno}: +{accepted} accepted, {coll} collisions ({rate*100:.1f}%), total {len(slot2gt)}')
    if accepted == 0:
        break
    if rate > 0.02:
        print(f'!! collision rate {rate*100:.1f}% > 2% -- STOP per spec halt condition')
        break

print(f'\nGROWTH CURVE: {growth}')
print(f'final mapped: {len(slot2gt)} / {N_TOTAL}  ({len(slot2gt)/N_TOTAL*100:.1f}%)')
print(f'total collisions rejected: {collisions_total}')

# sanity: how many accepted slots land on a REAL GT-adjacent row of an anchor?
# (already guaranteed by construction; report edge-consistency of the dense map)
soff = Counter()
for u, v in E:
    su, sv = gt2slot.get(u), gt2slot.get(v)
    if su is None or sv is None: continue
    soff[abs(su - sv)] += 1
tot = sum(soff.values())
print(f'dense map GT-edges covered: {tot}  offset1 {soff[1]} ({soff[1]/max(tot,1)*100:.0f}%), <=3 {sum(v for k,v in soff.items() if k<=3)}')

# ------------------- recompute rows with dense map + re-save thread.pkl -------------------
new_rows = []
k = 0; last_ref = None
for gi, g in enumerate(groups):
    if g['refs']:
        last_ref = g['refs'][-1]
    elif g['delim'] == 'e003':
        cands = []
        gr = slot2gt.get(last_ref) if last_ref is not None else None
        if gr is not None:
            cands = sorted(gt2slot[v] for v in nbr[gr] if v in gt2slot)
        new_rows.append((k, gi, last_ref, cands))
        k += 1
pickle.dump((slot2gt, gt2slot, new_rows), open('thread.pkl', 'wb'))
print(f'\nre-saved thread.pkl (dense): {k} idless groups, '
      f'{sum(1 for r in new_rows if r[3])} with >=1 cand')
