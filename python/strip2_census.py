"""RESUME-2026-07-11 step 1 census: anchor-segmented strip structure.

Questions (all GT-free except where labeled):
  A. How many groups carry A-form (absolute) refs? S-form? idless? is01/other?
  B. A->A step census (should be -95..-160 column pitch) and segment lengths
     (groups between consecutive A-anchors).
  C. Within a segment: how do S-form refs step relative to the anchor?
     (expect +1/-1 walk along previous column if anchors are fold inits)
  D. Composition of a segment: counts of idless (C) vs ref (R/L) groups.
"""
import pickle, collections

groups = pickle.load(open('refs_v2.pkl', 'rb'))
N = len(groups)

# --- A. composition census -------------------------------------------------
kinds = collections.Counter()
for g in groups:
    if g['is01']:
        kinds['is01_nonface'] += 1
    elif not g['refs']:
        kinds['idless'] += 1
    else:
        kinds['+'.join(g['forms'])] += 1
print('A. group kinds:', dict(kinds), 'total', N)

delims = collections.Counter(g['delim'] for g in groups)
print('   delims:', dict(delims.most_common(10)))

# --- B. anchor steps + segment lengths --------------------------------------
anchors = [(i, g['refs'][0]) for i, g in enumerate(groups)
           if g['refs'] and g['forms'][0] == 'A']
print('B. anchors (first-ref A):', len(anchors))
steps = collections.Counter(b[1] - a[1] for a, b in zip(anchors, anchors[1:]))
print('   top A->A steps:', steps.most_common(15))
seglen = collections.Counter(b[0] - a[0] for a, b in zip(anchors, anchors[1:]))
print('   seg lengths (groups between anchors):', sorted(seglen.items())[:25])
print('   seg length tail:', sorted(seglen.items())[-10:])

# --- C. S-ref walk relative to segment anchor -------------------------------
# for each segment: anchor value r0, then S refs r1,r2,... -> deltas r_k - r0
# and consecutive S-step census
sdelta_anchor = collections.Counter()
sstep = collections.Counter()
for (i0, r0), (i1, _) in zip(anchors, anchors[1:] + [(N, None)]):
    prev = r0
    for g in groups[i0:i1]:
        if g['is01'] or not g['refs']:
            continue
        for r, f in zip(g['refs'], g['forms']):
            if f == 'S':
                sdelta_anchor[r - r0] += 1
                sstep[r - prev] += 1
                prev = r
print('C. S-ref delta vs anchor (top20):', sdelta_anchor.most_common(20))
print('   S-ref consecutive step (top20):', sstep.most_common(20))

# --- D. per-segment composition ---------------------------------------------
comp = collections.Counter()
for (i0, _), (i1, _) in zip(anchors, anchors[1:] + [(N, None)]):
    nc = sum(1 for g in groups[i0:i1] if not g['is01'] and not g['refs'])
    nr = sum(1 for g in groups[i0:i1] if g['refs'])
    comp[(nr, nc)] += 1
print('D. per-segment (n_refgroups, n_idless) top20:', comp.most_common(20))
