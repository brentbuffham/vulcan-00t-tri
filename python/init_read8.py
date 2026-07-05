# init_read8.py — the sweep-phase channel as a strip-count readout:
# first-op arg bits[7:2] = phase counter, constant within a phase, +step between
# phases. Hypothesis: step size == #active strips (round-robin size), and the
# phase-run LENGTH == #groups per phase == same count => run length ~ step.
# Push/pop events = where step/run-length changes. Census it.
import pickle
from collections import Counter

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))

# idless e003 groups with first op 60:17/40:17-class: channel from SECOND op?
# 07-07: FIRST-op arg channel on REF groups steps +6. Take every group's first
# op (lead, arg); channel = arg >> 2.
seq = []
for gi, g in enumerate(groups):
    if not g['ops']: continue
    lead, arg = g['ops'][0]
    seq.append((gi, g['delim'], len(g['refs']), lead, arg, arg >> 2, arg & 3))

print('lo2 census of first-op arg:', Counter(s[6] for s in seq).most_common())
print()
print('=== raw walk g100..g190: gi delim refs lead:arg ch ===')
for s in seq:
    if 100 <= s[0] <= 190:
        print(f'g{s[0]:4d} {s[1]} r{s[2]} {s[3]:02x}:{s[4]:02x} ch={s[5]:2d}.{s[6]}')
