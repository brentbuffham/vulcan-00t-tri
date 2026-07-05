# init_read9.py — DECISIVE probe: are ref-group op channels per-strip +6 counters?
# Model: each strip, on each round-robin turn, stamps its ref group with a 6-bit
# channel that advances +6 per turn (mod 64), lead byte constant per strip.
# Runs of consecutive identical (lead,ch) = one turn (a few quad pairs).
# Chain = linked runs ch -> ch+6 (allow +12 = skipped turn) with gi-locality.
# PASS: >=60% of runs link into chains AND #chains ~ 200-260 (e002/e004 counts).
# Then census: chain starts vs e002 gi's, chain ends vs e004 gi's.
import pickle
from collections import Counter

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))

# sequence of ref-group stamps (gi, lead, ch)
stamps = []
for gi, g in enumerate(groups):
    if g['refs'] and g['ops']:
        lead, arg = g['ops'][0]
        if (arg & 3) == 3 and 0x20 <= lead < 0x80:   # canonical op form
            stamps.append((gi, lead, arg >> 2))
print(f'ref-group stamps: {len(stamps)}')

# RLE into runs
runs = []
for gi, lead, ch in stamps:
    if runs and runs[-1][1] == lead and runs[-1][2] == ch and gi - runs[-1][3] <= 40:
        runs[-1][3] = gi; runs[-1][4] += 1
    else:
        runs.append([gi, lead, ch, gi, 1])   # [gi_start, lead, ch, gi_end, n]
print(f'runs: {len(runs)}   run-length census: {Counter(r[4] for r in runs).most_common(8)}')

# chain linking: open chains keyed by (lead, expected_next_ch)
WINDOW = 400   # max gi gap between a strip's turns
open_chains = []   # each: dict(lead, last_ch, last_gi, runs=[...])
chains_done = []
linked = 0
for r in runs:
    gi0, lead, ch, gi1, n = r
    # expire stale chains
    still = []
    for c in open_chains:
        if gi0 - c['last_gi'] > WINDOW: chains_done.append(c)
        else: still.append(c)
    open_chains = still
    # find open chain expecting this ch (+6 or +12 mod 64), same lead
    best = None
    for c in open_chains:
        if c['lead'] != lead: continue
        d = (ch - c['last_ch']) % 64
        if d in (6, 12):
            if best is None or c['last_gi'] > best['last_gi']: best = c
    if best is not None:
        best['last_ch'] = ch; best['last_gi'] = gi1; best['runs'].append(r); linked += 1
    else:
        open_chains.append(dict(lead=lead, last_ch=ch, last_gi=gi1, runs=[r]))
chains_done.extend(open_chains)
nruns = len(runs)
print(f'linked runs: {linked}/{nruns - len(chains_done)} link-attempts; chains: {len(chains_done)}')
frac = linked / max(nruns, 1)
print(f'fraction of runs that continue a chain: {frac*100:.0f}%  (rest start chains)')
clen = Counter(len(c["runs"]) for c in chains_done)
print('chain length (in turns) census:', clen.most_common(10))
long_chains = [c for c in chains_done if len(c['runs']) >= 3]
print(f'chains with >=3 turns: {len(long_chains)}   singleton chains: {clen[1]}')

# verdict inputs
e002 = [gi for gi, g in enumerate(groups) if g['delim'] == 'e002']
e004 = [gi for gi, g in enumerate(groups) if g['delim'] == 'e004']
print(f'\ne002: {len(e002)}  e004: {len(e004)}  chains(>=2 turns): {len(chains_done) - clen[1]}')

# chain start/end proximity to e002/e004
import bisect
def mindist(sorted_gis, gi):
    i = bisect.bisect_left(sorted_gis, gi); best = 10**9
    for j in (i - 1, i, i + 1):
        if 0 <= j < len(sorted_gis): best = min(best, abs(sorted_gis[j] - gi))
    return best
for name, evs in (('e002', e002), ('e004', e004)):
    for what, key in (('starts', 0), ('ends', 1)):
        ds = []
        for c in long_chains:
            gi = c['runs'][0][0] if key == 0 else c['runs'][-1][3]
            ds.append(mindist(evs, gi))
        within = sum(1 for x in ds if x <= 4)
        print(f'chain {what} within 4 groups of {name}: {within}/{len(ds)} ({within/max(len(ds),1)*100:.0f}%)')
import random
random.seed(5)
base = sum(1 for _ in range(1000) if mindist(e002, random.randrange(len(groups))) <= 4) / 10
print(f'control: random gi within 4 of e002: {base:.0f}%')

# concurrency trace: how many chains alive at gi (sample)
alive_at = []
for probe in range(200, len(groups), 400):
    n_alive = sum(1 for c in chains_done
                  if c['runs'][0][0] <= probe <= c['runs'][-1][3] and len(c['runs']) >= 2)
    alive_at.append((probe, n_alive))
print('concurrent chains (gi, n):', alive_at)
