"""Test: are A-refs FRONTIER-RELATIVE (r = S_running - d, d ~ column pitch)?

S_running = number of new-vertex allocations so far (idless e003 groups),
i.e. the emission frontier, assuming allocation = sequential emission slots.
If refs reuse "same row, previous column", d = S - r should be ~pitch and
locally smooth (varies slowly with column length). GT-free.
"""
import pickle, collections, statistics

groups = pickle.load(open('refs_v2.pkl', 'rb'))

S = 3  # first triangle allocates 3 slots before any ref appears (init guess)
rows = []
for i, g in enumerate(groups):
    if g['is01']:
        continue
    if not g['refs'] and g['delim'] == 'e003':
        S += 1
        continue
    for r, f in zip(g['refs'], g['forms']):
        rows.append((i, f, r, S, S - r))

ds = [d for _, f, r, s, d in rows if f == 'A']
print('A-refs: n=%d  d=S-r  median=%s  mean=%.1f' % (
    len(ds), statistics.median(ds), statistics.mean(ds)))
c = collections.Counter(ds)
print('top d:', c.most_common(20))
neg = sum(1 for d in ds if d < 0)
print('d<0 (ref ahead of frontier):', neg, '/', len(ds))
band = sum(1 for d in ds if 60 <= d <= 200)
print('d in [60,200]:', band, '/', len(ds), '= %.1f%%' % (100*band/len(ds)))

# local smoothness: consecutive A-ref d deltas
dd = [b - a for a, b in zip(ds, ds[1:])]
cdd = collections.Counter(dd)
print('consecutive d-delta top20:', cdd.most_common(20))
small = sum(1 for x in dd if abs(x) <= 3)
print('|d-delta|<=3: %d/%d = %.1f%%' % (small, len(dd), 100*small/len(dd)))

# print a strip of the sequence to eyeball
print('\nfirst 40 ref rows (gi, form, r, S, d):')
for row in rows[:40]:
    print('  g%-5d %s r=%-5d S=%-5d d=%d' % row)
