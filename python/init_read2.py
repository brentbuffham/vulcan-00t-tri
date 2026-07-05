# init_read2.py — test whether n0 is DERIVED serpentine state:
#  T1: n0 is a coord-emission COLUMN BOUNDARY (slot s where the (s,s+1) or
#      (s-1,s) emission-adjacency GT-edge chain breaks), vs base rate.
#  T2: n0 is at/adjacent to the far end of the column NEXT to r's column.
#  T3: d = -sign(ref-rail direction) for the 18 strips with d != 0.
import pickle, re
import numpy as np
from collections import defaultdict

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread_970.pkl', 'rb'))
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)

N = 2975
# emission-adjacency edge flag: is (s, s+1) a GT edge? (only where both mapped)
adj = np.zeros(N, dtype=np.int8)  # 1=edge, -1=not-edge, 0=unknown
for s in range(N - 1):
    if s in slot2gt and (s + 1) in slot2gt:
        adj[s] = 1 if (slot2gt[s + 1] in nbr[slot2gt[s]]) else -1
known = int((adj != 0).sum())
print(f'adjacency known for {known}/{N-1} slot pairs; edge={int((adj==1).sum())} notedge={int((adj==-1).sum())}')

def boundary_status(s):
    """Is slot s a column boundary? left break = (s-1,s) not edge; right break = (s,s+1) not edge."""
    L = adj[s - 1] if s >= 1 else -1
    R = adj[s] if s < N - 1 else -1
    return L, R

# parse init sites
sites = []
for line in open('init_sites.txt'):
    m = re.match(r'gi=\s*(\d+) rid=\s*(\d+) n0=\s*(\d+) r=\s*(\d+)', line)
    if m:
        sites.append(tuple(map(int, m.groups())))
print(f'{len(sites)} sites')

# T1: n0 boundary census
print('\n=== T1: is n0 a column boundary? (L,R adjacency of n0; 1=edge -1=break 0=unknown) ===')
cnt = defaultdict(int)
for gi, rid, n0, r in sites:
    L, R = boundary_status(n0)
    cnt[(int(L), int(R))] += 1
print(dict(cnt))
# base rate: fraction of known slots that are boundaries
import random
base = defaultdict(int)
for s in range(1, N - 1):
    L, R = boundary_status(s)
    base[(int(L), int(R))] += 1
tot = sum(base.values())
print('base rates:', {k: f'{v/tot*100:.1f}%' for k, v in sorted(base.items())})

# T2: relationship of n0 to r's column end. Walk from r along +1 until break, and -1.
print('\n=== T2: r-column extent vs n0 ===')
def col_extent(s):
    a = s
    while a - 1 >= 0 and adj[a - 1] == 1: a -= 1
    b = s
    while b < N - 1 and adj[b] == 1: b += 1
    return a, b
hits2 = 0
for gi, rid, n0, r in sites:
    a, b = col_extent(r)
    # if n0 is just past either end of r's column (start of next col in slot space)
    rel = None
    if n0 == b + 1: rel = 'b+1'
    elif n0 == a - 1: rel = 'a-1'
    # or n0 is far end of the NEXT column
    na, nb = col_extent(b + 1) if b + 1 < N else (None, None)
    pa, pb = col_extent(a - 1) if a - 1 >= 0 else (None, None)
    if n0 == nb: rel = rel or 'next_far'
    if pa is not None and n0 == pa: rel = rel or 'prev_far'
    if rel: hits2 += 1
    print(f'gi={gi:5d} r={r:5d} col=[{a},{b}] (len {b-a+1}) n0={n0:5d} rel={rel}')
print(f'T2 hits: {hits2}/{len(sites)}')

# T3: d vs rail direction
print('\n=== T3: d vs ref-rail direction ===')
st = np.load('strip_table.npy')
# find rail direction: rails[rid]['vals'] near gi
rail_by_id = {rr['id']: rr for rr in rails}
ok3 = bad3 = 0
for row in st:
    gi0, gi1, rid, n0, d, ln, rf = row
    if d == 0: continue
    rr = rail_by_id.get(int(rid))
    if rr is None: continue
    vals = rr['vals']  # list of (gi, r)
    rs = [r for g, r in vals]
    if len(rs) < 2: continue
    rdir = np.sign(rs[-1] - rs[0])
    verdict = 'OK' if d == -rdir else 'BAD'
    if verdict == 'OK': ok3 += 1
    else: bad3 += 1
    print(f'rid={int(rid):4d} d={int(d):+d} rail_dir={int(rdir):+d} rs[:6]={rs[:6]} {verdict}')
print(f'T3: d==-raildir {ok3} / {ok3+bad3}')
