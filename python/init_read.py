# init_read.py — Fable session 2026-07-09/05: read n0/d from the 57 INIT sites.
# Step 1 (RESUME-07-09 NEXT STEP): test whether n0 is DERIVED, not stored.
#   (a) d = -sign(ref-rail direction)?
#   (b) S constant per rail (multiple strips on same rail share S)?
#   (c) n0 recurrence / block tiling: n0 = end of previous strip's block +-1?
# Step 2: correlate first/second-op bytes + pre-delim bytes against (r, S, d, n0).
import numpy as np, re, collections

st = np.load('strip_table.npy')
print('strip_table:', st.shape, st.dtype)
print(st[:8])
print()

# parse init_sites.txt
sites = []
txt = open('init_sites.txt').read().splitlines()
i = 0
while i < len(txt):
    m = re.match(r'gi=\s*(\d+) rid=\s*(\d+) n0=\s*(\d+) r=\s*(\d+) S\?=\s*(\d+) delim=(\w+) refs=\[\] ops=\[(.*)\]', txt[i])
    if m:
        gi, rid, n0, r, S = map(int, m.groups()[:5])
        ops = re.findall(r"\('0x([0-9a-f]+)', '0x([0-9a-f]+)'\)", m.group(7))
        ops = [(int(a,16), int(b,16)) for a,b in ops]
        mb = re.search(r'bytes\[-6:\+18\]=([0-9a-f]+)', txt[i+1])
        b = bytes.fromhex(mb.group(1))
        sites.append(dict(gi=gi, rid=rid, n0=n0, r=r, S=S, ops=ops, b=b))
        i += 2
    else:
        i += 1
print('parsed sites:', len(sites))
print()

# --- Test: pre-delim 2-byte value == r (big-endian) ---
print('=== pre-delim bytes[-6:-4] BE vs r ===')
hit = miss = 0
for s in sites:
    v = (s['b'][0] << 8) | s['b'][1]
    ok = (v == s['r'])
    if ok: hit += 1
    else:
        miss += 1
        print(f"  MISS gi={s['gi']:5d} val={v:5d} (0x{v:04x}) r={s['r']:5d} (0x{s['r']:04x}) n0={s['n0']} S={s['S']} bytes={s['b'][:8].hex()}")
print(f'pre-delim==r: {hit}/{hit+miss}')
print()

# --- strip_table tests ---
# assume cols: gi_start, gi_end, rail_id, n0, d, len, resolved_frac
gi0, gi1, rid, n0c, dc, ln, rf = (st[:,k] for k in range(7))
print('=== d census ===', collections.Counter(dc.tolist()))
print()

# (b) S per rail: same rid -> same S?  and same n0 across different rids?
by_rid = collections.defaultdict(list)
for s in sites: by_rid[s['rid']].append(s)
multi = {k:v for k,v in by_rid.items() if len(v)>1}
print('rids with >1 strip:', {k:[(x['n0'],x['r'],x['S']) for x in v] for k,v in multi.items()})
n0_counts = collections.Counter(s['n0'] for s in sites)
print('recurring n0:', {k:v for k,v in n0_counts.items() if v>1})
print()

# (c) block tiling: block covered = [min,max] of {n0, n0 - d*(len-1)} per strip (from strip_table)
print('=== strips sorted by gi_start: block ranges ===')
order = np.argsort(gi0)
prev_end = None
for k in order:
    a = int(n0c[k]); d = int(dc[k]); L = int(ln[k])
    b_end = a - d*(L-1) if d != 0 else a
    lo, hi = min(a, b_end), max(a, b_end)
    print(f'gi={int(gi0[k]):5d}-{int(gi1[k]):5d} rid={int(rid[k]):4d} n0={a:5d} d={d:+d} len={L:4d} block=[{lo},{hi}] rf={rf[k]:.2f}')
