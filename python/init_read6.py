# init_read6.py — pin the non-e003 delimiter variants as strip push/pop:
#  (1) census all group delims;
#  (2) for each of the 57 INIT gi's: distance back to the nearest non-e003 delim;
#      control = same census at random gi;
#  (3) dump the group context (delim, #refs, first op) around a few INIT sites.
import pickle, re, random
from collections import Counter

groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))
sites = []
for line in open('init_sites.txt'):
    m = re.match(r'gi=\s*(\d+) rid=\s*(\d+) n0=\s*(\d+) r=\s*(\d+)', line)
    if m: sites.append(tuple(map(int, m.groups())))

print('=== delim census over', len(groups), 'groups ===')
c = Counter(g['delim'] for g in groups)
print(c.most_common(20))
print()

def back_to_nondelim(gi):
    for back in range(0, 30):
        if gi - back < 0: return None, None
        dl = groups[gi - back]['delim']
        if dl != 'e003': return back, dl
    return 99, None

print('=== distance from INIT gi back to nearest non-e003 delim ===')
cc = Counter(); dl_at = Counter()
for gi, rid, n0, r in sites:
    b, dl = back_to_nondelim(gi)
    cc[b] += 1; dl_at[dl] += 1
print('back-distance census:', sorted(cc.items()))
print('delim found:', dl_at.most_common())
random.seed(3)
ctl = Counter()
for _ in range(500):
    b, dl = back_to_nondelim(random.randrange(60, len(groups)))
    ctl[b] += 1
print('control back-distance (500 random gi):', sorted(ctl.items())[:12])
print()

print('=== context dump: groups gi-6..gi+2 for first 6 sites ===')
for gi, rid, n0, r in sites[:6]:
    print(f'--- site gi={gi} n0={n0} r={r} ---')
    for gj in range(gi - 6, gi + 3):
        g = groups[gj]
        ops = ' '.join(f'{a:02x}:{b:02x}' for a, b in g['ops'][:5])
        refs = g['refs'][:6]
        mark = ' <== INIT' if gj == gi else ''
        print(f'  g{gj}: {g["delim"]} refs={refs} ops=[{ops}]{mark}')
