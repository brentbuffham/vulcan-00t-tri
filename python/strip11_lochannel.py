"""Lo-channel (`00 pp` pp<0x80) retest against CLEAN rails (rails_v3).

Re-tokenize with ma_refdecode grammar, capturing per-group lo values.
Correlate pp against: rail structure (birth/death), fitS (teacher-forced
mechanism key), r, n=S-r, turn composition. Prior sweeps (ma_refdecode5/6/7)
tested pp as slot-index encodings on DIRTY structure - all <=40%.
"""
import struct, pickle
from collections import Counter, defaultdict

RAW = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(RAW, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
occ = [i for i in range(8326, len(d) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = len(d)
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90:
        face_start = occ[k]
        break

def extract():
    pos = face_start; groups = []; cur = None
    prev_ref = 0
    state = 'body'
    def ng(delim, p):
        return {'delim': delim, 'pos': p, 'refs': [], 'forms': [],
                'fop': None, 'is01': False, 'lo': [], 'ops': []}
    while pos < geo_end:
        b = d[pos]
        if b in (0xE0, 0xE1):
            if cur: groups.append(cur)
            cur = ng(d[pos:pos + 2].hex(), pos); pos += 2
            state = 'delim0'; continue
        if cur is None:
            cur = ng('HEAD', pos); state = 'body'
        if state == 'delim0':
            if b == 0x00: pos += 1
            state = 'firstop'; continue
        if state == 'firstop':
            if b >= 0x20:
                cur['fop'] = d[pos:pos + 2].hex(); pos += 2
            elif b == 0x01:
                cur['fop'] = d[pos:pos + 3].hex(); cur['is01'] = True; pos += 3
            state = 'body'; continue
        if b == 0x00:
            p = d[pos + 1] if pos + 1 < geo_end else 0
            if p >= 0x80 and not cur['is01']:
                r = p + 256 * round((prev_ref - p) / 256)
                if r < 0: r += 256
                if 0 <= r <= 2974:
                    cur['refs'].append(r); cur['forms'].append('S')
                    prev_ref = r
            else:
                cur['lo'].append(p)
            pos += 2; state = 'body'; continue
        if b == 0x01:
            v = int.from_bytes(d[pos + 1:pos + 3], 'big')
            if 1 <= v <= 2974 and not cur['is01']:
                cur['refs'].append(v); cur['forms'].append('A')
                prev_ref = v
            pos += 3; state = 'body'; continue
        if 0x02 <= b <= 0x06: pos += 1; state = 'body'; continue
        if 0x08 <= b < 0x20: pos += 1; state = 'body'; continue
        cur['ops'].append(d[pos:pos + 2].hex())
        pos += 2; state = 'body'; continue
    if cur: groups.append(cur)
    return groups

groups = extract()
print('groups', len(groups))
nlo = sum(len(g['lo']) for g in groups)
print('lo events:', nlo, ' groups with lo:', sum(1 for g in groups if g['lo']))

# lo value histogram
lov = Counter(v for g in groups for v in g['lo'])
print('lo value hist top20:', lov.most_common(20))
print('lo zero count:', lov[0])

# which delim/kind carries lo?
bykind = Counter()
for g in groups:
    if not g['lo']:
        continue
    kind = ('is01' if g['is01'] else
            'ref' if g['refs'] else 'idless')
    bykind[(g['delim'], kind, len(g['lo']))] += 1
print('lo carriers (delim,kind,n_lo) top15:', bykind.most_common(15))

# --- correlate with rails_v3 -------------------------------------------------
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# rail birth/death gi sets (rails >=3)
birth_gi = {rails[rid]['vals'][0][0] for rid in range(len(rails))
            if len(rails[rid]['vals']) >= 3}
death_gi = {rails[rid]['vals'][-1][0] for rid in range(len(rails))
            if len(rails[rid]['vals']) >= 3}

# distance from each lo-carrying group to nearest rail birth
import bisect
bs = sorted(birth_gi)
def dist_to_birth(gi):
    i = bisect.bisect_left(bs, gi)
    c = []
    if i < len(bs): c.append(bs[i] - gi)
    if i: c.append(gi - bs[i - 1])
    return min(c) if c else 999

dd = Counter()
for gi, g in enumerate(groups):
    if g['lo'] and not g['is01']:
        dd[min(dist_to_birth(gi), 10)] += 1
base = Counter()
for gi, g in enumerate(groups):
    base[min(dist_to_birth(gi), 10)] += 1
print('lo groups dist-to-rail-birth (vs all-group base):')
for k in sorted(dd):
    print('  d=%d: %d lo vs %d all (%.2fx)' % (
        k, dd[k], base[k], (dd[k] / nlo) / max(base[k] / len(groups), 1e-9)))

# nonzero lo values vs local ref value (mod 128) at nearest rail
nz = [(gi, v) for gi, g in enumerate(groups) if not g['is01']
      for v in g['lo'] if v > 0]
print('nonzero lo events:', len(nz))
match = Counter()
lastref = {}
cur = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur = g2[gi]
    if g['lo'] and cur is not None and not g['is01']:
        rid, r = cur
        for v in g['lo']:
            if v == 0:
                continue
            if v == r % 128: match['r%128'] += 1
            if v == r % 100: match['r%100'] += 1
            if v == (r // 128) % 128: match['r//128'] += 1
            d0 = rails[rid]['vals'][0][1]
            if v == abs(r - d0): match['|r-railstart|'] += 1
            match['tot'] += 1
print('nonzero-lo identity tests vs current rail:', dict(match))
pickle.dump(groups, open('refs_v3.pkl', 'wb'))
print('saved refs_v3.pkl (with lo + ops)')
