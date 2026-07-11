"""Dump raw bytes of idless e003 groups (the lo carriers) so we can see the
FULL record structure, not just the extracted lo. Goal: locate the low byte
of the alloc slot if lo is the high byte.
"""
import struct, pickle

RAW = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(RAW, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]

groups = pickle.load(open('refs_v3.pkl', 'rb'))

# find idless e003 groups with a single lo in 1..8; print raw bytes from
# this group's pos to next group's pos
posns = [g['pos'] for g in groups]
shown = 0
for i, g in enumerate(groups):
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if not (1 <= v <= 8):
        continue
    p0 = g['pos']
    p1 = posns[i + 1] if i + 1 < len(posns) else geo_end
    raw = d[p0:p1]
    # also show preceding ref group
    pp0 = posns[i - 1] if i > 0 else p0
    prevraw = d[pp0:p0]
    print('g%-5d lo=%d  fop=%s ops=%s' % (i, v, g['fop'], g['ops']))
    print('   prev[%s]: %s' % (groups[i-1].get('delim'), prevraw.hex(' ')))
    print('   this    : %s' % raw.hex(' '))
    shown += 1
    if shown >= 25:
        break
