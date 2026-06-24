#!/usr/bin/env python3
"""Count TAG.17.count delta records across the bounded geometry blob and
compare against ground-truth vertex/coord counts."""
import sys, struct
from collections import Counter

path = sys.argv[1]
d = open(path, 'rb').read()
hdr = struct.unpack('<15i', d[0:60])
geo_end = hdr[11]            # directory pointer = geometry end / attribute start
GEO = 8328                   # vertex-0 data start (from decode probe)
blob = d[GEO:geo_end]
print(f'geometry blob: [{GEO} .. {geo_end}]  = {len(blob):,} bytes')
print(f'header[8]={hdr[8]:,}  header[11]={hdr[11]:,}  header[13]={hdr[13]:,}')

# Count records of the form  <tag> 17 <count> ...   where 0x17 is the SEP.
# Walk: at each pos, if byte[pos+1]==0x17 treat byte[pos]=tag, byte[pos+2]=count,
# advance by 3+payload. Payload length hypothesis: count+1 (from hex: 04->5, 02->3).
tags = Counter()
counts = Counter()
nrec = 0
pos = 0
N = len(blob)
bad = 0
while pos + 3 <= N:
    if blob[pos+1] == 0x17 and (blob[pos] & 0x0f) == 0x00:  # tag low nibble 0
        tag = blob[pos]
        cnt = blob[pos+2]
        tags[tag] += 1
        counts[cnt] += 1
        nrec += 1
        payload = cnt + 1 if cnt <= 0x10 else 8
        pos += 3 + payload
    else:
        pos += 1
        bad += 1

print(f'\nrecords found (tag.17.count): {nrec:,}')
print(f'unaligned bytes skipped      : {bad:,}')
print(f'GT unique verts={1_212_592:,}  ->  x3 coords = {3*1_212_592:,}')
print(f'candidate stored-vert count @8296 = 1,450,044  -> x3 = {3*1_450_044:,}')
print('\ntop tags  :', tags.most_common(8))
print('top counts:', counts.most_common(10))
