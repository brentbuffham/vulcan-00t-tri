#!/usr/bin/env python3
"""Search for TRUNCATED big-endian double prefixes of known coordinate values.

If coords are stored as count-prefixed truncated doubles, the leading 2-4 bytes
of each value's IEEE-754 BE form should appear in the file, ideally preceded by
a small count byte (0x01..0x06).
"""
import struct, re, sys

stem = sys.argv[1] if len(sys.argv) > 1 else 'tri-crack-solid'
data = open(f'exampleFiles/{stem}.00t', 'rb').read()

# the meaningful cube coordinate values
vals = [100.0, 300.0, 500.0, 600.0, 900.0, 950.0,
        25.0, 50.0, 75.0, 150.0, 200.0, 5000.0, 5500.0, 1000.0]

print(f'== {stem} ==  size={len(data)}\n')
for cv in vals:
    be = struct.pack('>d', cv)
    print(f'{cv:>8}  BE={be.hex()}')
    for plen in (4, 3, 2):
        pref = be[:plen]
        hits = [m.start() for m in re.finditer(re.escape(pref), data)]
        # show count byte preceding each hit
        annotated = []
        for h in hits[:12]:
            pre = data[h-1] if h > 0 else None
            annotated.append(f'{h}(pre=0x{pre:02x})' if pre is not None else str(h))
        if hits:
            print(f'    [{plen}B {pref.hex()}] {len(hits)} hits: {annotated}')
