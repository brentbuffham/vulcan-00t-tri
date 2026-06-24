#!/usr/bin/env python3
"""Clean streaming decoder for production .00t — core TAG.17.count grammar
only, no toy escape special-cases. Prints the first N decoded coords so we
can see the axis structure."""
import sys, struct

path = sys.argv[1]
PRINTN = int(sys.argv[2]) if len(sys.argv) > 2 else 60
d = open(path, 'rb').read()
hdr = struct.unpack('<15i', d[0:60])
geo_end = hdr[11]

TAG_CLASSES = (0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0)
FULL_IND = (0x40, 0x41, 0xC0, 0xC1)

def be(bs):
    return struct.unpack('>d', bytes((list(bs) + [0]*8)[:8]))[0]

def is_sep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

# vertex 0 = three full BE doubles at 8328
V0 = 8328
x0, y0, z0 = be(d[V0:V0+8]), be(d[V0+8:V0+16]), be(d[V0+16:V0+24])
print(f'vertex 0 (3 full BE doubles): X={x0:.4f} Y={y0:.4f} Z={z0:.4f}')

# running prev (8 bytes). Seed with vertex-0 X bytes.
prev = list(d[V0:V0+8])
pos = V0 + 24
end = geo_end
emitted = 0
last_tag = None

print(f"{'off':>8} {'tag':>4} {'nb':>3} {'kind':>5}  value           stored-bytes")
while pos < end and emitted < PRINTN:
    b = d[pos]
    if b <= 0x06:
        nb = b + 1
        stored = list(d[pos+1:pos+1+nb])
        if stored and stored[0] in FULL_IND:
            r = stored + [0]*(8-nb)
            kind = 'FULL'
            prev = (r + [0]*8)[:8]
            val = be(r)
        else:
            # DELTA: byte0 + stored + trailing-from-prev (old-format rule)
            r = [prev[0]] + stored + list(prev[nb+1:8])
            r = (r + [0]*8)[:8]
            kind = 'DELTA'
            prev = r
            val = be(r)
        print(f'{pos:8d} {str(last_tag):>4} {nb:3d} {kind:>5}  {val:15.4f}  '
              + ' '.join(f'{x:02x}' for x in stored))
        emitted += 1
        pos += 1 + nb
    elif is_sep(b):
        pos += 1
    elif (b & 0xE0) in TAG_CLASSES:
        last_tag = f'{b:02x}'
        pos += 1
    else:
        pos += 1
