import struct

def isSep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

def readBE64(result):
    return struct.unpack('>d', bytes(result[:8]))[0]

with open('C:/Users/brent/desktop/GIT/vulcan-00t-tri/exampleFiles/tri-crack.00t', 'rb') as f:
    data = f.read()

hdrIdx = data.find(bytes([0x43, 0xE0, 0x0E, 0x2F]))
ds = hdrIdx - 5
cs = ds + 23

# Find face marker
fm = -1
for i in range(ds + 30, len(data) - 1):
    if data[i] == 0x20 and data[i+1] == 0x00:
        fm = i
        break

coordRegion = data[cs:fm]
print(f"Plane coord section ({len(coordRegion)} bytes):")
print(' '.join(f'{b:02x}' for b in coordRegion))

print(f"\nHeader: verts={data[ds+12]}, faces={data[ds+19]}")

# Parse with OLD rules (all non-count non-sep = 2-byte tag)
def parse_old(cr):
    prev = [0]*8
    pos = 0
    groups = []
    while pos < len(cr):
        b = cr[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(cr): break
            stored = list(cr[pos+1:pos+1+nb])
            result = [0]*8
            isFull = stored[0] in (0x40, 0x41, 0xC0, 0xC1)
            if isFull:
                for i in range(nb): result[i] = stored[i]
            else:
                result[0] = prev[0]
                for i in range(nb): result[i+1] = stored[i]
                for i in range(nb+1, 8): result[i] = prev[i]
            val = readBE64(result)
            prev = result[:]
            tags = []
            groups.append({'value': val, 'tags': tags, 'seps': []})
            pos += 1 + nb
        elif isSep(b):
            if groups: groups[-1]['seps'].append(b)
            pos += 1
        elif pos + 1 < len(cr):
            b2 = cr[pos+1]
            cls_map = {0x20:'20',0x40:'40',0x60:'60',0x80:'80',0xA0:'A0',0xC0:'C0',0xE0:'E0'}
            cls = cls_map.get(b & 0xE0, '??')
            if groups: groups[-1]['tags'].append({'cls':cls, 'byte2':b2, 'lo':b2&0xF, 'hi':(b2>>4)&0xF})
            pos += 2
        else:
            break
    return groups

# Parse with NEW rules (tags >= 0x60 only)
def parse_new(cr):
    prev = [0]*8
    pos = 0
    hadFull = False
    groups = []
    while pos < len(cr):
        b = cr[pos]
        if b <= 0x06:
            if b == 0 and not hadFull:
                groups.append({'value': 0.0, 'tags': [], 'seps': []})
                pos += 1
                continue
            nb = b + 1
            if pos + 1 + nb > len(cr): break
            stored = list(cr[pos+1:pos+1+nb])
            result = [0]*8
            isFull = stored[0] in (0x40, 0x41, 0xC0, 0xC1)
            if isFull:
                for i in range(nb): result[i] = stored[i]
                hadFull = True
            else:
                result[0] = prev[0]
                for i in range(nb): result[i+1] = stored[i]
                for i in range(nb+1, 8): result[i] = prev[i]
            val = readBE64(result)
            prev = result[:]
            groups.append({'value': val, 'tags': [], 'seps': []})
            pos += 1 + nb
        elif isSep(b):
            if groups: groups[-1]['seps'].append(b)
            pos += 1
        elif b >= 0x60 and pos + 1 < len(cr):
            b2 = cr[pos+1]
            cls_map = {0x60:'60',0x80:'80',0xA0:'A0',0xC0:'C0',0xE0:'E0'}
            cls = cls_map.get(b & 0xE0, '??')
            if groups: groups[-1]['tags'].append({'cls':cls, 'byte2':b2, 'lo':b2&0xF, 'hi':(b2>>4)&0xF})
            pos += 2
        else:
            pos += 1
    return groups

old_groups = parse_old(coordRegion)
new_groups = parse_new(coordRegion)

print("\nOLD parser:")
for i, g in enumerate(old_groups):
    tags_str = ', '.join(f"{t['cls']}:{t['byte2']:02x}" for t in g['tags'])
    seps_str = ', '.join(f"{s:02x}" for s in g['seps'])
    print(f"  [{i}] val={g['value']:.1f}  tags=[{tags_str}]  seps=[{seps_str}]")

print("\nNEW parser:")
for i, g in enumerate(new_groups):
    tags_str = ', '.join(f"{t['cls']}:{t['byte2']:02x}" for t in g['tags'])
    seps_str = ', '.join(f"{s:02x}" for s in g['seps'])
    print(f"  [{i}] val={g['value']:.1f}  tags=[{tags_str}]  seps=[{seps_str}]")
