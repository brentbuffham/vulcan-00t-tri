"""Test that parser changes don't break cube and improve pyramid."""
import struct
import os

def isSep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

def readBE64(result):
    return struct.unpack('>d', bytes(result[:8]))[0]

def parse_coords_new(coordRegion):
    """New parser: zero literal before first FULL, tags >= 0x60 only."""
    prev = [0]*8
    pos = 0
    hadFull = False
    groups = []

    while pos < len(coordRegion):
        b = coordRegion[pos]
        if b <= 0x06:
            if b == 0x00 and not hadFull:
                groups.append({'value': 0.0, 'tags': [], 'seps': []})
                pos += 1
                continue
            nb = b + 1
            if pos + 1 + nb > len(coordRegion):
                break
            stored = list(coordRegion[pos+1:pos+1+nb])
            result = [0]*8
            isFull = stored[0] in (0x40, 0x41, 0xC0, 0xC1)
            if isFull:
                for i in range(nb):
                    result[i] = stored[i]
                hadFull = True
            else:
                result[0] = prev[0]
                for i in range(nb):
                    result[i+1] = stored[i]
                for i in range(nb+1, 8):
                    result[i] = prev[i]
            val = readBE64(result)
            prev = result[:]
            groups.append({'value': val, 'tags': [], 'seps': []})
            pos += 1 + nb
        elif isSep(b):
            if groups:
                groups[-1]['seps'].append(b)
            pos += 1
        elif b >= 0x60 and pos + 1 < len(coordRegion):
            b2 = coordRegion[pos+1]
            cls_map = {0x60:'60',0x80:'80',0xA0:'A0',0xC0:'C0',0xE0:'E0'}
            cls = cls_map.get(b & 0xE0, '??')
            if groups:
                groups[-1]['tags'].append({'cls':cls, 'byte2':b2, 'lo':b2&0xF, 'hi':(b2>>4)&0xF})
            pos += 2
        else:
            pos += 1

    return groups

def get_coord_region(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    hdrPattern = bytes([0x43, 0xE0, 0x0E, 0x2F])
    hdrIdx = data.find(hdrPattern)
    if hdrIdx < 0:
        return None
    ds = hdrIdx - 5
    coordStart = ds + 23

    # Find face marker
    faceMarker = -1
    for i in range(ds + 30, len(data) - 1):
        if data[i] == 0x20 and data[i+1] == 0x00:
            faceMarker = i
            break

    coordEnd = faceMarker if faceMarker > 0 else len(data)
    return data[coordStart:coordEnd]

base = 'C:/Users/brent/desktop/GIT/vulcan-00t-tri/exampleFiles/'

tests = {
    'cube': 'tri-crack-solid.00t',
    'triangle': 'tri-crack-triangle.00t',
    'plane': 'tri-crack.00t',
    'pyramid': 'tri-crack-Stepped-pyramid.00t',
    'prism': 'tri-crack-prism.00t',
    '4prism': 'tri-crack-4sides-prism.00t',
    'linear': 'tri-crack-linear.00t',
    'fan': 'tri-crack-fan.00t',
}

for name, fname in tests.items():
    path = base + fname
    if not os.path.exists(path):
        print(f"{name}: FILE NOT FOUND")
        continue
    region = get_coord_region(path)
    if region is None:
        print(f"{name}: NO HEADER FOUND")
        continue
    groups = parse_coords_new(region)
    values = [g['value'] for g in groups]
    print(f"{name} ({len(values)} coords): {[f'{v:.1f}' for v in values]}")
