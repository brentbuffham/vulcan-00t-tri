"""Test OLD parser logic (before changes) for comparison."""
import struct
import os

def isSep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

def readBE64(result):
    return struct.unpack('>d', bytes(result[:8]))[0]

def parse_coords_old(coordRegion):
    """Old parser: count=0 reads 1 byte, ALL non-count non-sep = 2-byte tag."""
    prev = [0]*8
    pos = 0
    groups = []

    while pos < len(coordRegion):
        b = coordRegion[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(coordRegion):
                break
            stored = list(coordRegion[pos+1:pos+1+nb])
            result = [0]*8
            isFull = stored[0] in (0x40, 0x41, 0xC0, 0xC1)
            if isFull:
                for i in range(nb):
                    result[i] = stored[i]
            else:
                result[0] = prev[0]
                for i in range(nb):
                    result[i+1] = stored[i]
                for i in range(nb+1, 8):
                    result[i] = prev[i]
            val = readBE64(result)
            prev = result[:]
            groups.append({'value': val})
            pos += 1 + nb
        elif isSep(b):
            pos += 1
        elif pos + 1 < len(coordRegion):
            pos += 2
        else:
            break

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
        continue
    region = get_coord_region(path)
    if region is None:
        continue
    groups = parse_coords_old(region)
    values = [g['value'] for g in groups]
    print(f"{name} OLD ({len(values)} coords): {[f'{v:.1f}' for v in values]}")
