import struct, os

def isSep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

def readBE64(result):
    return struct.unpack('>d', bytes(result[:8]))[0]

def parse_coords(cr):
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

def get_file_data(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    hdrIdx = data.find(bytes([0x43, 0xE0, 0x0E, 0x2F]))
    if hdrIdx < 0: return None, 0, 0
    ds = hdrIdx - 5
    cs = ds + 23
    nv = data[ds+12]
    nf = data[ds+19]
    fm = -1
    for i in range(ds + 30, len(data) - 1):
        if data[i] == 0x20 and data[i+1] == 0x00:
            fm = i
            break
    ce = fm if fm > 0 else len(data)
    return data[cs:ce], nv, nf

def axis_machine(groups):
    axis = 0
    direction = 1
    axisMap = []
    for i in range(len(groups)):
        ft = None
        for t in groups[i]['tags']:
            if t['cls'] != 'C0':
                ft = t
                break
        if i < 3:
            ax = i
        elif ft is None:
            ax = (axis + direction) % 3
        elif ft['cls'] == 'E0':
            ax = axis
        elif ft['lo'] == 0xF and ft['hi'] == 0:
            direction = -1
            ax = (axis - 1) % 3
        elif ft['lo'] == 0xF and ft['hi'] > 0:
            ax = axis
        else:
            ax = (axis + direction) % 3
        axisMap.append(ax)
        axis = ax
    return axisMap

def build_vertices(groups, axisMap, coordGroupEnd):
    baseValues = [None, None, None]
    zValues = []
    for i in range(coordGroupEnd):
        ax = axisMap[i]
        if 0 <= ax <= 2:
            if baseValues[ax] is None: baseValues[ax] = groups[i]['value']
            if ax == 2 and groups[i]['value'] not in zValues: zValues.append(groups[i]['value'])

    running = [0, 0, 0]
    c0Slots = {}
    primaries = []

    for i in range(coordGroupEnd):
        g = groups[i]
        ax = axisMap[i]
        if ax < 0 or ax > 2: continue
        running[ax] = g['value']

        if i == 2:
            primaries.append([running[0], running[1], running[2]])
        elif i > 2:
            ft = None
            for t in g['tags']:
                if t['cls'] != 'C0':
                    ft = t
                    break

            if len(zValues) >= 2 and ft and ft['lo'] == 0xF:
                primaries.append([running[0], running[1], zValues[0]])
                primaries.append([running[0], running[1], zValues[1]])
            elif ft and ft['lo'] == 0xF and ft['hi'] == 0:
                primaries.append([running[0], running[1], running[2]])
                baseV = [running[0], running[1], running[2]]
                prevAx = axisMap[i-1] if i > 0 else ax
                if prevAx != ax and baseValues[prevAx] is not None:
                    baseV[prevAx] = baseValues[prevAx]
                else:
                    baseV[ax] = baseValues[ax] if baseValues[ax] is not None else running[ax]
                primaries.append(baseV)
            else:
                primaries.append([running[0], running[1], running[2]])

        for t in g['tags']:
            if t['cls'] != 'C0': continue
            slot = t['hi']
            if slot not in c0Slots:
                c0Slots[slot] = [baseValues[0] or 0, baseValues[1] or 0, baseValues[2] or 0]
            c0Slots[slot][ax] = g['value']
            if len(zValues) >= 2:
                if t['lo'] == 0x07: c0Slots[slot][2] = zValues[0]
                elif t['lo'] == 0x0F: c0Slots[slot][2] = zValues[1]

    vertices = list(primaries)
    for slot in sorted(c0Slots.keys()):
        vertices.append(c0Slots[slot])
    return vertices

def coord_group_end(groups):
    maxSeen = 0
    for i in range(min(3, len(groups))):
        maxSeen = max(maxSeen, abs(groups[i]['value']))
    cge = len(groups)
    for i in range(3, len(groups)):
        v = groups[i]['value']
        av = abs(v)
        if maxSeen > 10 and av < maxSeen / 100 and av < 10:
            cge = i; break
        if any(t['cls'] == '20' and t['byte2'] == 0x03 for t in groups[i]['tags']):
            cge = i; break
        if v < -0.5 and i > 3 and groups[i-1]['value'] > 0:
            cge = i; break
        if av > 1: maxSeen = max(maxSeen, av)
    return cge

def get_dxf_vertices(dxf_path):
    with open(dxf_path, 'r') as f:
        content = f.read()
    verts = set()
    faces = content.split('3DFACE')
    for face in faces[1:]:
        lines = face.strip().split('\n')
        coords = {}
        for j, line in enumerate(lines):
            code = line.strip()
            if code in ('10','11','12','13','20','21','22','23','30','31','32','33'):
                coords[int(code)] = float(lines[j+1].strip())
        for vi in range(4):
            x = coords.get(10+vi, 0)
            y = coords.get(20+vi, 0)
            z = coords.get(30+vi, 0)
            if abs(x) < 1e10:
                verts.add((round(x,2), round(y,2), round(z,2)))
    return sorted(verts)

base = 'C:/Users/brent/desktop/GIT/vulcan-00t-tri/exampleFiles/'
tests = [
    ('triangle', 'tri-crack-triangle'),
    ('plane', 'tri-crack'),
    ('cube', 'tri-crack-solid'),
    ('prism', 'tri-crack-prism'),
]

for name, prefix in tests:
    oot_path = base + prefix + '.00t'
    dxf_path = base + prefix + '.dxf'
    if not os.path.exists(oot_path): continue
    cr, nv, nf = get_file_data(oot_path)
    if cr is None: continue
    groups = parse_coords(cr)
    axMap = axis_machine(groups)
    cge = coord_group_end(groups)
    verts = build_vertices(groups, axMap, cge)
    dxf_verts = get_dxf_vertices(dxf_path)

    print(f"\n{'='*60}")
    print(f"{name}: header verts={nv} faces={nf}, coords={len(groups)}, cge={cge}")
    vals = [f"{g['value']:.1f}" for g in groups[:cge]]
    print(f"  Coord values: {vals}")
    print(f"  Axes: {axMap[:cge]}")
    print(f"  OOT vertices ({len(verts)}):")
    for i, v in enumerate(verts):
        print(f"    V{i}: ({v[0]:.0f}, {v[1]:.0f}, {v[2]:.0f})")
    print(f"  DXF vertices ({len(dxf_verts)}):")
    for v in dxf_verts:
        print(f"    ({v[0]}, {v[1]}, {v[2]})")
    oot_set = set()
    for v in verts:
        oot_set.add((round(v[0],1), round(v[1],1), round(v[2],1)))
    dxf_set = set(dxf_verts)
    matched = oot_set & dxf_set
    missing = dxf_set - oot_set
    extra = oot_set - dxf_set
    status = "PERFECT!" if not missing else ""
    print(f"  Matched: {len(matched)}/{len(dxf_set)} {status}")
    if missing: print(f"  Missing: {missing}")
    if extra: print(f"  Extra: {extra}")
