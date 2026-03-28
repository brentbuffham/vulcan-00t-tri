#!/usr/bin/env python3
"""
Crack how the coordinate section tags build the vertex table.

Focus: the LINEAR STRIP has 4 unique coord values (1000, 1100, 1200, 1300)
that must produce 7 vertices. The tags between coords encode the assignment.

DXF vertices (ground truth):
  V0: (1000, 1000, 1000)
  V1: (1100, 1100, 1000)
  V2: (1100, 1000, 1000)
  V3: (1200, 1100, 1000)
  V4: (1200, 1000, 1000)
  V5: (1300, 1100, 1000)
  V6: (1300, 1000, 1000)

Unique axis values: X in {1000,1100,1200,1300}, Y in {1000,1100}, Z = {1000}
Total unique values: 4 (since 1000 and 1100 serve both X and Y)
"""

import struct
import ezdxf


def is_separator(b):
    return (b & 0x07) == 0x07 and b >= 0x07


# ══════════════════════════════════════════════════════════════
# LINEAR STRIP — detailed coord section trace
# ══════════════════════════════════════════════════════════════

print("=" * 78)
print("  LINEAR STRIP: Coord section vertex construction")
print("=" * 78)

# DXF ground truth
doc = ezdxf.readfile("exampleFiles/tri-crack-linear.dxf")
msp = doc.modelspace()
vm, vl, fl = {}, [], []
for e in msp:
    if e.dxftype() == "3DFACE":
        tri = []
        for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2]:
            key = (round(p[0], 2), round(p[1], 2), round(p[2], 2))
            if key not in vm:
                vm[key] = len(vl)
                vl.append(key)
            tri.append(vm[key])
        fl.append(tuple(tri))

print("\nDXF vertices:")
for i, v in enumerate(vl):
    print(f"  V{i}: X={v[0]:.0f} Y={v[1]:.0f} Z={v[2]:.0f}")

# Which values are used for each axis?
xs = sorted(set(v[0] for v in vl))
ys = sorted(set(v[1] for v in vl))
zs = sorted(set(v[2] for v in vl))
print(f"\nUnique X values: {xs}")
print(f"Unique Y values: {ys}")
print(f"Unique Z values: {zs}")

# Coord section raw elements (from previous analysis)
print("""
COORD SECTION (annotated):
  [  0] COORD #0: 1000.0  (FULL, 3B: 02 40 8F 40)
  [  4] TAG 60:16  (cls=60, lo=6, hi=1)
  [  6] TAG E0:08  (cls=E0, lo=8, hi=0)
  [  8] SEP 0x07
  [  9] COORD #1: 1100.0  (DELTA, 2B: 01 91 30)
  [ 12] TAG 80:17  (cls=80, lo=7, hi=1)
  [ 14] TAG C0:07  (cls=C0, lo=7, hi=0)
  [ 16] TAG C0:27  (cls=C0, lo=7, hi=2)
  [ 18] TAG E0:07  (cls=E0, lo=7, hi=0)
  [ 20] SEP 0x0F
  [ 21] TAG C0:17  (cls=C0, lo=7, hi=1)
  [ 23] COORD #2: 1200.0  (DELTA, 2B: 01 92 C0)
  [ 26] TAG E0:0D  (cls=E0, lo=D, hi=0)
  [ 28] SEP 0x2F
  [ 29] TAG C0:17  (cls=C0, lo=7, hi=1)
  [ 31] TAG C0:27  (cls=C0, lo=7, hi=2)
  [ 33] TAG C0:07  (cls=C0, lo=7, hi=0)
  [ 35] COORD #3: 1300.0  (DELTA, 2B: 01 94 50)
  [ 38] TAG E0:0D  (cls=E0, lo=D, hi=0)
  [ 40] SEP 0x2F
  [ 41] TAG C0:17  (cls=C0, lo=7, hi=1)
  [ 43] TAG C0:27  (cls=C0, lo=7, hi=2)
  [ 45] TAG A0:07  (cls=A0, lo=7, hi=0)
""")

# ══════════════════════════════════════════════════════════════
# Hypothesis: C0 tags assign current coord value to vertices
# C0:X7 where X = vertex index -> "vertex X gets this value for current axis"
# ══════════════════════════════════════════════════════════════

print("=" * 78)
print("  HYPOTHESIS: C0:X7 means 'vertex X gets this coord value'")
print("=" * 78)

# After coord 1000.0: no C0 tags, just 60:16 and E0:08
# After coord 1100.0: C0:07(v0), C0:27(v2), C0:17(v1)
# After coord 1200.0: C0:17(v1), C0:27(v2), C0:07(v0)
# After coord 1300.0: C0:17(v1), C0:27(v2)

# Build vertex table:
# First 3 coords = initial vertex V0: X=1000, Y=1000, Z=1000
# Wait, the first coord is 1000.0. What axis?

# The initial 3 coords should be V0's X, Y, Z.
# But V0=(1000, 1000, 1000) — all same value!
# And there's only ONE 1000.0 coord stored.

# Maybe the first coord value isn't just for V0.
# The tags AFTER coord 1000.0 are: 60:16 and E0:08.
# These might tell us: "1000.0 is used for X AND Y AND Z of V0"

# After 1000.0:
#   60:16 — could mean "duplicate this value" or "this is X,Y,Z"
#   E0:08 — end of initial vertex setup
#   SEP 07 — boundary marker

# After 1100.0:
#   80:17 — "set axis" for the main vertex
#   C0:07 (hi=0) — vertex 0 also uses 1100? Or axis 0 (X)?
#   C0:27 (hi=2) — vertex 2 or axis 2 (Z)?
#   E0:07 — end marker
#   SEP 0F
#   C0:17 (hi=1) — vertex 1 or axis 1 (Y)?

# Let's try AXIS interpretation: hi = axis index (0=X, 1=Y, 2=Z)
# After 1100.0: C0:07->X, C0:27->Z, C0:17->Y
# That would mean: set X=1100, Z=1100, Y=1100 for... which vertex?

# DXF V1 = (1100, 1100, 1000) — X=1100, Y=1100 but Z=1000
# DXF V2 = (1100, 1000, 1000) — X=1100 but Y=1000, Z=1000

# If C0:07 means X=1100, C0:27 means Z=1100, that contradicts DXF
# (no vertex has Z=1100)

# OK, axis interpretation doesn't work directly.
# Let's try VERTEX interpretation: hi = vertex index
# After 1100.0: C0:07->V0, C0:27->V2, C0:17->V1
# Meaning: V0 gets 1100, V2 gets 1100, V1 gets 1100 for some axis

# DXF: which vertices use 1100?
# V1: X=1100, Y=1100 -> uses 1100 twice
# V2: X=1100 -> uses 1100 once
# V3: X=1200, Y=1100 -> uses 1100 once (Y only)
# V5: X=1300, Y=1100 -> uses 1100 once (Y only)

# If C0 assigns to OOT vertices (not DXF vertices), and there are 7 vertices:
# C0:07 -> OOT V0, C0:17 -> OOT V1, C0:27 -> OOT V2

# We don't know OOT vertex ordering. But we know:
# - First coord (1000) = likely X of first vertex
# - OOT V0 = first vertex in coord stream

print("""
Let's trace vertex construction step by step:

The initial vertex is built from the first 3 axis values.
But the linear strip only has 4 unique values total, so the
initial vertex can't use 3 different values.

Key insight: Z=1000 for ALL vertices! And Y alternates 1000/1100.
So the coord stream stores the UNIQUE axis values and the tags
tell us which vertices get which values for which axes.

Let me trace assuming the tag PATTERN tells us the vertex construction:
""")

# Let me approach this differently: what if the FIRST tag after each coord
# tells us the AXIS (X=0, Y=1, Z=2) and the C0 tags tell us which OTHER
# vertices also get this value?

# Pattern after each coord:
# Coord 0 (1000.0): 60:16, E0:08, SEP07
# Coord 1 (1100.0): 80:17, C0:07, C0:27, E0:07, SEP0F, C0:17
# Coord 2 (1200.0): E0:0D, SEP2F, C0:17, C0:27, C0:07
# Coord 3 (1300.0): E0:0D, SEP2F, C0:17, C0:27, A0:07

# The 80/60/A0 class tags that appear first might encode axis info.
# 80:15 (after coord 0 in triangle/plane/cube) -> always first
# 60:08 -> always second
# 80:07 -> always third

# After the initial 3 coords, the pattern changes to:
# 80:17 or E0:0D or 80:0F

# For the CUBE, initial coords:
# Coord 0 (100.0): 80:15
# Coord 1 (500.0): 60:08
# Coord 2 (900.0): 80:07

# For PLANE:
# Coord 0 (100.0): 80:15
# Coord 1 (500.0): 60:08
# Coord 2 (900.0): 80:07

# ALWAYS 80:15, 60:08, 80:07 for first 3 coords!
# This must encode X, Y, Z axis assignments.

print("UNIVERSAL PATTERN: first 3 coords always tagged:")
print("  Coord 0: 80:15 -> X axis")
print("  Coord 1: 60:08 -> Y axis")
print("  Coord 2: 80:07 -> Z axis")
print()

# Now for the C0 tags. Let's track the lo_nib:
# ALL C0 tags in the linear strip have lo_nib = 7 (0x07, 0x17, 0x27)
# The lo_nib=7 matches the 80:07 Z-axis tag!
#
# But wait: C0:07 has lo=7, C0:17 has lo=7, C0:27 has lo=7.
# ALL the C0 tags have lo=7. So lo doesn't vary — it's fixed at 7.
# Only the hi_nib varies: 0, 1, 2.

# Let me check ALL coord-section C0 tags across files:
print("ALL C0 tags in coord sections:")

files = {
    "TRIANGLE": "exampleFiles/tri-crack-triangle.00t",
    "PLANE": "exampleFiles/tri-crack.00t",
    "LINEAR": "exampleFiles/tri-crack-linear.00t",
    "CUBE": "exampleFiles/tri-crack-solid.00t",
}

for name, path in files.items():
    with open(path, 'rb') as f:
        raw = f.read()

    vi = raw.find(b'Variant\x00')
    ds = vi + 8

    attr_suffix = bytes([0x00, 0x05, 0x40, 0x04, 0x00, 0x0A, 0x20, 0x08, 0x07])
    attr_pos = raw.find(attr_suffix, ds)
    if attr_pos < 0: attr_pos = len(raw)

    face_marker = -1
    for i in range(attr_pos - 2, ds + 30, -1):
        if raw[i] == 0x20 and raw[i+1] == 0x00:
            face_marker = i
            break

    coord_region = raw[ds+23:face_marker] if face_marker > 0 else raw[ds+23:attr_pos]

    c0_tags = []
    pos = 0
    coord_idx = -1
    last_coord_val = None
    while pos < len(coord_region):
        b = coord_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(coord_region): break
            stored = list(coord_region[pos+1:pos+1+nb])
            prev_bytes = [0]*8
            if stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r = stored + [0]*(8-nb)
            else:
                r = [0x40] + stored + [0]*(7-nb)  # simplified
            r = (r + [0]*8)[:8]
            val = struct.unpack('>d', bytes(r))[0]
            coord_idx += 1
            last_coord_val = val
            pos += 1 + nb
        elif is_separator(b):
            pos += 1
        elif pos + 1 < len(coord_region):
            b2 = coord_region[pos+1]
            hi_cls = b & 0xE0
            if hi_cls == 0xC0:
                lo = b2 & 0x0F
                hi = (b2 >> 4) & 0x0F
                c0_tags.append({
                    'after_coord': coord_idx,
                    'byte1': b,
                    'byte2': b2,
                    'lo': lo,
                    'hi': hi,
                    'tag': f'C0:{b2:02X}',
                })
            pos += 2
        else:
            break

    print(f"\n  {name}:")
    if not c0_tags:
        print(f"    (no C0 tags in coord section)")
    for t in c0_tags:
        print(f"    after coord #{t['after_coord']}: {t['tag']}  lo={t['lo']:X} hi={t['hi']}")

    # Count unique hi values
    if c0_tags:
        his = [t['hi'] for t in c0_tags]
        print(f"    hi_nib values: {his}")
        print(f"    unique: {sorted(set(his))}")

# ══════════════════════════════════════════════════════════════
# Let me try building vertices for the LINEAR STRIP
# ══════════════════════════════════════════════════════════════

print(f"\n{'='*78}")
print("  LINEAR STRIP: Vertex construction trace")
print(f"{'='*78}")

print("""
Hypothesis:
- The coord section builds a vertex table incrementally.
- Vertices start as copies of the previous vertex.
- Each coord value updates ONE axis of the CURRENT vertex.
- C0 tags create ADDITIONAL vertices that share the same value.
- The hi_nib in C0 tags might be a vertex index or a "copy from" reference.

Let's try: after a coord value is set for the current vertex,
C0:X7 means "also set this axis to this value for vertex X".

Initial vertex V0: built from first 3 coords.
""")

# Trace:
vertices = {}
current_axis = 0  # 0=X, 1=Y, 2=Z
current_vertex = 0
coord_values = [1000.0, 1100.0, 1200.0, 1300.0]

# Initialize V0 with first coord
vertices[0] = [None, None, None]

print("Step-by-step trace:")
print()

# Coord 0: 1000.0, followed by 80:15 (axis tag), then 60:08
# First coord -> X of V0
vertices[0][0] = 1000.0
print(f"  Coord 1000.0 -> V0.X = 1000.0  (tag 80:15 = X axis)")

# But wait — V0 = (1000, 1000, 1000) in DXF. ALL axes = 1000.
# The tags 60:16 and E0:08 after coord 0 might mean "copy to Y and Z"

# After 1000.0: tags are 60:16, E0:08, SEP 07
# Maybe: 80:15 = "X axis done"
#         60:16 = "Y axis = same value"?
#         E0:08 = "Z axis = same value"?
# Or the tags encode something about the vertex structure.

# For simplicity, let me try: first coord = X, and if Y,Z aren't set
# by subsequent coords, they inherit from X.

# After coord 0 (1000.0), before coord 1:
# Tags: 80:15, 60:16, E0:08, SEP07
# These might set up V0 completely as (1000, 1000, 1000)

vertices[0] = [1000.0, 1000.0, 1000.0]
print(f"  Tags 60:16, E0:08 -> V0.Y=1000.0, V0.Z=1000.0")
print(f"  V0 = {vertices[0]}")
print()

# Coord 1: 1100.0, followed by 80:17, C0:07, C0:27, E0:07, SEP, C0:17
# 80:17 might mean "this is a Y-axis value" or "this goes to current vertex"
# Then C0:07(hi=0), C0:27(hi=2), C0:17(hi=1)

# Which DXF vertices use 1100?
# V1(1100,1100,1000): X=1100, Y=1100
# V2(1100,1000,1000): X=1100
# V3(1200,1100,1000): Y=1100
# V5(1300,1100,1000): Y=1100

# 1100 is used as X for V1,V2 and as Y for V1,V3,V5
# Three C0 tags after 1100.0: C0:07, C0:27, C0:17
# If each creates a vertex or assigns to a vertex...

# Maybe the SEQUENCE of vertices in OOT order is:
# V0 = (1000,1000,1000) — all 1000
# Then each coord delta creates new vertices by changing one axis:
# 1100 replaces... which axis of which vertex?

# Let me try a different approach: delta-based vertex creation
# Each new coord value represents a change from the previous vertex.
# The C0 tags tell us how many vertices share this change.

# V0 = (1000, 1000, 1000)
# Delta to 1100: one axis changes from 1000 to 1100
# Tags: C0:07, C0:27, C0:17 = create 3 vertex slots with this value

# If we number slots: slot 0, 2, 1 (from hi_nibs)
# Maybe these are slot indices within a "batch" of vertices being created?

# Actually, let me count: we have 7 vertices total.
# V0 created from initial.
# After 1100.0: 3 C0 tags -> could create/modify 3 vertices
# After 1200.0: 3 C0 tags -> modify/create 3 more
# After 1300.0: 2 C0 tags -> modify/create 2 more
# Total: 1 + 3 + 3 + 2 = 9? Too many for 7 vertices.
# Unless some C0 tags update EXISTING vertices rather than creating new ones.

# Hmm, let me just try ALL possible interpretations of the hi_nib
# as "vertex index" and see which one produces the correct DXF vertices.

print("=" * 78)
print("  BRUTE FORCE: Try all axis/vertex interpretations")
print("=" * 78)
print()

# We know 4 coord values: 1000, 1100, 1200, 1300
# We need 7 vertices, each with X, Y, Z
# DXF ground truth vertices (we don't know OOT ordering):

dxf_verts = [
    (1000, 1000, 1000),
    (1100, 1100, 1000),
    (1100, 1000, 1000),
    (1200, 1100, 1000),
    (1200, 1000, 1000),
    (1300, 1100, 1000),
    (1300, 1000, 1000),
]

# Tags between coords (excluding the initial 80/60/E0 tags):
# After 1100.0: 80:17, C0:07(hi=0), C0:27(hi=2), E0:07, C0:17(hi=1)
# After 1200.0: E0:0D, C0:17(hi=1), C0:27(hi=2), C0:07(hi=0)
# After 1300.0: E0:0D, C0:17(hi=1), C0:27(hi=2), A0:07

# C0 tag hi_nibs after each coord:
c0_after = {
    1100: [0, 2, 1],  # C0:07, C0:27, C0:17
    1200: [1, 2, 0],  # C0:17, C0:27, C0:07
    1300: [1, 2],      # C0:17, C0:27
}

print("C0 tag hi_nibs after each coord value:")
for val, nibs in c0_after.items():
    print(f"  {val}: {nibs}")

# Notice pattern: after 1100 and 1200, we get {0, 1, 2} in different orders
# After 1300 we get {1, 2} (missing 0)

# What if hi_nib encodes AXIS (0=X, 1=Y, 2=Z)?
# C0:07(hi=0)->X, C0:17(hi=1)->Y, C0:27(hi=2)->Z

# After 1100.0: set X=1100, Z=1100, Y=1100 (for some vertex/vertices)
# After 1200.0: set Y=1200, Z=1200, X=1200
# After 1300.0: set Y=1300, Z=1300

# But Z=1000 for ALL DXF vertices! So setting Z=1100 contradicts DXF.
# UNLESS the C0 tags are building MULTIPLE vertices simultaneously.

# What if each C0 tag creates a NEW vertex by copying the previous
# vertex and overriding one axis?

print("\n--- Hypothesis: C0:X7 = 'create new vertex, override axis X' ---")
print("Each C0 tag forks a new vertex from current state.\n")

# Start: V0 = (1000, 1000, 1000) from initial coord
# Coord 1100.0 arrives. Current axis changes (the delta-compressed value)
# Let's say the primary vertex gets X=1100 -> becomes (1100, 1000, 1000)
# Then C0:07 (axis 0=X) -> fork a vertex with X=1100 -> but that's same?
# Or C0:07 means "the value goes to axis 0 of a new vertex"

# Actually, maybe the primary assignment is tracked by the 80:17 tag,
# and the C0 tags are SECONDARY assignments.

# 80:17 after 1100.0: 80 class, byte2=17, lo=7, hi=1
# What if 80 means "primary set" and hi=1 means axis 1 (Y)?
# So: 1100.0 -> primary: set Y of current vertex to 1100

# Then C0:07(hi=0) -> also set X of some vertex to 1100
# C0:27(hi=2) -> also set Z of some vertex to 1100
# C0:17(hi=1) -> also set Y of some vertex to 1100

# If this creates new vertices by forking:
# Primary: current vertex becomes (..., Y=1100, ...)
# C0 forks: each C0 creates a new vertex with the specified axis = 1100

# Let me try this with the DXF vertices:
# V0 = (1000, 1000, 1000)
# Coord 1100.0 arrives.
# 80:17 (hi=1) -> primary: V0.Y = 1100 -> V0 becomes (1000, 1100, 1000)?
#   Wait, that changes V0. But DXF V0 = (1000, 1000, 1000).

# OK maybe 80:17 sets the axis for a NEW vertex, not V0.
# V1 = copy of V0 = (1000, 1000, 1000), then set axis 1 (Y) = 1100
# V1 = (1000, 1100, 1000) <- this is DXF V... hmm, no DXF vertex matches

# Actually wait: DXF has no vertex (1000, 1100, 1000). Let me check:
# DXF V0=(1000,1000,1000) ✓ exists
# (1000,1100,1000) <- NOT in DXF

# Hmm. Let me try hi=1 means axis X (offset differently):
# 80:15 = axis 0/X (first coord)
# 60:08 = axis 1/Y (second coord)
# 80:07 = axis 2/Z (third coord)

# But those byte2 values (15, 08, 07) don't have a clean axis encoding.
# Unless the TAG CLASS encodes the axis: 80=X, 60=Y, 80=Z? That's ambiguous.

# Let me try yet another approach: look at the NON-C0 tags for axis info.

print("\n--- Non-C0 tag analysis ---")
print("First tag after each coord (all files):\n")

for name, path in files.items():
    with open(path, 'rb') as f:
        raw = f.read()
    vi = raw.find(b'Variant\x00')
    ds = vi + 8
    attr_suffix = bytes([0x00, 0x05, 0x40, 0x04, 0x00, 0x0A, 0x20, 0x08, 0x07])
    attr_pos = raw.find(attr_suffix, ds)
    if attr_pos < 0: attr_pos = len(raw)
    face_marker = -1
    for i in range(attr_pos - 2, ds + 30, -1):
        if raw[i] == 0x20 and raw[i+1] == 0x00:
            face_marker = i; break
    coord_region = raw[ds+23:face_marker] if face_marker > 0 else raw[ds+23:attr_pos]

    prev = [0]*8
    pos = 0
    cidx = 0
    print(f"  {name}:")
    while pos < len(coord_region):
        b = coord_region[pos]
        if b <= 0x06:
            nb = b + 1
            if pos + 1 + nb > len(coord_region): break
            stored = list(coord_region[pos+1:pos+1+nb])
            if stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r = stored + [0]*(8-nb)
            else:
                r = [prev[0]] + stored + list(prev[nb+1:8])
            r = (r + [0]*8)[:8]
            val = struct.unpack('>d', bytes(r))[0]
            prev = r
            # Find first tag after this coord
            p2 = pos + 1 + nb
            first_tag = None
            while p2 < len(coord_region):
                b2 = coord_region[p2]
                if b2 <= 0x06:
                    break  # next coord
                elif is_separator(b2):
                    p2 += 1
                elif p2 + 1 < len(coord_region):
                    bt1 = coord_region[p2]
                    bt2 = coord_region[p2+1]
                    hi_cls = bt1 & 0xE0
                    cls = {0x20:'20', 0x40:'40', 0x60:'60', 0x80:'80',
                           0xA0:'A0', 0xC0:'C0', 0xE0:'E0'}.get(hi_cls, f'{bt1:02X}')
                    first_tag = f"{cls}:{bt2:02X}"
                    break
                else:
                    break

            print(f"    Coord #{cidx}: {val:12.4f} -> first tag: {first_tag}")
            cidx += 1
            pos += 1 + nb
        elif is_separator(b):
            pos += 1
        elif pos + 1 < len(coord_region):
            pos += 2
        else:
            break
    print()
