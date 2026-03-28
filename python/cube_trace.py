#!/usr/bin/env python3
"""
Deep trace of cube (tri-crack-solid) face topology.
8 vertices, 12 faces, includes C0 (split) operations.
"""

import ezdxf
from itertools import permutations, product
from collections import Counter

# ── DXF Ground Truth ──
doc = ezdxf.readfile("exampleFiles/tri-crack-solid.dxf")
msp = doc.modelspace()
vm, vl, fl = {}, [], []
for e in msp:
    if e.dxftype() == "3DFACE":
        tri = []
        for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2]:
            key = (round(p[0], 4), round(p[1], 4), round(p[2], 4))
            if key not in vm:
                vm[key] = len(vl)
                vl.append(key)
            tri.append(vm[key])
        fl.append(tuple(tri))

print("=== DXF GROUND TRUTH (Cube) ===")
for i, v in enumerate(vl):
    print(f"  V{i}: ({v[0]:.1f}, {v[1]:.1f}, {v[2]:.1f})")
for i, f in enumerate(fl):
    print(f"  F{i}: {f}")

dxf_sets = {frozenset(f) for f in fl}
vf = Counter()
for f in fl:
    for v in f:
        vf[v] += 1
print(f"\nVertex freq: {dict(sorted(vf.items()))}")
print(f"Adjacency profile: {sorted(vf.values())}")

# ── Cube face section (from earlier hex dump) ──
face_raw = bytes([
    0x20, 0x00, 0x40, 0x17, 0x00, 0x03, 0x20, 0x07, 0xE0, 0x0B,
    0x2F, 0x40, 0x17, 0xE0, 0x07, 0x2F, 0xC0, 0x5B, 0x00, 0x06,
    0x20, 0x33, 0xE0, 0x03, 0x00, 0x40, 0x17, 0x40, 0x2B, 0xE0,
    0x07, 0x17, 0x40, 0x43, 0x40, 0x5B, 0xE1, 0x07, 0x87, 0x40,
    0x17, 0x00, 0x07, 0x20, 0x40, 0x40, 0x33, 0xE0, 0x03, 0x00,
    0xC0, 0x17, 0xE0, 0x07, 0x2F, 0xC0, 0x43, 0xE0, 0x07, 0x5F,
    0x40, 0x3F, 0x40, 0x13, 0x40, 0x4B, 0xE0, 0x03, 0x00, 0xC0,
    0x13, 0xE0, 0x04, 0x47, 0x40, 0xEC, 0x00, 0x82, 0x20, 0x25,
])

print(f"\n=== FACE SECTION ({len(face_raw)} bytes) ===")
print(f"Raw: {' '.join(f'{b:02X}' for b in face_raw)}")

# Parse into elements
elements = []
pos = 0
while pos < len(face_raw):
    b = face_raw[pos]
    if b <= 0x06:
        nb = b + 1
        if pos + 1 + nb > len(face_raw): break
        dv = face_raw[pos+1] if nb == 1 else int.from_bytes(face_raw[pos+1:pos+1+nb], 'big')
        elements.append(("DATA", pos, dv))
        pos += 1 + nb
    elif (b & 0x07) == 0x07 and b >= 0x07:
        elements.append(("SEP", pos, b))
        pos += 1
    elif pos + 1 < len(face_raw):
        b2 = face_raw[pos+1]
        hi_byte = b & 0xE0
        if b == 0xE1:
            cls = "E1"
        else:
            cls = {0x20: "20", 0x40: "40", 0x60: "60", 0x80: "80",
                   0xA0: "A0", 0xC0: "C0", 0xE0: "E0"}.get(hi_byte, f"{b:02X}")
        lo = b2 & 0x0F
        hi = (b2 >> 4) & 0x0F
        elements.append(("TAG", pos, cls, b2, lo, hi))
        pos += 2
    else:
        break

print("\nParsed elements:")
for e in elements:
    if e[0] == "DATA":
        val = e[2]
        note = ""
        if val == 0x40: note = " (FLAG)"
        elif val == 0x82: note = " (TRAILER)"
        elif val == 0xC0: note = " (FLAG?)"
        elif 1 <= val <= 8: note = f" (vertex {val}, 0-based={val-1})"
        print(f"  [{e[1]:3d}] DATA  0x{val:02X} = {val}{note}")
    elif e[0] == "SEP":
        print(f"  [{e[1]:3d}] SEP   0x{e[2]:02X}")
    elif e[0] == "TAG":
        print(f"  [{e[1]:3d}] TAG   {e[2]}:{e[3]:02X}  (lo={e[4]:X} hi={e[5]:X})")

# ── Structural breakdown ──
print(f"\n=== STRUCTURAL BREAKDOWN ===")
print("""
INITIAL SECTION (implicit initial tri 0,1,2):
  [  0] TAG 20:00  <- section start
  [  2] TAG 40:17  <- initial face tag (nib=7, same as fan/linear)
  [  4] DATA 0x03  <- vertex 3 (1-based) = idx 2
  [  6] TAG 20:07  <- delimiter
  [  8] TAG E0:0B  <- preamble? (different from E0:03)
  [ 10] SEP 2F
  [ 11] TAG 40:17  <- topology op (nib=7)
  [ 13] TAG E0:07
  [ 15] SEP 2F

SPLIT? SECTION:
  [ 16] TAG C0:5B  <- C0 class! Split op? (lo=B, hi=5)
  [ 18] DATA 0x06  <- vertex 6 (1-based) = idx 5
  [ 20] TAG 20:33  <- delimiter (different from 20:03!)
  [ 22] TAG E0:03  <- end group

GROUP A:
  [ 24] DATA 0x40  <- flag
  [ 26] SEP 17
  [ 27] TAG 40:2B  <- op (nib=B, hi=2)
  [ 29] TAG E0:07
  [ 31] SEP 17
  [ 32] TAG 40:43  <- op (nib=3, hi=4)
  [ 34] TAG 40:5B  <- op (nib=B, hi=5)
  [ 36] TAG E1:07  <- E1 class (not E0!)
  [ 38] SEP 87

GROUP B:
  [ 39] TAG 40:17  <- op (nib=7, hi=1)
  [ 41] DATA 0x07  <- vertex 7 (1-based) = idx 6
  [ 43] TAG 20:40  <- delimiter (different again!)
  [ 45] TAG 40:33  <- op (nib=3, hi=3)
  [ 47] TAG E0:03  <- end group

GROUP C:
  [ 49] DATA 0xC0  <- flag? (0xC0 not 0x40!)
  [ 51] SEP 17
  [ 52] TAG E0:07
  [ 54] SEP 2F
  [ 55] TAG C0:43  <- C0 class! Split? (lo=3, hi=4)
  [ 57] TAG E0:07
  [ 59] SEP 5F

GROUP D:
  [ 60] TAG 40:3F  <- op (nib=F, hi=3)
  [ 62] TAG 40:13  <- op (nib=3, hi=1)
  [ 64] TAG 40:4B  <- op (nib=B, hi=4)
  [ 66] TAG E0:03  <- end group

CLOSING:
  [ 68] DATA 0xC0  <- flag (0xC0 again)
  [ 70] SEP 13     <- wait, 0x13 & 0x07 = 3, not 7 -> NOT a separator!
""")

# Re-check: 0x13 as separator
b = 0x13
print(f"0x13: b & 0x07 = {b & 0x07}, is_sep = {(b & 0x07) == 0x07 and b >= 0x07}")
# 0x13 & 0x07 = 0x03 != 0x07, so NOT a separator. It's a tag pair byte.
# Let me re-parse this section more carefully

print("\n=== RE-PARSE CLOSING SECTION (offset 68+) ===")
# After E0:03 at offset 66:
# 68: 00 C0 -> DATA count=0, value=0xC0
# 70: 13 E0 -> TAG? 0x13 is not a count (>6), not a sep (0x13 & 7 = 3)
#              So it's a TAG: 13:E0 (class=??)
# 72: 04 47 40 EC 00 -> count=4, data=[47,40,EC,00,82] -- that's 5 bytes for count=4
# Wait: count=4 means read 5 bytes: [47, 40, EC, 00, 82]
# 72: 04 -> count=4, read 5 bytes: raw[73:78] = 47 40 EC 00 82
# 78: 20 25 -> TAG 20:25

tail = face_raw[68:]
print(f"Bytes from 68: {' '.join(f'{b:02X}' for b in tail)}")

pos2 = 0
while pos2 < len(tail):
    b = tail[pos2]
    if b <= 0x06:
        nb = b + 1
        if pos2 + 1 + nb > len(tail):
            print(f"  [{68+pos2}] COUNT={b} TRUNCATED (need {nb}, have {len(tail)-pos2-1})")
            break
        dv = tail[pos2+1:pos2+1+nb]
        print(f"  [{68+pos2}] COUNT={b} data=[{' '.join(f'{x:02X}' for x in dv)}]")
        pos2 += 1 + nb
    elif (b & 0x07) == 0x07 and b >= 0x07:
        print(f"  [{68+pos2}] SEP 0x{b:02X}")
        pos2 += 1
    elif pos2 + 1 < len(tail):
        b2 = tail[pos2+1]
        print(f"  [{68+pos2}] TAG {b:02X}:{b2:02X}")
        pos2 += 2
    else:
        break

# ── Collect all topology ops ──
print(f"\n=== ALL TOPOLOGY OPS ===")
ops_40 = []
ops_C0 = []
for e in elements:
    if e[0] == "TAG":
        cls, b2, lo, hi = e[2], e[3], e[4], e[5]
        if cls == "40":
            ops_40.append((lo, hi, e[1]))
            print(f"  40:{b2:02X} at [{e[1]}]  lo={lo:X} hi={hi:X}")
        elif cls == "C0":
            ops_C0.append((lo, hi, e[1]))
            print(f"  C0:{b2:02X} at [{e[1]}]  lo={lo:X} hi={hi:X}  ** SPLIT? **")

print(f"\n40-class: {len(ops_40)} ops")
print(f"C0-class: {len(ops_C0)} ops")
print(f"Total topology ops: {len(ops_40) + len(ops_C0)}")

# Vertex references in face section
verts_in_face = []
for e in elements:
    if e[0] == "DATA" and 1 <= e[2] <= 8:
        verts_in_face.append(e[2])
print(f"\nVertex refs (1-based): {verts_in_face}")
print(f"Vertex refs (0-based): {[v-1 for v in verts_in_face]}")
print(f"Unique: {sorted(set(verts_in_face))}")
print(f"Header says 8 verts, 12 faces")
print(f"Initial tri uses 0,1,2. Listed: {[v-1 for v in verts_in_face]}")
print(f"Not listed: {sorted(set(range(8)) - set(v-1 for v in verts_in_face) - {0,1,2})}")

# ── Build operation sequence for brute force ──
# From structural analysis, the cube has a more complex structure than fan/linear.
# Let me identify the groups and their vertex associations.

print(f"\n=== OPERATION SEQUENCE ANALYSIS ===")
print("""
The cube face section has these distinct segments:

1. INITIAL: 40:17 + vertex 3(=idx2) -> initial face uses V0,V1,V2 + references V2
   Then 40:17 (another C?) + C0:5B (split!) + vertex 6(=idx5) -> complex topology

2. GROUP A: 40:2B, 40:43, 40:5B (3 ops)

3. GROUP B: 40:17 + vertex 7(=idx6) + 40:33 (2 ops, 1 vertex)

4. GROUP C: C0:43 (split!)

5. GROUP D: 40:3F, 40:13, 40:4B (3 ops)

6. CLOSING: remaining ops

Cube has 12 faces. Initial = 1. Need 11 more from ~12 topology ops.
That's ~1 face per op, consistent with EdgeBreaker where each CLERS op = 1 face.

Key difference from fan/linear: cube is CLOSED (no boundary at end).
This means we need E operations to close all boundary edges.
Also need S (split) operations for the cube topology (genus 0 closed manifold).
""")

# ── Topology checker ──
def check_topo(decoded, truth):
    d_sets = {frozenset(f) for f in decoded}
    t_sets = {frozenset(f) for f in truth}
    if len(d_sets) != len(t_sets):
        return False, None, len(d_sets & t_sets)
    d_v, t_v = set(), set()
    for f in d_sets: d_v.update(f)
    for f in t_sets: t_v.update(f)
    if len(d_v) != len(t_v):
        return False, None, len(d_sets & t_sets)
    df, tf = Counter(), Counter()
    for f in d_sets:
        for v in f: df[v] += 1
    for f in t_sets:
        for v in f: tf[v] += 1
    if sorted(df.values()) != sorted(tf.values()):
        return False, None, 0
    for perm in permutations(sorted(t_v)):
        m = dict(zip(sorted(d_v), perm))
        if {frozenset(m[v] for v in f) for f in d_sets} == t_sets:
            return True, m, len(t_sets)
    return False, None, 0

# ── EdgeBreaker with split support ──
def trace_eb(init, gate, ops):
    bnd = list(init)
    faces = [init]
    g = gate
    nv = max(init) + 1
    errs = []
    stack = []  # for split operations

    for op in ops:
        if errs: break
        n = len(bnd)
        if n < 3 and op[0] not in ("GATE", "SKIP", "POP"):
            errs.append(f"bnd={n} at op {op}")
            break

        if n >= 3:
            li = g % n
            ri = (g+1) % n
            L, R = bnd[li], bnd[ri]

        if op[0] == "C":
            v = op[1] if op[1] is not None else nv
            if op[1] is None: nv += 1
            elif v >= nv: nv = v + 1
            faces.append((L, R, v))
            bnd.insert(li+1, v)
            g = li + 1

        elif op[0] == "L":
            if n < 4: errs.append("L<4"); break
            fl = bnd[(g-1)%n]
            faces.append((fl, L, R))
            bnd.pop(li)
            g = (li-1) % len(bnd)

        elif op[0] == "R":
            if n < 4: errs.append("R<4"); break
            fr = bnd[(g+2)%n]
            faces.append((L, R, fr))
            bnd.pop(ri)
            if g >= len(bnd): g = g % len(bnd)

        elif op[0] == "E":
            if n == 3:
                faces.append(tuple(bnd))
                bnd = []
                # Pop from stack if available
                if stack:
                    bnd, g = stack.pop()
            elif n >= 4:
                fl = bnd[(g-1)%n]
                faces.append((fl, L, R))
                bnd.pop(li)
                g = (li-1) % len(bnd)

        elif op[0] == "S":
            # Split: connect to a boundary vertex at offset, splitting boundary
            offset = op[1] if len(op) > 1 else 2
            target_idx = (g - 1 - offset) % n
            target = bnd[target_idx]
            faces.append((target, L, R))

            # Split boundary into two loops
            # Loop 1 (active): from target forward to R
            # Loop 2 (stacked): from R forward to target
            loop1 = []
            loop2 = []

            # Walk from R to target (loop 2 - goes on stack)
            i = ri
            while i != target_idx:
                loop2.append(bnd[i])
                i = (i + 1) % n
            loop2.append(bnd[target_idx])

            # Walk from target to L (loop 1 - stays active)
            # Actually: after removing the face (target, L, R),
            # L is consumed. The two new boundaries share target and R.
            # Loop 1: target -> ... -> stuff before L (= after R going around)
            # This is complex. Let me use a simpler model:

            # Remove L from boundary, split at target
            # Everything between target and R (exclusive) stays active
            # Everything between R and target (the other way) goes on stack

            bnd.pop(li)  # remove L
            n2 = len(bnd)
            # Find target and R in new boundary
            ti = bnd.index(target)
            ri2 = bnd.index(R)

            # Loop from target to R (exclusive): active
            active = []
            i = ti
            while True:
                active.append(bnd[i])
                if i == ri2: break
                i = (i + 1) % n2

            # Loop from R to target: stacked
            stacked = []
            i = ri2
            while True:
                stacked.append(bnd[i])
                if i == ti: break
                i = (i + 1) % n2

            if len(stacked) >= 3:
                stack.append((stacked, 0))
            if len(active) >= 3:
                bnd = active
                g = 0
            else:
                errs.append(f"S produced small loop: active={len(active)}")

        elif op[0] == "GATE":
            g = (g + op[1]) % max(len(bnd), 1)

        elif op[0] == "SKIP":
            pass

        elif op[0] == "POP":
            if stack:
                bnd, g = stack.pop()
            else:
                errs.append("POP with empty stack")

    return faces, errs, bnd, stack

# ── Brute force search for the cube ──
# The cube has ~12 topology ops for 11 additional faces.
# Each op is one of: C(new), C(explicit), L, R, E, S
# Plus gate advances between groups.
#
# From the structural analysis, I'll try different interpretations of each segment.

print(f"\n{'='*70}")
print("BRUTE FORCE: Trying cube operation sequences")
print(f"{'='*70}")

# Simplified: try the ops as a flat sequence
# 40-class ops (10): nib7 x4, nibB x3, nibF x1, nib3 x3
# C0-class ops (2): C0:5B(nibB), C0:43(nib3)
# Explicit vertices: 3(idx2), 6(idx5), 7(idx6)
# Missing vertices (must be implicit C): idx 3, 4, 7 (0-based)

# Let me try: each 40 op = one of C/L/R/E, each C0 op = S
# Explicit vertices consumed by C ops in order: 2, 5, 6
# Remaining vertices (3, 4, 7) created by implicit C ops

# Full op sequence from parse (in order of appearance):
# 40:17(7), 40:17(7), C0:5B(B), [v=5], 40:2B(B), 40:43(3), 40:5B(B),
# 40:17(7), [v=6], 40:33(3), C0:43(3), 40:3F(F), 40:13(3), 40:4B(B)
# Plus gate advances between groups

# The nibble->op mapping from fan/linear:
# nib=7 -> C (confirmed)
# nib=F -> C or R (context dependent)
# nib=B -> C, R, or finalizer (context dependent)
# nib=3 -> unknown (only in cube)

# For a closed manifold (cube), we need exactly:
# V-2 = 8-2 = 6 C operations (one per new vertex beyond initial edge)
# Plus L/R/S/E operations for the remaining faces
# Total ops should be F-1 = 11 (12 faces minus initial)

# With 12 topology ops and needing 11 faces, one op might be a gate/no-op

# Let me try nib=3 as L (most likely for closing faces on a cube)
# And handle C0 as S (split)

# Approach: try all combinations of nib->op mapping constrained by:
# - nib=7 = C (confirmed)
# - C0 class = S (split hypothesis)
# - Must produce exactly 12 faces on 8 vertices

nib_options = {
    0x3: ["L", "R", "E"],       # unknown, try all
    0x7: ["C"],                  # confirmed
    0xB: ["C", "L", "R", "FIN"],# context dependent
    0xF: ["C", "R"],            # confirmed C or R
}

# Build the flat op sequence with vertex associations
raw_ops = [
    ("40", 0x7, 0x1, None),      # 40:17 - initial area
    ("40", 0x7, 0x1, None),      # 40:17
    ("C0", 0xB, 0x5, None),      # C0:5B - split?
    # vertex 5 (0-based) appears here
    ("40", 0xB, 0x2, None),      # 40:2B
    ("40", 0x3, 0x4, None),      # 40:43
    ("40", 0xB, 0x5, None),      # 40:5B
    # E1:07 + sep here
    ("40", 0x7, 0x1, None),      # 40:17
    # vertex 6 (0-based) appears here
    ("40", 0x3, 0x3, None),      # 40:33
    ("C0", 0x3, 0x4, None),      # C0:43 - split?
    ("40", 0xF, 0x3, None),      # 40:3F
    ("40", 0x3, 0x1, None),      # 40:13
    ("40", 0xB, 0x4, None),      # 40:4B
]

# Explicit vertices: idx 2, 5, 6 appear at positions after ops 2, 6
# Implicit vertices needed: 3, 4, 7

explicit_verts = [2, 5, 6]  # 0-based, in order of appearance

best = []
count = 0

# For each nib=3 interpretation and nib=B/F interpretation
for n3_op in ["L", "R", "E"]:
    for n_b_ops in product(["C", "L", "R"], repeat=4):  # 4 nib=B occurrences
        for n_f_op in ["C", "R"]:
            count += 1

            # Build op sequence
            ops = []
            explicit_iter = iter(explicit_verts)
            nib_b_idx = 0
            implicit_next = 3  # first implicit vertex
            implicit_verts = [3, 4, 7]  # 0-based
            implicit_iter = iter(implicit_verts)

            valid = True
            for cls, lo, hi, _ in raw_ops:
                if cls == "C0":
                    # Split operation
                    ops.append(("S", hi))
                    continue

                if lo == 0x7:
                    op_type = "C"
                elif lo == 0xF:
                    op_type = n_f_op
                elif lo == 0x3:
                    op_type = n3_op
                elif lo == 0xB:
                    op_type = n_b_ops[nib_b_idx]
                    nib_b_idx += 1
                else:
                    valid = False
                    break

                if op_type == "C":
                    # Try explicit first, then implicit
                    try:
                        v = next(explicit_iter)
                    except StopIteration:
                        try:
                            v = next(implicit_iter)
                        except StopIteration:
                            v = None  # auto
                    ops.append(("C", v))
                elif op_type == "L":
                    ops.append(("L",))
                elif op_type == "R":
                    ops.append(("R",))
                elif op_type == "E":
                    ops.append(("E",))
                elif op_type == "FIN":
                    ops.append(("GATE", -1))

            if not valid:
                continue

            # Try different gate positions
            for ig in [0, 1, 2]:
                faces, errs, bnd, stk = trace_eb((0, 1, 2), ig, ops)

                if not errs and len(faces) >= 10:
                    match, mapping, overlap = check_topo(faces, fl)
                    if overlap >= 8:
                        best.append({
                            "ig": ig,
                            "n3": n3_op,
                            "nB": n_b_ops,
                            "nF": n_f_op,
                            "faces": len(faces),
                            "overlap": overlap,
                            "match": match,
                            "mapping": mapping,
                            "errs": errs,
                        })

print(f"\nSearched {count * 3} combinations")
print(f"Found {len(best)} results with 8+ face overlap\n")

# Sort by overlap then match
best.sort(key=lambda r: (r["match"], r["overlap"], -len(r["errs"])), reverse=True)

for i, r in enumerate(best[:20]):
    flag = " *** PERFECT ***" if r["match"] else ""
    print(f"  #{i}: gate={r['ig']}, n3={r['n3']}, nB={r['nB']}, nF={r['nF']}"
          f"  faces={r['faces']} overlap={r['overlap']}/12{flag}")
    if r["match"]:
        print(f"    Mapping: {r['mapping']}")
    if r["errs"]:
        print(f"    Errors: {r['errs'][:2]}")
PYEOF
