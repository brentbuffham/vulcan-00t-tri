#!/usr/bin/env python3
"""
Cube face topology decoder v2.
Proper split handling, correct op count (11 ops for 11 faces).
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

dxf_sets = {frozenset(f) for f in fl}
print(f"DXF: 8 verts, 12 faces")
print(f"Adjacency profile: {sorted(Counter(v for f in fl for v in f).values())}")

# ── Op sequence (11 ops, excluding initial metadata tag at [2]) ──
# Starting from offset [11]:
raw_ops = [
    # (cls, lo_nib, hi_nib, offset)
    ("40", 0x7, 1, 11),    # 40:17
    ("C0", 0xB, 5, 16),    # C0:5B  -- SPLIT candidate
    ("40", 0xB, 2, 27),    # 40:2B
    ("40", 0x3, 4, 32),    # 40:43
    ("40", 0xB, 5, 34),    # 40:5B
    ("40", 0x7, 1, 39),    # 40:17
    ("40", 0x3, 3, 45),    # 40:33
    ("C0", 0x3, 4, 55),    # C0:43  -- SPLIT candidate
    ("40", 0xF, 3, 60),    # 40:3F
    ("40", 0x3, 1, 62),    # 40:13
    ("40", 0xB, 4, 64),    # 40:4B
]

# Explicit vertex refs (1-based): 3, 6, 7 = 0-based: 2, 5, 6
# Vertex 2 is in initial triangle -> back-reference
# Vertices 5, 6 are new
# Implicit new vertices needed: 3, 4, 7

print(f"\n11 topology ops:")
for cls, lo, hi, off in raw_ops:
    print(f"  [{off:2d}] {cls}:{(hi<<4)|lo:02X}  lo={lo:X} hi={hi}")

# ── Topology checker (fast: profile-based pre-filter) ──
CUBE_PROFILE = sorted([4, 4, 4, 4, 5, 5, 5, 5])  # vertex frequency in faces

def quick_topo_check(decoded, truth_sets):
    """Fast topology check using vertex frequency profile + isomorphism."""
    d_sets = {frozenset(f) for f in decoded}
    if len(d_sets) != len(truth_sets):
        return False, None

    d_v = set()
    for f in d_sets: d_v.update(f)
    if len(d_v) != 8:
        return False, None

    df = Counter()
    for f in d_sets:
        for v in f: df[v] += 1
    if sorted(df.values()) != CUBE_PROFILE:
        return False, None

    # Full isomorphism check
    t_v = set()
    for f in truth_sets: t_v.update(f)
    for perm in permutations(sorted(t_v)):
        m = dict(zip(sorted(d_v), perm))
        if {frozenset(m[v] for v in f) for f in d_sets} == truth_sets:
            return True, m
    return False, None


# ── EdgeBreaker decoder with working split ──
class EBDecoder:
    def __init__(self, tri, gate):
        self.faces = [tri]
        self.bnd = list(tri)
        self.g = gate
        self.nv = max(tri) + 1
        self.stack = []
        self.err = None

    def _LR(self):
        n = len(self.bnd)
        li = self.g % n
        ri = (self.g + 1) % n
        return self.bnd[li], self.bnd[ri], li, ri, n

    def C(self, v=None):
        if self.err: return
        if len(self.bnd) < 3:
            self.err = "C:small"; return
        L, R, li, ri, n = self._LR()
        if v is None:
            v = self.nv; self.nv += 1
        elif v >= self.nv:
            self.nv = v + 1
        self.faces.append((L, R, v))
        self.bnd.insert(li + 1, v)
        self.g = li + 1

    def L(self):
        if self.err: return
        n = len(self.bnd)
        if n < 4:
            self.err = "L:small"; return
        L, R, li, ri, n = self._LR()
        fl = self.bnd[(self.g - 1) % n]
        self.faces.append((fl, L, R))
        self.bnd.pop(li)
        self.g = (li - 1) % len(self.bnd)

    def R(self):
        if self.err: return
        n = len(self.bnd)
        if n < 4:
            self.err = "R:small"; return
        L, R, li, ri, n = self._LR()
        fr = self.bnd[(self.g + 2) % n]
        self.faces.append((L, R, fr))
        self.bnd.pop(ri)
        if self.g >= len(self.bnd):
            self.g = self.g % len(self.bnd)

    def E(self):
        if self.err: return
        n = len(self.bnd)
        if n == 3:
            self.faces.append(tuple(self.bnd))
            self.bnd = []
            if self.stack:
                self.bnd, self.g = self.stack.pop()
        elif n >= 4:
            L, R, li, ri, n = self._LR()
            fl = self.bnd[(self.g - 1) % n]
            self.faces.append((fl, L, R))
            self.bnd.pop(li)
            self.g = (li - 1) % len(self.bnd)
        else:
            self.err = "E:empty"

    def S(self, offset=2):
        """Split: connect gate to boundary vertex at offset positions left of gate.
        Creates a face, splits boundary into active + stacked loops."""
        if self.err: return
        n = len(self.bnd)
        if n < 5:
            self.err = f"S:small({n})"; return

        L, R, li, ri, n = self._LR()

        # Target vertex: 'offset' positions to the left of L
        ti = (self.g - offset) % n
        T = self.bnd[ti]

        self.faces.append((T, L, R))

        # Split boundary into two loops:
        # Active loop: from R clockwise to T (inclusive)
        # Stacked loop: from T clockwise to R (inclusive)

        # Build both loops by walking the boundary
        active = []  # R ... T
        i = ri
        while True:
            active.append(self.bnd[i])
            if i == ti:
                break
            i = (i + 1) % n

        stacked = []  # T ... R
        i = ti
        while True:
            stacked.append(self.bnd[i])
            if i == ri:
                break
            i = (i + 1) % n

        # Stack the smaller/later loop, keep the other active
        if len(stacked) >= 3:
            self.stack.append((stacked, 0))
        if len(active) >= 3:
            self.bnd = active
            self.g = 0  # gate at first edge of active loop
        elif self.stack:
            self.bnd, self.g = self.stack.pop()
        else:
            self.err = "S:no-valid-loop"


# ── Brute force ──
print(f"\n{'='*70}")
print("BRUTE FORCE SEARCH")
print(f"{'='*70}")

# Constraints:
# - nib=7 -> C (confirmed, 3 occurrences at positions 0, 5)
#   Wait, positions 0 and 5 of the 11-op sequence.
#   Position 0: 40:17, Position 5: 40:17. That's only 2 nib=7.
#   Oh wait: I listed 11 ops. Let me recount nib=7:
#   ops[0]=nib7, ops[5]=nib7 -> 2 nib=7 ops
# - C0 class -> try S or E
# - nib=B (40-class): 3 occurrences -> try C/L/R/E
# - nib=3 (40-class): 3 occurrences -> try C/L/R/E
# - nib=F: 1 occurrence -> try C/L/R/E

# Vertex tracking:
# - When C is assigned, consume next vertex from pool
# - Explicit vertices: [2, 5, 6] (0-based)
# - Implicit when explicit runs out: auto-increment

# How to assign explicit vertices to C ops?
# In fan/linear: explicit vertex associated with its group
# Here: vertex 2 appears near ops 0-1, vertex 5 near op 1-2, vertex 6 near ops 5-6

# Let me try multiple vertex assignment strategies

OPS = ["C", "L", "R", "E"]

best = []
count = 0

# nib=7 positions: [0, 5] -> always C
# C0 positions: [1, 7] -> try S(offset) or E
# nib=B (40-class) positions: [2, 4] (wait let me recount)

# Re-index:
# pos 0: 40:17 nib7
# pos 1: C0:5B nibB
# pos 2: 40:2B nibB
# pos 3: 40:43 nib3
# pos 4: 40:5B nibB
# pos 5: 40:17 nib7
# pos 6: 40:33 nib3
# pos 7: C0:43 nib3
# pos 8: 40:3F nibF
# pos 9: 40:13 nib3
# pos10: 40:4B nibB

# Unconstrained positions: 2(B), 3(3), 4(B), 6(3), 8(F), 9(3), 10(B)
# That's 7 unconstrained positions -> 4^7 = 16384 combos

# C0 positions [1, 7] -> try: S(2), S(3), S(4), E
C0_options = ["S2", "S3", "S4", "E"]

for ig in [0, 1, 2]:
    for c0_1 in C0_options:
        for c0_2 in C0_options:
            for combo in product(OPS, repeat=7):
                count += 1

                # Assign ops
                op_types = [None] * 11
                op_types[0] = "C"  # nib7
                op_types[5] = "C"  # nib7
                op_types[1] = c0_1  # C0
                op_types[7] = c0_2  # C0

                # Unconstrained at indices 2,3,4,6,8,9,10
                uc_idx = [2, 3, 4, 6, 8, 9, 10]
                for i, idx in enumerate(uc_idx):
                    op_types[idx] = combo[i]

                # Count C ops
                c_count = sum(1 for o in op_types if o == "C")
                # We need exactly 5 C ops (for 5 new vertices)
                if c_count != 5:
                    continue

                # Count S ops
                s_count = sum(1 for o in op_types if o.startswith("S"))
                e_count = sum(1 for o in op_types if o == "E")
                # For closed manifold: #E = #S + 1
                # But E might work differently in this variant

                # Execute
                dec = EBDecoder((0, 1, 2), ig)

                vert_pool = [2, 5, 6, 3, 4, 7]  # explicit first, then implicit
                vi = iter(vert_pool)

                for ot in op_types:
                    if dec.err:
                        break
                    if ot == "C":
                        try:
                            v = next(vi)
                        except StopIteration:
                            v = None
                        dec.C(v)
                    elif ot == "L":
                        dec.L()
                    elif ot == "R":
                        dec.R()
                    elif ot == "E":
                        dec.E()
                    elif ot.startswith("S"):
                        offset = int(ot[1])
                        dec.S(offset)

                if dec.err:
                    continue
                if len(dec.faces) != 12:
                    continue

                match, mapping = quick_topo_check(dec.faces, dxf_sets)
                if match:
                    best.append({
                        "ig": ig,
                        "c0_1": c0_1, "c0_2": c0_2,
                        "combo": combo,
                        "ops": op_types,
                        "faces": dec.faces,
                        "map": mapping,
                    })
                    # Print immediately
                    print(f"\n  *** MATCH #{len(best)} ***")
                    print(f"  gate={ig}, C0ops=[{c0_1},{c0_2}]")
                    print(f"  ops: {op_types}")
                    print(f"  faces: {[set(f) for f in dec.faces]}")
                    print(f"  mapping: {mapping}")

if count % 100000 == 0:
    pass

print(f"\nSearched {count} combinations")
print(f"Found {len(best)} PERFECT MATCHES")

if best:
    # Pattern analysis
    print(f"\n{'='*70}")
    print("PATTERN ANALYSIS")
    print(f"{'='*70}")
    c = Counter()
    for r in best:
        c[("gate", r["ig"])] += 1
        c[("c0_1", r["c0_1"])] += 1
        c[("c0_2", r["c0_2"])] += 1
        for i, o in enumerate(r["ops"]):
            c[("op" + str(i), o)] += 1

    for key in sorted(set(k for k, _ in c.keys())):
        vals = [(v, cnt) for (k, v), cnt in c.items() if k == key]
        vals.sort(key=lambda x: -x[1])
        print(f"  {key}: {vals[:5]}")
