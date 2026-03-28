#!/usr/bin/env python3
"""
Cube trace v3: remove vertex pre-assignment, auto-assign all C ops.
Also try C0 as different op types, not just S.
"""

import ezdxf
from itertools import permutations, product
from collections import Counter
import sys

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
CUBE_PROFILE = sorted([4, 4, 4, 4, 5, 5, 5, 5])

# ── EdgeBreaker decoder ──
class EB:
    def __init__(self, tri, gate):
        self.faces = [tri]
        self.bnd = list(tri)
        self.g = gate
        self.nv = max(tri) + 1
        self.stack = []
        self.err = None

    def _lr(self):
        n = len(self.bnd)
        if n < 3:
            self.err = "tiny"
            return 0, 0, 0, 0, 0
        li = self.g % n
        ri = (self.g + 1) % n
        return self.bnd[li], self.bnd[ri], li, ri, n

    def C(self):
        if self.err: return
        L, R, li, ri, n = self._lr()
        if self.err: return
        v = self.nv; self.nv += 1
        self.faces.append((L, R, v))
        self.bnd.insert(li + 1, v)
        self.g = li + 1

    def L(self):
        if self.err: return
        L, R, li, ri, n = self._lr()
        if self.err or n < 4: self.err = self.err or "L<4"; return
        fl = self.bnd[(self.g - 1) % n]
        self.faces.append((fl, L, R))
        self.bnd.pop(li)
        self.g = (li - 1) % len(self.bnd)

    def R(self):
        if self.err: return
        L, R, li, ri, n = self._lr()
        if self.err or n < 4: self.err = self.err or "R<4"; return
        fr = self.bnd[(self.g + 2) % n]
        self.faces.append((L, R, fr))
        self.bnd.pop(ri)
        if self.g >= len(self.bnd):
            self.g %= len(self.bnd)

    def E(self):
        if self.err: return
        n = len(self.bnd)
        if n == 3:
            self.faces.append(tuple(self.bnd))
            self.bnd = []
            if self.stack:
                self.bnd, self.g = self.stack.pop()
            return
        if n < 3:
            self.err = "E:empty"; return
        L, R, li, ri, n = self._lr()
        if self.err: return
        fl = self.bnd[(self.g - 1) % n]
        self.faces.append((fl, L, R))
        self.bnd.pop(li)
        self.g = (li - 1) % len(self.bnd)

    def S(self, offset=2):
        if self.err: return
        n = len(self.bnd)
        if n < 5: self.err = f"S<5({n})"; return
        L, R, li, ri, n = self._lr()
        if self.err: return
        ti = (li - offset) % n
        T = self.bnd[ti]
        self.faces.append((T, L, R))

        # Build two loops
        # Active: R -> ... -> T (clockwise from R to T)
        active = []
        i = ri
        while True:
            active.append(self.bnd[i])
            if i == ti: break
            i = (i + 1) % n

        # Stacked: T -> ... -> R (clockwise from T to R)
        stacked = []
        i = ti
        while True:
            stacked.append(self.bnd[i])
            if i == ri: break
            i = (i + 1) % n

        if len(active) >= 3 and len(stacked) >= 3:
            self.stack.append((stacked, 0))
            self.bnd = active
            self.g = 0
        elif len(active) >= 3:
            self.bnd = active
            self.g = 0
        elif len(stacked) >= 3:
            self.bnd = stacked
            self.g = 0
        else:
            self.err = "S:bad-loops"

    def gate_advance(self, off):
        if self.bnd:
            self.g = (self.g + off) % len(self.bnd)


def quick_check(faces):
    d_sets = {frozenset(f) for f in faces}
    if len(d_sets) != 12:
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
    for perm in permutations(sorted(set().union(*dxf_sets))):
        m = dict(zip(sorted(d_v), perm))
        if {frozenset(m[v] for v in f) for f in d_sets} == dxf_sets:
            return True, m
    return False, None


# ── Search ──
# 11 ops. Constrained:
# pos 0, 5: nib=7 -> C (2 ops)
# pos 1, 7: C0 class -> try S2/S3/S4, C, L, R, E
# pos 2,4,10: nib=B -> C/L/R/E
# pos 3,6,9: nib=3 -> C/L/R/E
# pos 8: nib=F -> C/L/R/E

# Must produce exactly 12 faces on 8 vertices (5 C ops needed for 8-3=5 new verts)

# Also try gate advances at group boundaries.
# From structural analysis, groups end at E0:03 markers.
# Group boundaries after ops: [after op1 (E0:0B)], [after op4 (E1:07)],
# [after op6 (E0:03)], [after op7 (C0 + E0:07)], [after op10 (E0:03)]

OPS = ["C", "L", "R", "E"]
C0_OPS = ["S2", "S3", "S4", "C", "L", "R", "E"]

total = 0
found = 0
best = []

# Gate advances at key positions: after ops 1, 4, 6, 7
# Try with and without gate advances
gate_patterns = [
    [],  # no gate advances
    [(2, -1)],  # after op 1, advance -1
    [(5, -1)],  # after op 4, advance -1
    [(2, -1), (5, -1)],
    [(2, -1), (7, -1)],
    [(2, -1), (5, -1), (8, -1)],
]

for ig in [0, 1, 2]:
    for c0_ops in product(C0_OPS, repeat=2):
        for b_ops in product(OPS, repeat=3):  # pos 2, 4, 10
            for three_ops in product(OPS, repeat=3):  # pos 3, 6, 9
                for f_op in OPS:  # pos 8
                    total += 1

                    # Build op types
                    ot = [None] * 11
                    ot[0] = "C"
                    ot[5] = "C"
                    ot[1] = c0_ops[0]
                    ot[7] = c0_ops[1]
                    ot[2] = b_ops[0]
                    ot[4] = b_ops[1]
                    ot[10] = b_ops[2]
                    ot[3] = three_ops[0]
                    ot[6] = three_ops[1]
                    ot[9] = three_ops[2]
                    ot[8] = f_op

                    # Quick filter: need exactly 5 C ops
                    c_count = sum(1 for o in ot if o == "C")
                    if c_count != 5:
                        continue

                    # Try with basic gate advance patterns
                    for gp in gate_patterns:
                        dec = EB((0, 1, 2), ig)

                        for idx, o in enumerate(ot):
                            if dec.err: break

                            # Apply gate advance if scheduled
                            for ga_pos, ga_off in gp:
                                if idx == ga_pos:
                                    dec.gate_advance(ga_off)

                            if o == "C": dec.C()
                            elif o == "L": dec.L()
                            elif o == "R": dec.R()
                            elif o == "E": dec.E()
                            elif o == "S2": dec.S(2)
                            elif o == "S3": dec.S(3)
                            elif o == "S4": dec.S(4)

                        if dec.err or len(dec.faces) != 12:
                            continue

                        match, mapping = quick_check(dec.faces)
                        if match:
                            found += 1
                            best.append({
                                "ig": ig, "ops": list(ot),
                                "gp": gp, "map": mapping,
                                "faces": dec.faces,
                            })
                            print(f"\n*** MATCH #{found} ***")
                            print(f"  gate={ig}, ops={ot}")
                            print(f"  gate_pattern={gp}")
                            print(f"  mapping={mapping}")
                            fsets = [set(f) for f in dec.faces]
                            print(f"  faces={fsets}")

                            if found >= 10:
                                print(f"\nFound {found} matches, stopping.")
                                sys.exit(0)

print(f"\nSearched {total} op combos x {len(gate_patterns)} gate patterns x 3 gates")
print(f"Found {found} PERFECT MATCHES")
