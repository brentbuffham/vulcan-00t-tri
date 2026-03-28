#!/usr/bin/env python3
"""
Cube trace v4: Constrained by EdgeBreaker theory.
For closed genus-0 manifold: 5C + 2S + 3E + 1(L/R) = 11 ops.
"""
import sys
import ezdxf
from itertools import combinations, permutations
from collections import Counter


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
        if self.err or n < 4:
            self.err = self.err or "L<4"; return
        fl = self.bnd[(self.g - 1) % n]
        self.faces.append((fl, L, R))
        self.bnd.pop(li)
        self.g = (li - 1) % len(self.bnd)

    def R(self):
        if self.err: return
        L, R, li, ri, n = self._lr()
        if self.err or n < 4:
            self.err = self.err or "R<4"; return
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
        if n < 5:
            self.err = f"S<5({n})"; return
        L, R, li, ri, n = self._lr()
        if self.err: return
        ti = (li - offset) % n
        T = self.bnd[ti]
        self.faces.append((T, L, R))

        active, stacked = [], []
        i = ri
        while True:
            active.append(self.bnd[i])
            if i == ti: break
            i = (i + 1) % n
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
            self.err = "S:bad"

    def ga(self, off):
        if self.bnd:
            self.g = (self.g + off) % len(self.bnd)


# Load DXF
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
CP = sorted([4, 4, 4, 4, 5, 5, 5, 5])


def check(faces):
    ds = {frozenset(f) for f in faces}
    if len(ds) != 12: return False, None
    dv = set()
    for f in ds: dv.update(f)
    if len(dv) != 8: return False, None
    df = Counter()
    for f in ds:
        for v in f: df[v] += 1
    if sorted(df.values()) != CP: return False, None
    for perm in permutations(sorted(set().union(*dxf_sets))):
        m = dict(zip(sorted(dv), perm))
        if {frozenset(m[v] for v in f) for f in ds} == dxf_sets:
            return True, m
    return False, None


# Op positions:
# 0=C, 1=S, 2=?, 3=?, 4=?, 5=C, 6=?, 7=S, 8=?, 9=?, 10=?
# Unconstrained: [2,3,4,6,8,9,10] -> need 3C + 3E + 1(L/R)
UC = [2, 3, 4, 6, 8, 9, 10]

found = 0
total = 0

ga_patterns = [
    {},
    {2: -1}, {5: -1}, {8: -1},
    {2: -1, 5: -1}, {2: -1, 8: -1}, {5: -1, 8: -1},
    {2: -1, 5: -1, 8: -1},
    {2: 1}, {5: 1}, {8: 1},
    {2: -1, 5: 1}, {2: 1, 5: -1},
]

for ig in [0, 1, 2]:
    for s1_off in [2, 3, 4]:
        for s2_off in [2, 3, 4]:
            for c_pos in combinations(range(7), 3):
                remaining = [i for i in range(7) if i not in c_pos]
                for lr_idx in range(4):
                    for lr_op in ["L", "R"]:
                        total += 1

                        ot = ["?"] * 11
                        ot[0] = "C"
                        ot[5] = "C"
                        ot[1] = f"S{s1_off}"
                        ot[7] = f"S{s2_off}"

                        for ci in c_pos:
                            ot[UC[ci]] = "C"
                        for ri_idx, ridx in enumerate(remaining):
                            if ri_idx == lr_idx:
                                ot[UC[ridx]] = lr_op
                            else:
                                ot[UC[ridx]] = "E"

                        for gap in ga_patterns:
                            dec = EB((0, 1, 2), ig)

                            for idx, o in enumerate(ot):
                                if dec.err: break
                                if idx in gap:
                                    dec.ga(gap[idx])
                                if o == "C":
                                    dec.C()
                                elif o == "L":
                                    dec.L()
                                elif o == "R":
                                    dec.R()
                                elif o == "E":
                                    dec.E()
                                elif o.startswith("S"):
                                    dec.S(int(o[1]))

                            if dec.err or len(dec.faces) != 12:
                                continue

                            match, mapping = check(dec.faces)
                            if match:
                                found += 1
                                print(f"\n*** MATCH #{found} ***")
                                print(f"  gate={ig}, s1={s1_off}, s2={s2_off}")
                                print(f"  ops={ot}")
                                print(f"  gate_advances={gap}")
                                print(f"  mapping={mapping}")
                                fsets = [set(f) for f in dec.faces]
                                print(f"  faces={fsets}")
                                if found >= 5:
                                    print(f"\nTotal: {total}")
                                    sys.exit(0)

print(f"\nSearched {total} combos x {len(ga_patterns)} ga x 3 gates")
print(f"Found {found} matches")
