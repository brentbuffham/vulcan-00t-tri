#!/usr/bin/env python3
"""
Deterministic decoding analysis.

For each test file, replay the known-correct EdgeBreaker traversal
and record the full boundary state at each operation. Then correlate
with the actual tag bytes to find what makes decoding unambiguous.
"""

from collections import Counter


class EB:
    """EdgeBreaker decoder with full state logging."""
    def __init__(self, tri, gate):
        self.faces = [tri]
        self.bnd = list(tri)
        self.g = gate
        self.nv = max(tri) + 1
        self.stack = []
        self.log = []

    def _state(self):
        n = len(self.bnd)
        if n < 3:
            return {"bnd": list(self.bnd), "gate": self.g, "bnd_size": n}
        li = self.g % n
        ri = (self.g + 1) % n
        L = self.bnd[li]
        R = self.bnd[ri]
        return {
            "bnd": list(self.bnd),
            "gate": self.g,
            "bnd_size": n,
            "left": L,
            "right": R,
            "gate_edge": (L, R),
        }

    def C(self):
        state = self._state()
        n = len(self.bnd)
        L, R = self.bnd[self.g % n], self.bnd[(self.g+1) % n]
        v = self.nv; self.nv += 1
        self.faces.append((L, R, v))
        self.bnd.insert((self.g % n) + 1, v)
        self.g = (self.g % n) + 1
        state["op"] = "C"
        state["new_vertex"] = v
        state["face"] = (L, R, v)
        self.log.append(state)

    def L(self):
        state = self._state()
        n = len(self.bnd)
        li = self.g % n
        L = self.bnd[li]
        R = self.bnd[(self.g+1) % n]
        fl = self.bnd[(self.g-1) % n]
        self.faces.append((fl, L, R))
        self.bnd.pop(li)
        self.g = (li - 1) % len(self.bnd)
        state["op"] = "L"
        state["far_left"] = fl
        state["face"] = (fl, L, R)
        self.log.append(state)

    def R(self):
        state = self._state()
        n = len(self.bnd)
        li = self.g % n
        ri = (self.g+1) % n
        L = self.bnd[li]
        R = self.bnd[ri]
        fr = self.bnd[(self.g+2) % n]
        self.faces.append((L, R, fr))
        self.bnd.pop(ri)
        if self.g >= len(self.bnd):
            self.g %= len(self.bnd)
        state["op"] = "R"
        state["far_right"] = fr
        state["face"] = (L, R, fr)
        self.log.append(state)

    def E(self):
        state = self._state()
        n = len(self.bnd)
        if n == 3:
            self.faces.append(tuple(self.bnd))
            state["op"] = "E"
            state["face"] = tuple(self.bnd)
            self.bnd = []
            if self.stack:
                self.bnd, self.g = self.stack.pop()
            self.log.append(state)
            return
        li = self.g % n
        L = self.bnd[li]
        R = self.bnd[(self.g+1) % n]
        fl = self.bnd[(self.g-1) % n]
        self.faces.append((fl, L, R))
        self.bnd.pop(li)
        self.g = (li - 1) % len(self.bnd)
        state["op"] = "E"
        state["face"] = (fl, L, R)
        self.log.append(state)


# ══════════════════════════════════════════════════════════════
# Known-correct traversals from our brute force results
# ══════════════════════════════════════════════════════════════

# Linear strip: gate=1, ops = C,C,gate(-1),C,C (all C, 2 groups)
# Tag sequence:  40:17, 40:2F, 40:1B(fin), 40:17, 40:2B, 40:1B(fin)
linear_tags = [
    (0x40, 0x17, 7, 1),  # C
    (0x40, 0x2F, 0xF, 2),  # C
    (0x40, 0x1B, 0xB, 1),  # finalizer (gate -1)
    (0x40, 0x17, 7, 1),  # C
    (0x40, 0x2B, 0xB, 2),  # C
    (0x40, 0x1B, 0xB, 1),  # finalizer (gate -1)
]
linear_ops = ["C", "C", "GATE-1", "C", "C", "GATE-1"]

# Fan: gate=1, ops = C,C,gate(-1),C,R,gate(-1),L/R/E
# Tag sequence: 40:17, 40:2F, 40:1B, 40:17, 40:2F, 40:1B, 40:17
fan_tags = [
    (0x40, 0x17, 7, 1),  # C
    (0x40, 0x2F, 0xF, 2),  # C
    (0x40, 0x1B, 0xB, 1),  # finalizer
    (0x40, 0x17, 7, 1),  # C
    (0x40, 0x2F, 0xF, 2),  # R (context: back-ref group)
    (0x40, 0x1B, 0xB, 1),  # finalizer
    (0x40, 0x17, 7, 1),  # L or R or E (closing)
]
fan_ops = ["C", "C", "GATE-1", "C", "R", "GATE-1", "E"]

# Cube (match #8, gate=1): C,C,C,R,C,C,R,L,L,R,E
# Tag sequence: 40:17, C0:5B, 40:2B, 40:43, 40:5B, 40:17, 40:33, C0:43, 40:3F, 40:13, 40:4B
cube_tags = [
    (0x40, 0x17, 7, 1),  # C
    (0xC0, 0x5B, 0xB, 5),  # C
    (0x40, 0x2B, 0xB, 2),  # C
    (0x40, 0x43, 3, 4),  # R
    (0x40, 0x5B, 0xB, 5),  # C
    (0x40, 0x17, 7, 1),  # C
    (0x40, 0x33, 3, 3),  # R
    (0xC0, 0x43, 3, 4),  # L
    (0x40, 0x3F, 0xF, 3),  # L
    (0x40, 0x13, 3, 1),  # R
    (0x40, 0x4B, 0xB, 4),  # E
]
cube_ops = ["C", "C", "C", "R", "C", "C", "R", "L", "L", "R", "E"]

# Plane: gate=1 (same convention), 1 op: C
# Tag: 40:AB, 40:1B (but we determined plane = 1 C + finalizer)
plane_tags = [
    (0x40, 0xAB, 0xB, 0xA),  # C
    (0x40, 0x1B, 0xB, 1),  # finalizer
]
plane_ops = ["C", "GATE-1"]


# ══════════════════════════════════════════════════════════════
# Replay each file and correlate tags with state
# ══════════════════════════════════════════════════════════════

def replay(name, tags, ops, init_gate=1):
    print(f"\n{'='*78}")
    print(f"  {name}")
    print(f"{'='*78}")

    dec = EB((0, 1, 2), init_gate)

    tag_idx = 0
    for op in ops:
        if op.startswith("GATE"):
            offset = int(op.split("GATE")[1])
            dec.g = (dec.g + offset) % max(len(dec.bnd), 1)
            # Still log the tag
            if tag_idx < len(tags):
                cls, b2, lo, hi = tags[tag_idx]
                n = len(dec.bnd)
                print(f"  [{tag_idx:2d}] {cls:02X}:{b2:02X} (lo={lo:X} hi={hi})  "
                      f"OP=GATE({offset:+d})  bnd_size={n}  gate={dec.g}")
                tag_idx += 1
            continue

        if op == "C":
            dec.C()
        elif op == "L":
            dec.L()
        elif op == "R":
            dec.R()
        elif op == "E":
            dec.E()

        entry = dec.log[-1]
        cls, b2, lo, hi = tags[tag_idx]

        # Compute interesting correlations
        bnd_size = entry["bnd_size"]
        gate = entry["gate"]
        left = entry.get("left", "?")
        right = entry.get("right", "?")
        bnd = entry["bnd"]
        face = entry.get("face", ())

        # Where is the new vertex / far vertex relative to boundary?
        if op == "C":
            new_v = entry.get("new_vertex", "?")
            detail = f"new_v={new_v}"
        elif op == "R":
            fr = entry.get("far_right", "?")
            # What position is far_right in the boundary?
            fr_pos = bnd.index(fr) if fr in bnd else "?"
            fr_offset = (fr_pos - gate) % bnd_size if isinstance(fr_pos, int) else "?"
            detail = f"far_right={fr} at bnd[{fr_pos}] offset={fr_offset}"
        elif op == "L":
            fl = entry.get("far_left", "?")
            fl_pos = bnd.index(fl) if fl in bnd else "?"
            fl_offset = (fl_pos - gate) % bnd_size if isinstance(fl_pos, int) else "?"
            detail = f"far_left={fl} at bnd[{fl_pos}] offset={fl_offset}"
        elif op == "E":
            detail = f"closing"
        else:
            detail = ""

        print(f"  [{tag_idx:2d}] {cls:02X}:{b2:02X} (lo={lo:X} hi={hi:X})  "
              f"OP={op:5s}  bnd={bnd}  gate={gate} edge=({left},{right})  "
              f"hi_nib={hi}  bnd_size={bnd_size}  {detail}")

        tag_idx += 1

    print(f"\n  Final faces ({len(dec.faces)}):")
    for i, f in enumerate(dec.faces):
        print(f"    F{i}: {set(f)}")


replay("LINEAR STRIP", linear_tags, linear_ops)
replay("FAN", fan_tags, fan_ops)
replay("CUBE (match #8)", cube_tags, cube_ops)
replay("PLANE", plane_tags, plane_ops)


# ══════════════════════════════════════════════════════════════
# Cross-file correlation table
# ══════════════════════════════════════════════════════════════

print(f"\n{'='*78}")
print(f"  CORRELATION TABLE: hi_nib vs boundary_size vs operation")
print(f"{'='*78}")

all_entries = []

def collect(name, tags, ops, init_gate=1):
    dec = EB((0, 1, 2), init_gate)
    tag_idx = 0
    for op in ops:
        if op.startswith("GATE"):
            offset = int(op.split("GATE")[1])
            dec.g = (dec.g + offset) % max(len(dec.bnd), 1)
            tag_idx += 1
            continue
        if op == "C": dec.C()
        elif op == "L": dec.L()
        elif op == "R": dec.R()
        elif op == "E": dec.E()

        entry = dec.log[-1]
        cls, b2, lo, hi = tags[tag_idx]
        all_entries.append({
            "file": name,
            "tag": f"{cls:02X}:{b2:02X}",
            "lo": lo,
            "hi": hi,
            "op": op,
            "bnd_size": entry["bnd_size"],
            "gate": entry["gate"],
            "cls": cls,
        })
        tag_idx += 1

collect("linear", linear_tags, linear_ops)
collect("fan", fan_tags, fan_ops)
collect("cube", cube_tags, cube_ops)
collect("plane", plane_tags, plane_ops)

# Print correlation table
print(f"\n{'tag':>8s} {'lo':>3s} {'hi':>3s} {'op':>5s} {'bnd':>4s} {'gate':>5s} {'cls':>4s}  file")
print("-" * 60)
for e in all_entries:
    print(f"{e['tag']:>8s} {e['lo']:3X} {e['hi']:3X} {e['op']:>5s} {e['bnd_size']:4d} {e['gate']:5d} {e['cls']:4X}  {e['file']}")

# Check: does hi_nib == bnd_size?
print(f"\n--- Does hi_nib correlate with boundary size? ---")
for e in all_entries:
    match = "YES" if e["hi"] == e["bnd_size"] else f"no (hi={e['hi']}, bnd={e['bnd_size']})"
    print(f"  {e['tag']} {e['op']:5s}: {match}")

# Check: does hi_nib == gate position?
print(f"\n--- Does hi_nib correlate with gate position? ---")
for e in all_entries:
    match = "YES" if e["hi"] == e["gate"] else f"no (hi={e['hi']}, gate={e['gate']})"
    print(f"  {e['tag']} {e['op']:5s}: {match}")

# Check: does (hi_nib * 2 + something) relate to bnd_size?
print(f"\n--- Other correlations ---")
print(f"\n  hi_nib values by operation type:")
by_op = {}
for e in all_entries:
    by_op.setdefault(e["op"], []).append(e["hi"])
for op, vals in sorted(by_op.items()):
    print(f"    {op}: hi_nib values = {vals}")

print(f"\n  bnd_size values by operation type:")
by_op2 = {}
for e in all_entries:
    by_op2.setdefault(e["op"], []).append(e["bnd_size"])
for op, vals in sorted(by_op2.items()):
    print(f"    {op}: bnd_size values = {vals}")

print(f"\n  lo_nib + hi_nib patterns:")
for e in all_entries:
    full = (e["hi"] << 4) | e["lo"]
    print(f"    {e['tag']} op={e['op']:5s}  full_byte2=0x{full:02X}={full:3d}  "
          f"lo={e['lo']:X} hi={e['hi']:X}  bnd={e['bnd_size']} gate={e['gate']}")
