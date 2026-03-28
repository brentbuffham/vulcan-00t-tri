#!/usr/bin/env python3
"""
Deep brute-force trace of the fan topology to find the correct
EdgeBreaker operation mapping and gate advancement rules.
"""

import struct
import ezdxf
from itertools import permutations
from collections import Counter

# ── Load DXF ground truth ──
doc = ezdxf.readfile('exampleFiles/tri-crack-fan.dxf')
msp = doc.modelspace()
vm, vl, fl = {}, [], []
for e in msp:
    if e.dxftype() == '3DFACE':
        tri = []
        for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2]:
            key = (round(p[0], 4), round(p[1], 4), round(p[2], 4))
            if key not in vm:
                vm[key] = len(vl)
                vl.append(key)
            tri.append(vm[key])
        fl.append(tuple(tri))

print("DXF Ground Truth:")
for i, v in enumerate(vl):
    print(f"  V{i}: ({v[0]:.4f}, {v[1]:.4f}, {v[2]:.4f})")
for i, f in enumerate(fl):
    print(f"  F{i}: {f} = {set(f)}")

dxf_face_sets = {frozenset(f) for f in fl}

vert_freq = Counter()
for f in fl:
    for v in f:
        vert_freq[v] += 1
print(f"\nVertex frequency: {dict(vert_freq)}")
fan_center = vert_freq.most_common(1)[0][0]
print(f"Fan center: DXF V{fan_center} (in {vert_freq[fan_center]}/6 faces)")

print(f"\nFace section structure:")
print(f"  G0: 40:17(C), 40:2F(C), 40:1B(fin)  [no explicit vertex]")
print(f"  G1: 40:17(?), 40:2F(?), 40:1B(fin)  [back-ref to OOT V1 (1-based=2)]")
print(f"  G2: 40:17(?)                         [back-ref to OOT V0 (1-based=1)]")


# ── Topology isomorphism check ──
def check_topology_match(decoded_faces, truth_faces):
    d_sets = {frozenset(f) for f in decoded_faces}
    t_sets = {frozenset(f) for f in truth_faces}

    if len(d_sets) != len(t_sets):
        return False, None

    d_verts = set()
    for f in d_sets:
        d_verts.update(f)
    t_verts = set()
    for f in t_sets:
        t_verts.update(f)

    if len(d_verts) != len(t_verts):
        return False, None

    d_freq = Counter()
    for f in d_sets:
        for v in f:
            d_freq[v] += 1
    t_freq = Counter()
    for f in t_sets:
        for v in f:
            t_freq[v] += 1

    if sorted(d_freq.values()) != sorted(t_freq.values()):
        return False, None

    d_sorted = sorted(d_verts)
    t_sorted = sorted(t_verts)

    for perm in permutations(t_sorted):
        mapping = dict(zip(d_sorted, perm))
        mapped = {frozenset(mapping[v] for v in f) for f in d_sets}
        if mapped == t_sets:
            return True, mapping

    return False, None


# ── EdgeBreaker tracer ──
def trace_eb(initial_tri, gate_pos, ops):
    boundary = list(initial_tri)
    faces = [initial_tri]
    gate = gate_pos
    next_v = max(initial_tri) + 1
    errors = []

    for op in ops:
        if errors:
            break
        n = len(boundary)
        if n < 3 and op[0] not in ('GATE', 'SKIP'):
            errors.append(f"boundary={n}")
            break

        l_idx = gate % n
        r_idx = (gate + 1) % n

        left = boundary[l_idx]
        right = boundary[r_idx]

        if op[0] == 'C':
            new_v = op[1] if op[1] is not None else next_v
            if op[1] is None:
                next_v += 1
            elif new_v >= next_v:
                next_v = new_v + 1
            faces.append((left, right, new_v))
            ins = l_idx + 1
            boundary.insert(ins, new_v)
            gate = ins

        elif op[0] == 'L':
            if n < 4:
                errors.append("L needs 4+ boundary")
                break
            fl_idx = (gate - 1) % n
            far_left = boundary[fl_idx]
            faces.append((far_left, left, right))
            boundary.pop(l_idx)
            gate = (l_idx - 1) % len(boundary)

        elif op[0] == 'R':
            if n < 4:
                errors.append("R needs 4+ boundary")
                break
            fr_idx = (gate + 2) % n
            far_right = boundary[fr_idx]
            faces.append((left, right, far_right))
            boundary.pop(r_idx)
            if gate >= len(boundary):
                gate = gate % len(boundary)

        elif op[0] == 'E':
            if n == 3:
                faces.append(tuple(boundary))
                boundary = []
            elif n >= 4:
                fl_idx = (gate - 1) % n
                far_left = boundary[fl_idx]
                faces.append((far_left, left, right))
                boundary.pop(l_idx)
                gate = (l_idx - 1) % len(boundary)
            else:
                errors.append(f"E boundary={n}")

        elif op[0] == 'GATE':
            gate = (gate + op[1]) % max(len(boundary), 1)

        elif op[0] == 'SKIP':
            pass

    return faces, errors, boundary


# ── Brute force search ──
print("\n" + "=" * 70)
print("BRUTE FORCE SEARCH")
print("=" * 70)

best = []
gate_offsets = range(-4, 5)

strategies_g1 = [
    'L_C', 'C_L', 'C_R', 'R_C', 'L_R', 'R_L',
    'C_C', 'CC_backref',
]
strategies_g2 = ['L', 'R', 'E', 'C0']

count = 0
for init_gate in [0, 1, 2]:
    for g0_fin in gate_offsets:
        for g1_strat in strategies_g1:
            for g1_fin in gate_offsets:
                for g2_strat in strategies_g2:
                    count += 1
                    ops = []

                    # G0: C(3), C(4), gate_advance
                    ops.append(('C', 3))
                    ops.append(('C', None))  # 4
                    ops.append(('GATE', g0_fin))

                    # G1: varies
                    if g1_strat == 'L_C':
                        ops.append(('L',))
                        ops.append(('C', None))  # 5
                    elif g1_strat == 'C_L':
                        ops.append(('C', None))  # 5
                        ops.append(('L',))
                    elif g1_strat == 'C_R':
                        ops.append(('C', None))
                        ops.append(('R',))
                    elif g1_strat == 'R_C':
                        ops.append(('R',))
                        ops.append(('C', None))
                    elif g1_strat == 'L_R':
                        ops.append(('L',))
                        ops.append(('R',))
                    elif g1_strat == 'R_L':
                        ops.append(('R',))
                        ops.append(('L',))
                    elif g1_strat == 'C_C':
                        ops.append(('C', None))
                        ops.append(('C', None))
                    elif g1_strat == 'CC_backref':
                        ops.append(('C', 1))  # back-ref as C vertex
                        ops.append(('C', None))

                    ops.append(('GATE', g1_fin))

                    # G2: single op
                    if g2_strat == 'L':
                        ops.append(('L',))
                    elif g2_strat == 'R':
                        ops.append(('R',))
                    elif g2_strat == 'E':
                        ops.append(('E',))
                    elif g2_strat == 'C0':
                        ops.append(('C', 0))

                    faces, errors, bnd = trace_eb((0, 1, 2), init_gate, ops)

                    if not errors and len(faces) == 6:
                        match, mapping = check_topology_match(faces, fl)
                        if match:
                            best.append({
                                'ig': init_gate,
                                'g0f': g0_fin,
                                'g1s': g1_strat,
                                'g1f': g1_fin,
                                'g2s': g2_strat,
                                'faces': faces,
                                'map': mapping,
                                'bnd': bnd,
                            })

print(f"\nSearched {count} combinations")
print(f"Found {len(best)} PERFECT TOPOLOGY MATCHES!\n")

for i, r in enumerate(best[:30]):
    print(f"  #{i}: gate={r['ig']}, g0_fin={r['g0f']:+d}, "
          f"g1={r['g1s']}, g1_fin={r['g1f']:+d}, g2={r['g2s']}")
    fs = [set(f) for f in r['faces']]
    print(f"    Faces: {fs}")
    print(f"    OOT->DXF: {r['map']}")
    print(f"    Boundary: {r['bnd']}")

# ── Analyze common patterns in matches ──
if best:
    print(f"\n{'='*70}")
    print("PATTERN ANALYSIS across all matches")
    print(f"{'='*70}")

    c = Counter()
    for r in best:
        c[('init_gate', r['ig'])] += 1
        c[('g0_fin', r['g0f'])] += 1
        c[('g1_strat', r['g1s'])] += 1
        c[('g1_fin', r['g1f'])] += 1
        c[('g2_strat', r['g2s'])] += 1

    for key in ['init_gate', 'g0_fin', 'g1_strat', 'g1_fin', 'g2_strat']:
        values = [(v, cnt) for (k, v), cnt in c.items() if k == key]
        values.sort(key=lambda x: -x[1])
        print(f"\n  {key}:")
        for v, cnt in values:
            pct = 100 * cnt / len(best)
            print(f"    {v}: {cnt}/{len(best)} ({pct:.0f}%)")
