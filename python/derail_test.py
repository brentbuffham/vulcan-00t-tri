#!/usr/bin/env python3
"""Derail test: run the existing parser on a large production .00t and
report how far it gets (counts, timing, where it breaks)."""
import sys, time, traceback
sys.path.insert(0, 'python')
from oot_parser_v2 import parse_oot_v2

path = sys.argv[1]
t0 = time.time()
try:
    r = parse_oot_v2(path)
    dt = time.time() - t0
    print(f'parse returned in {dt:.1f}s')
    print('n_verts_header :', getattr(r, 'n_verts_header', None))
    print('n_faces_header :', getattr(r, 'n_faces_header', None))
    verts = getattr(r, 'vertices', None)
    faces = getattr(r, 'faces', None)
    print('vertices decoded:', len(verts) if verts is not None else None)
    print('faces decoded   :', len(faces) if faces is not None else None)
    w = getattr(r, 'warnings', [])
    print('warnings:', len(w))
    for x in w[:20]:
        print('   -', x)
    if verts:
        print('first 3 verts:', verts[:3])
        print('last 3 verts :', verts[-3:])
except Exception as e:
    dt = time.time() - t0
    print(f'EXCEPTION after {dt:.1f}s: {type(e).__name__}: {e}')
    traceback.print_exc()
