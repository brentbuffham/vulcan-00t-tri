#!/usr/bin/env python3
"""Run the full authoritative toy parser parse_oot_v2 on any .00t; report counts,
bbox, first verts. Tests whether toy-format real files (SOLID_MM, cube) decode."""
import sys
sys.path.insert(0,'python')
from oot_parser_v2 import parse_oot_v2
r=parse_oot_v2(sys.argv[1])
v=getattr(r,'vertices',None); f=getattr(r,'faces',None)
print('warnings:',getattr(r,'warnings',None))
print('attrs:',[a for a in dir(r) if not a.startswith('_')])
if v is not None:
    print(f'vertices={len(v)} faces={len(f) if f else 0}')
    for i,vv in enumerate(v[:8]): print('  ',vv)
    if v:
        xs=[p[0] for p in v]; ys=[p[1] for p in v]; zs=[p[2] for p in v]
        print(f'bbox X[{min(xs):.3f},{max(xs):.3f}] Y[{min(ys):.3f},{max(ys):.3f}] Z[{min(zs):.3f},{max(zs):.3f}]')
