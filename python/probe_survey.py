#!/usr/bin/env python3
"""Survey every toy DXF: per-axis ranges (overlap?) and value-collision count.
Goal: find the file where coordinate VALUES are most distinct, so each decoded
value can be labelled to a unique (vertex,axis) slot -> lets us read the encoder's
EMISSION ORDER directly (vertex-major? axis-major? traversal?) without guessing.
This is the ORDER experiment, the gap the 8 byte-feature attempts (T001-008) missed."""
import glob, os
from collections import Counter

def verts(path):
    """Return list of (x,y,z) triples from 3DFACE entities (dedup by rounded coord)."""
    lines = open(path,'r',errors='ignore').read().split('\n')
    pts=[]
    i=0
    # 3DFACE: codes 10/20/30, 11/21/31, 12/22/32, 13/23/33 are the 4 corners
    cur={}
    while i < len(lines)-1:
        code=lines[i].strip(); val=lines[i+1].strip()
        try:
            c=int(code); f=float(val)
            if abs(f)<1e7:
                if c in (10,11,12,13): cur.setdefault(c-10 if c==10 else {11:1,12:2,13:3}[c],[None,None,None])[0]=round(f,3)
        except: pass
        i+=1
    return pts

def faces(path):
    """Parse 3DFACE corners -> set of unique vertices + the full slot list."""
    lines=open(path,'r',errors='ignore').read().split('\n')
    i=0
    corners=[]  # each corner = [x,y,z]
    cx={}
    n=len(lines)
    while i<n-1:
        try: c=int(lines[i].strip())
        except: i+=1; continue
        try: f=float(lines[i+1].strip())
        except: i+=1; continue
        if abs(f)>=1e7: i+=1; continue
        # corner index by tens digit: 10/20/30->c0, 11/21/31->c1, ...
        for ci in range(4):
            if c==10+ci: cx.setdefault(ci,[None,None,None])[0]=round(f,3)
            elif c==20+ci: cx.setdefault(ci,[None,None,None])[1]=round(f,3)
            elif c==30+ci: cx.setdefault(ci,[None,None,None])[2]=round(f,3)
        # a 3DFACE block ends loosely; flush when we see code 10 starting a new face after corners filled
        i+=1
        if len(cx)==4 and all(all(v is not None for v in cx[k]) for k in cx):
            for k in range(4): corners.append(tuple(cx[k]))
            cx={}
    return corners

for path in sorted(glob.glob('exampleFiles/*.dxf')):
    name=os.path.basename(path)
    c=faces(path)
    if not c:
        print(f'{name:32s}  (no 3DFACE corners parsed)'); continue
    uniq=sorted(set(c))
    xs=[v[0] for v in uniq]; ys=[v[1] for v in uniq]; zs=[v[2] for v in uniq]
    # value collisions: same numeric value used in >1 (axis) slot across the unique-vertex set
    allvals=Counter()
    for v in uniq:
        for a in range(3): allvals[round(v[a],3)]+=1
    # a value is "ambiguous for ordering" if it appears for more than one distinct (vertex,axis)
    slots=[]
    for vi,v in enumerate(uniq):
        for a in range(3): slots.append(v[a])
    sc=Counter(slots)
    dup_slots=sum(1 for s,n in sc.items() if n>1)
    total_slots=len(slots)
    xr=(min(xs),max(xs)); yr=(min(ys),max(ys)); zr=(min(zs),max(zs))
    xy_overlap = not (xr[1]<yr[0] or yr[1]<xr[0])
    print(f'{name:32s} V={len(uniq):4d}  X[{xr[0]:.1f},{xr[1]:.1f}] Y[{yr[0]:.1f},{yr[1]:.1f}] Z[{zr[0]:.1f},{zr[1]:.1f}]'
          f'  XYover={xy_overlap}  dupSlotVals={dup_slots}/{total_slots}')
