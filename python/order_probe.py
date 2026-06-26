#!/usr/bin/env python3
"""ORDER experiment (the gap T001-008 missed). Decode a toy file's coord region to
a SEQUENCE of scalar values (no axis assumed). Label each value to its (vertex,axis)
slot by matching the DXF. Then READ THE EMISSION ORDER:
  - vertex-major  -> axis sequence cycles  X Y Z X Y Z ...
  - axis-major    -> axis sequence blocks  X..X Y..Y Z..Z   (column-major)
  - traversal     -> neither; order follows the mesh walk (couples to faces)
GT (DXF) used ONLY to label for discovering the order; the resulting order rule is
ground-truth-free. tol=0.3 absorbs the known 0.25 DELTA precision errors."""
import sys
sys.path.insert(0,'python')
from oot_parser_v2 import parse_coord_elements, group_coord_elements
from collections import Counter

def coord_region(raw):
    """Inlined from axis_supervised.py (which runs code at import)."""
    vi = raw.find(b'Variant'); variant_len = raw[vi-1]; ds = vi+variant_len
    anchor = raw.find(b'\x43\xE0\x0E', ds, ds+20)
    coord_start = -1
    for off in range(15,25):
        pos=anchor+off
        if pos+2<len(raw) and raw[pos]==0xE0 and raw[pos+2]==0x14: coord_start=pos+3; break
    if coord_start<0:
        for off in range(15,25):
            pos=anchor+off
            if pos<len(raw) and raw[pos]<=0x06: coord_start=pos; break
    if coord_start<0: coord_start=anchor+18
    is_new = variant_len>8
    shaded=raw.find(b'SHADED',ds);  shaded = shaded if shaded>=0 else len(raw)
    if is_new:
        sep_line=raw.find(b'separator_line',ds); face_end=sep_line-2 if sep_line>0 else shaded
        face_marker=-1; first=-1
        for i in range(coord_start+10,face_end-1):
            if raw[i]==0xE0 and raw[i+1]==0x03: first=i; break
        if first>0:
            for i in range(first,face_end-1):
                if raw[i]==0x20 and raw[i+1]==0x00 and i+2<face_end and (raw[i+2]&0xE0)==0x40: face_marker=i; break
        if face_marker<0:
            for i in range(face_end-2,coord_start,-1):
                if raw[i]==0x20 and raw[i+1]==0x00: face_marker=i; break
    else:
        attr=raw.find(b'\x00\x05\x40\x04\x00\x0A\x20\x08\x07',ds); face_end=attr if attr>0 else shaded
        face_marker=-1
        for i in range(coord_start+5,face_end-2):
            if raw[i]==0x20 and raw[i+1]==0x00 and raw[i+2]<=0x06: face_marker=i; break
        if face_marker<0:
            for i in range(coord_start+20,face_end-1):
                if raw[i]==0x20 and raw[i+1]==0x00: face_marker=i; break
    coord_end = face_marker if face_marker>0 else face_end
    return raw[coord_start:coord_end], is_new

def dxf_slots(path):
    """Return dict value->set(axis) and list of (vi,x,y,z) unique verts (rounded)."""
    import re
    lines=open(path,'r',errors='ignore').read().split('\n')
    i=0; cx={}; corners=[]
    n=len(lines)
    while i<n-1:
        try: c=int(lines[i].strip())
        except: i+=1; continue
        try: f=float(lines[i+1].strip())
        except: i+=1; continue
        if abs(f)<1e7:
            for ci in range(4):
                if c==10+ci: cx.setdefault(ci,[None,None,None])[0]=round(f,3)
                elif c==20+ci: cx.setdefault(ci,[None,None,None])[1]=round(f,3)
                elif c==30+ci: cx.setdefault(ci,[None,None,None])[2]=round(f,3)
        i+=1
        if len(cx)==4 and all(all(v is not None for v in cx[k]) for k in cx):
            for k in range(4): corners.append(tuple(cx[k]))
            cx={}
    uniq=sorted(set(corners))
    val2axis={}
    for v in uniq:
        for a in range(3):
            val2axis.setdefault(round(v[a],3),set()).add(a)
    return val2axis, uniq

def label(v, val2axis, tol=0.3):
    """Return ('X'/'Y'/'Z'/'XY'/'?'/'MISS', matched_value)."""
    best=None; bestd=tol
    for gv in val2axis:
        d=abs(v-gv)
        if d<bestd: bestd=d; best=gv
    if best is None: return ('MISS', None)
    axes=val2axis[best]
    nm=''.join('XYZ'[a] for a in sorted(axes))
    return (nm, best)

AX='XYZ'
def run(oot, dxf):
    raw=open(oot,'rb').read()
    region,is_new=coord_region(raw)
    groups=group_coord_elements(parse_coord_elements(region,new_format=is_new))
    val2axis,uniq=dxf_slots(dxf)
    print(f'\n=== {oot}  ({len(groups)} coord groups, {len(uniq)} DXF verts) ===')
    seq=[]
    for i,g in enumerate(groups):
        nm,mv=label(g.value,val2axis)
        seq.append(nm)
        if i<40:
            print(f'  [{i:2d}] decoded={g.value:10.3f}  -> {nm:4s} (gtval={mv})  kind={g.kind}')
    # collapse to clean single-axis labels for the cycle test
    clean=[s for s in seq if s in ('X','Y','Z')]
    print(f'  clean single-axis labels ({len(clean)}/{len(seq)}): {"".join(clean)[:80]}')
    # cycle test: does it look like XYZXYZ?
    if clean:
        cyc=Counter()
        for a,b in zip(clean,clean[1:]): cyc[a+b]+=1
        print(f'  adjacent-pair transitions: {dict(cyc)}')

if __name__=='__main__':
    pairs=[
        ('exampleFiles/tri-crack-prism.00t','exampleFiles/tri-crack-prism.dxf'),
        ('exampleFiles/tri-crack-linear.00t','exampleFiles/tri-crack-linear.dxf'),
        ('exampleFiles/tri-crack-NonRound.00t','exampleFiles/tri-crack-NonRound.dxf'),
    ]
    if len(sys.argv)==3: pairs=[(sys.argv[1],sys.argv[2])]
    for o,d in pairs: run(o,d)
