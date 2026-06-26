#!/usr/bin/env python3
"""UNIFIED axis-rule search. Decode a toy file's coord groups with the production
grammar, label each group's TRUE axis from the DXF ground truth (axis = which of
X/Y/Z value-set the value belongs to), then test which BYTE feature predicts the
axis. The rule found here must be the SAME rule that decodes production.
GT (DXF) is used for LABELLING/SCORING only — never fed to the decoder."""
import sys, struct
sys.path.insert(0, 'python')
from oot_parser_v2 import parse_coord_elements, group_coord_elements
from collections import Counter, defaultdict

def coord_region(raw):
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

def dxf_axes(path):
    lines=open(path,'r',errors='ignore').read().split('\n')
    xs,ys,zs=set(),set(),set()
    i=0
    while i<len(lines)-1:
        code=lines[i].strip(); val=lines[i+1].strip()
        try:
            c=int(code); f=float(val)
            if abs(f)<1e7:
                if c in (10,11,12,13): xs.add(round(f,2))
                elif c in (20,21,22,23): ys.add(round(f,2))
                elif c in (30,31,32,33): zs.add(round(f,2))
        except: pass
        i+=2
    return [xs,ys,zs]

def label_axis(v, axes, tol=0.05):
    hits=[a for a in range(3) if any(abs(v-g)<tol for g in axes[a])]
    return hits[0] if len(hits)==1 else (-1 if not hits else -2)  # -2 = ambiguous(overlap)

oot=sys.argv[1]; dxf=sys.argv[2]
raw=open(oot,'rb').read()
region,is_new=coord_region(raw)
groups=group_coord_elements(parse_coord_elements(region,new_format=is_new))
axes=dxf_axes(dxf)
print(f'{oot}: {len(groups)} coord groups | DXF unique X={len(axes[0])} Y={len(axes[1])} Z={len(axes[2])}')
print(f'  X range {min(axes[0]):.1f}..{max(axes[0]):.1f}  Y {min(axes[1]):.1f}..{max(axes[1]):.1f}  Z {min(axes[2]):.1f}..{max(axes[2]):.1f}')
# label
labels=[label_axis(g.value,axes) for g in groups]
lc=Counter(labels)
print(f'  labels: clean={sum(1 for l in labels if l>=0)} ambiguous(overlap)={lc[-2]} none={lc[-1]}')

# feature extraction per group
def feats(i,g):
    ft = g.tags[0] if g.tags else None
    return {
        'firstTagCls': ft.cls if ft else 'none',
        'firstLoNib': ft.lo_nib if ft else -1,
        'firstHiNib': ft.hi_nib if ft else -1,
        'firstByte2': ft.byte2 if ft else -1,
        'lastSep': (g.seps[-1] if g.seps else -1),
        'kind': g.kind,
        'nb': g.n_bytes,
    }

# cross-tab each feature vs TRUE axis (clean labels only)
from collections import defaultdict
def crosstab(name):
    tab=defaultdict(lambda:[0,0,0])
    for i,(g,l) in enumerate(zip(groups,labels)):
        if l<0: continue
        tab[feats(i,g)[name]][l]+=1
    return tab
for name in ['firstTagCls','firstLoNib','firstHiNib','lastSep','kind']:
    tab=crosstab(name)
    print(f'\n  feature {name} -> [X,Y,Z] (clean-labelled groups):')
    for k in sorted(tab, key=lambda x:str(x)):
        xyz=tab[k]; tot=sum(xyz); pur=max(xyz)/tot*100 if tot else 0
        flag=' <== PURE' if pur>=95 and tot>=3 else ''
        print(f'    {str(k):>10}: {xyz}  ({pur:.0f}% pure, n={tot}){flag}')
