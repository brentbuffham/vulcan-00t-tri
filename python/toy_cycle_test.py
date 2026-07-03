#!/usr/bin/env python3
"""Retest ALL toy files under the new production model:
unified tokenizer (prefix p<0x20 -> nb=(p&7)+1; FULL = literal 8B double;
zero-strip; T=2B; E=3B), strict X->Y->Z cycle, placement ends {8,7,6}.
Per toy: token accounting vs 3*NV (does one-token-per-scalar hold, or does
toy DEDUP break it?), then vertex-chain decode (X-uniqueness lookup) recall."""
import glob, os, struct
import numpy as np
from collections import defaultdict, Counter
TOL=0.0006
def parse_dxf(p):
    lines=open(p,'r',errors='ignore').read().split('\n')
    i=0;n=len(lines);cur={};in3d=False;vs=set()
    def fnum(s):
        try: return float(s)
        except: return None
    def flush():
        if len(cur)>=9:
            for k in range(3):
                vs.add((round(cur[(k,0)],3),round(cur[(k,1)],3),round(cur[(k,2)],3)))
    while i<n-1:
        code=lines[i].strip(); val=lines[i+1].strip() if i+1<n else ''
        if code=='0':
            if in3d: flush()
            in3d=(val.upper()=='3DFACE'); cur={}
        elif in3d:
            c=fnum(code); f=fnum(val)
            if c is not None and f is not None and abs(f)<1e8:
                ci=int(c)
                for k in range(4):
                    if ci==10+k: cur[(k,0)]=f
                    elif ci==20+k: cur[(k,1)]=f
                    elif ci==30+k: cur[(k,2)]=f
        i+=2
    if in3d: flush()
    return np.array(sorted(vs))
def be(b): return struct.unpack('>d',bytes(b))[0]
def decode_toy(oot,Gu):
    d=open(oot,'rb').read()
    if len(d)<8350: return None
    lo=[Gu[:,a].min() for a in range(3)];hi=[Gu[:,a].max() for a in range(3)]
    def band(v):
        # nearest axis range (toys: ranges may overlap -> band by closest range)
        best=-1;bd=1e18
        for a in range(3):
            if lo[a]-1<=v<=hi[a]+1:
                c=0.0
            else:
                c=min(abs(v-lo[a]),abs(v-hi[a]))
            if c<bd: bd=c;best=a
        return best if bd<1e6 else -1
    def sane(v):
        return np.isfinite(v) and any(lo[a]-1000<=v<=hi[a]+1000 for a in range(3))
    occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
    face_start=len(d)
    for k in range(len(occ)-3):
        if occ[k+3]-occ[k]<90: face_start=occ[k]; break
    toks=[];pos=8350
    while pos<face_start:
        b=d[pos]
        if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
            while pos<face_start and d[pos]==0: pos+=1
            continue
        if b in (0x40,0x41,0xC0,0xC1,0x3f,0xbf) and pos+8<=face_start and sane(be(d[pos:pos+8])):
            toks.append(('F',d[pos:pos+8])); pos+=8; continue
        if b<0x20 and pos+1+(b&7)+1<=face_start:
            nb=(b&7)+1
            toks.append(('V',d[pos+1:pos+1+nb])); pos+=1+nb; continue
        if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
        if b>=0x20 and pos+2<=face_start: pos+=2; continue
        pos+=1
    NV=len(Gu)
    nv=sum(1 for t in toks if t[0]=='V'); nf=sum(1 for t in toks if t[0]=='F')
    # vertex-chain
    xmap=defaultdict(list)
    for vi,(x,y,z) in enumerate(Gu): xmap[round(x,3)].append(vi)
    regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
    def opts(i,a):
        t=toks[i]
        if t[0]=='F':
            v=be(t[1]); return [(v,bytes(t[1]))]
        payload=t[1];nb=len(payload);out=[]
        for end in (8,7,6,5):
            k0=end-nb
            if k0<0: continue
            vb=bytes(regs[a][:k0])+payload+bytes(regs[a][end:])
            out.append((be(vb),vb))
        return out
    used=set();dec=0;i=0;N=len(toks)
    while i+2<N:
        got=None
        for xv,xb in opts(i,0):
            for vi in xmap.get(round(xv,3),[]):
                if vi in used: continue
                vx,vy,vz=Gu[vi]
                yb=next((vb for v,vb in opts(i+1,1) if abs(v-vy)<=TOL),None)
                if yb is None: continue
                zb=next((vb for v,vb in opts(i+2,2) if abs(v-vz)<=TOL),None)
                if zb is None: continue
                got=(vi,xb,yb,zb);break
            if got: break
        if got:
            vi,xb,yb,zb=got
            regs[0][:]=xb;regs[1][:]=yb;regs[2][:]=zb
            used.add(vi);dec+=1;i+=3
        else:
            i+=1
    return NV,nv,nf,len(used)
pairs=[]
for oot in sorted(glob.glob('exampleFiles/*.00t')):
    base=os.path.splitext(os.path.basename(oot))[0].lower()
    dxf=None
    for dx in glob.glob('exampleFiles/*.dxf'):
        if os.path.splitext(os.path.basename(dx))[0].lower().replace('big-grid','biggrid')==base.replace('biggrid','biggrid'):
            dxf=dx;break
    if not dxf:
        for dx in glob.glob('exampleFiles/*.dxf'):
            if os.path.splitext(os.path.basename(dx))[0].lower()==base: dxf=dx;break
    if dxf: pairs.append((oot,dxf))
print(f'{"file":36s} {"NV":>5s} {"Vtok":>5s} {"F":>3s} {"tok/3NV":>8s} {"chainRecall":>12s}')
for oot,dxf in pairs:
    try:
        Gu=parse_dxf(dxf)
        if len(Gu)==0: print(f'{os.path.basename(oot):36s}  (no GT verts)');continue
        r=decode_toy(oot,Gu)
        if r is None: print(f'{os.path.basename(oot):36s}  (file too small)');continue
        NV,nv,nf,rec=r
        print(f'{os.path.basename(oot):36s} {NV:5d} {nv:5d} {nf:3d} {(nv+nf+3)/(3*NV):8.2f} {rec:5d}/{NV} ({rec/NV*100:.0f}%)')
    except Exception as e:
        print(f'{os.path.basename(oot):36s}  ERROR {e}')
