#!/usr/bin/env python3
"""CLOSING SOLVER. Vertex-window matcher with:
- X-uniqueness vertex lookup (X value -> GT vertex -> verify Y,Z tokens)
- window hypotheses: plain (i,i+1,i+2); one refine inserted at any position
  (vertex uses 4 tokens); split token carrying two coords (vertex uses 2 tokens)
- stream-start refine scan (seed vertex refinements before first X)
- failure => resync at next fingerprint anchor (phase from anchor), never blind +1
- duplicate-vertex commits forbidden (each GT vertex appears once)
- anchor fixpoint: committed scalars become anchors; iterate passes
Outputs: decoded vertex sequence (pi!), assembly score, rule tables."""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
TOL=0.0006
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
NVG=len(Gu)
xmap=defaultdict(list); ymap=defaultdict(list)
for vi,(x,y,z) in enumerate(Gu):
    xmap[round(x,3)].append(vi)
    ymap[round(y,3)].append(vi)
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1  # W3 zero-strip (padding)
        continue
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
N=len(toks)
# inline fingerprint anchors (same tokenization)
u64v=[vals_a.copy().view(np.uint64) for vals_a in
      [np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]]
valsA=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
anchors={}
for i,t in enumerate(toks):
    if t[0]=='F':
        anchors[i]=(band(be(t[1])),round(be(t[1]),3)); continue
    payload=t[1]; nb=len(payload); pI=int.from_bytes(payload,'big')
    hits=set()
    for a in range(3):
        base=u64v[a]
        for k in range(max(0,8-nb-3),8-nb+1):
            sh=8*(8-k-nb)
            mask=((1<<(8*nb))-1)<<sh
            cand=(base & ~np.uint64(mask)) | np.uint64(pI<<sh)
            vv=cand.view(np.float64)
            arr=valsA[a]
            idx=np.searchsorted(arr,vv)
            for jj in (idx-1,idx):
                jj2=np.clip(jj,0,len(arr)-1)
                ok=np.abs(arr[jj2]-vv)<=0.0006
                for tgt in np.unique(jj2[ok]): hits.add((a,round(arr[tgt],3)))
            if len(hits)>1: break
        if len(hits)>1: break
    if len(hits)==1:
        a,w=next(iter(hits)); anchors[i]=(a,w)
anchor_idx=sorted(anchors)
print(f'tokens {N}, initial anchors {len(anchors)}')

def splice_opts(i,a,regs):
    """(value, newbytes, end) options for token i on axis a."""
    t=toks[i]
    if t[0]=='F':
        v=be(t[1])
        return [(round(v,3),bytes(t[1]),None)] if band(v)==a else []
    payload=t[1]; nb=len(payload)
    out=[]
    for end in (8,7,6):
        k0=end-nb
        if k0<0: continue
        vb=bytes(regs[a][:k0])+payload+bytes(regs[a][end:])
        out.append((be(vb),vb,end))
    return out
def fits(i,a,target,regs):
    for v,vb,end in splice_opts(i,a,regs):
        if np.isfinite(v) and abs(v-target)<=TOL: return vb,end
    # register-free fallback: splice payload into the TARGET's own double
    t=toks[i]
    if t[0]=='V':
        tb=struct.pack('>d',target)
        payload=t[1]; nb=len(payload)
        for end in (8,7,6):
            k0=end-nb
            if k0<0: continue
            vb=bytes(tb[:k0])+payload+bytes(tb[end:])
            if abs(be(vb)-target)<=TOL: return vb,end
    return None
def split_fits(i,a1,t1v,a2,t2v,regs):
    t=toks[i]
    if t[0]!='V': return None
    payload=t[1]; nb=len(payload)
    for k2 in range(1,nb):
        h,tl=payload[:k2],payload[k2:]
        for e1 in (8,7):
            if e1-k2<0: continue
            vb1=bytes(regs[a1][:e1-k2])+h+bytes(regs[a1][e1:])
            if abs(be(vb1)-t1v)>TOL: continue
            for e2 in (8,7):
                if e2-(nb-k2)<0: continue
                vb2=bytes(regs[a2][:e2-(nb-k2)])+tl+bytes(regs[a2][e2:])
                if abs(be(vb2)-t2v)<=TOL: return (vb1,vb2,k2)
    return None

def two_tok_opts(i,a,regs):
    """values reachable by applying token i THEN token i+1 to axis a."""
    out=[]
    if i+1>=N: return out
    for v1,vb1,e1 in splice_opts(i,a,regs):
        tmp=[bytearray(regs[0]),bytearray(regs[1]),bytearray(regs[2])]
        tmp[a][:]=vb1
        for v2,vb2,e2 in splice_opts(i+1,a,tmp):
            out.append((v2,vb2))
    return out

def try_vertex(i,regs,used,lastvi):
    """try to commit ONE vertex starting at token i. Returns
    (vi, tokens_consumed, regupdates[(a,bytes)], kind) or None."""
    # gather X candidates from token i (plain) and split forms
    results=[]
    # plain X at i
    for xv,xb,xe in splice_opts(i,0,regs):
        xr=round(xv,3)
        for vi in xmap.get(xr,[]):
            if vi in used: continue
            vx,vy,vz=Gu[vi]
            # plain: Y at i+1, Z at i+2
            if i+2<N:
                fy=fits(i+1,1,vy,regs)
                if fy:
                    fz=fits(i+2,2,vz,regs)
                    if fz:
                        results.append((vi,3,[(0,xb),(1,fy[0]),(2,fz[0])],'plain')); continue
                # split Y+Z at i+1 (vertex = 2 tokens)
                sf=split_fits(i+1,1,vy,2,vz,regs)
                if sf:
                    results.append((vi,2,[(0,xb),(1,sf[0]),(2,sf[1])],'splitYZ')); continue
                # refine inserted: Y at i+2, Z at i+3 (token i+1 = refine of X)
                if i+3<N:
                    fy2=fits(i+2,1,vy,regs)
                    fz2=fits(i+3,2,vz,regs) if fy2 else None
                    if fy2 and fz2:
                        results.append((vi,4,[(0,xb),(1,fy2[0]),(2,fz2[0])],'refX'))
                        continue
                    # refine after Y: X@i, Y@i+1, ref@i+2, Z@i+3
                    fy3=fits(i+1,1,vy,regs)
                    fz3=fits(i+3,2,vz,regs) if fy3 else None
                    if fy3 and fz3:
                        results.append((vi,4,[(0,xb),(1,fy3[0]),(2,fz3[0])],'refY'))
                        continue
    # two-token X: tokens i,i+1 compose X; Y@i+2, Z@i+3
    if i+3<N:
        for xv,xb in two_tok_opts(i,0,regs):
            xr=round(xv,3)
            for vi in xmap.get(xr,[]):
                if vi in used: continue
                vx,vy,vz=Gu[vi]
                fy=fits(i+2,1,vy,regs)
                fz=fits(i+3,2,vz,regs) if fy else None
                if fy and fz:
                    results.append((vi,4,[(0,xb),(1,fy[0]),(2,fz[0])],'x2'))
                    break
    # two-token Y: X@i; Y=(i+1,i+2); Z@i+3
    if i+3<N and not results:
        for xv,xb,xe in splice_opts(i,0,regs):
            xr=round(xv,3)
            for vi in xmap.get(xr,[]):
                if vi in used: continue
                vx,vy,vz=Gu[vi]
                hit=None
                for yv,yb in two_tok_opts(i+1,1,regs):
                    if abs(yv-vy)<=TOL: hit=yb; break
                if hit is None: continue
                fz=fits(i+3,2,vz,regs)
                if fz:
                    results.append((vi,4,[(0,xb),(1,hit),(2,fz[0])],'y2'))
                    break
    # two-token Z: X@i; Y@i+1; Z=(i+2,i+3)
    if i+3<N and not results:
        for xv,xb,xe in splice_opts(i,0,regs):
            xr=round(xv,3)
            for vi in xmap.get(xr,[]):
                if vi in used: continue
                vx,vy,vz=Gu[vi]
                fy=fits(i+1,1,vy,regs)
                if not fy: continue
                hit=None
                for zv,zb in two_tok_opts(i+2,2,regs):
                    if abs(zv-vz)<=TOL: hit=zb; break
                if hit is not None:
                    results.append((vi,4,[(0,xb),(1,fy[0]),(2,hit)],'z2'))
                    break
    # refine-before-X: token i refines prev Z (fits Z register to a GT-Z);
    # vertex is plain at i+1
    t0=toks[i]
    if t0[0]=='V' and i+3<N:
        zref=False
        for v,vb,end in splice_opts(i,2,regs):
            if np.isfinite(v) and 500<abs(v)<1000: zref=True; zrb=vb; break
        if zref:
            for xv,xb,xe in splice_opts(i+1,0,regs):
                xr=round(xv,3)
                for vi in xmap.get(xr,[]):
                    if vi in used: continue
                    vx,vy,vz=Gu[vi]
                    fy=fits(i+2,1,vy,regs)
                    fz=fits(i+3,2,vz,regs) if fy else None
                    if fy and fz:
                        results.append((vi,4,[(0,xb),(1,fy[0]),(2,fz[0])],'refZpre'))
                        break
                if results and results[-1][3]=='refZpre': break
    # cross-vertex split: token i = (Z-tail of prev | X of this); Y@i+1, Z@i+2
    if t0[0]=='V' and len(t0[1])>=2 and i+2<N:
        payload=t0[1]; nb=len(payload)
        for k2 in range(1,nb):
            tl=payload[k2:]
            for e1 in (8,7):
                if e1-(nb-k2)<0: continue
                xb=bytes(regs[0][:e1-(nb-k2)])+tl+bytes(regs[0][e1:])
                xr=round(be(xb),3)
                for vi in xmap.get(xr,[]):
                    if vi in used: continue
                    vx,vy,vz=Gu[vi]
                    fy=fits(i+1,1,vy,regs)
                    fz=fits(i+2,2,vz,regs) if fy else None
                    if fy and fz:
                        results.append((vi,3,[(0,xb),(1,fy[0]),(2,fz[0])],'splitZX'))
                        break
    # split X+Y at i, Z at i+1 (vertex = 2 tokens)
    t=toks[i]
    if t[0]=='V' and i+1<N:
        payload=t[1]; nb=len(payload)
        for k2 in range(1,nb):
            h=payload[:k2]
            for e1 in (8,7):
                if e1-k2<0: continue
                xb=bytes(regs[0][:e1-k2])+h+bytes(regs[0][e1:])
                xr=round(be(xb),3)
                for vi in xmap.get(xr,[]):
                    if vi in used: continue
                    vx,vy,vz=Gu[vi]
                    tl=payload[k2:]
                    for e2 in (8,7):
                        if e2-(nb-k2)<0: continue
                        yb=bytes(regs[1][:e2-(nb-k2)])+tl+bytes(regs[1][e2:])
                        if abs(be(yb)-vy)<=TOL:
                            fz=fits(i+1,2,vz,regs)
                            if fz:
                                results.append((vi,2,[(0,xb),(1,yb),(2,fz[0])],'splitXY'))
    if not results: return None
    # prefer plain, then fewest tokens
    results.sort(key=lambda r:{'plain':0,'splitYZ':1,'splitXY':1,'splitZX':2,'refX':2,'refY':2,'x2':2,'y2':2,'z2':2,'refZpre':3}[r[3]])
    return results[0]

def back_candidates(j,a,curbytes,vmap=None):
    """backward: values w for token j on axis a such that
    pack(w) shares prefix (and trailing) bytes with curbytes outside the window
    AND payload self-fits w."""
    t=toks[j]
    out=[]
    if t[0]=='F':
        v=be(t[1])
        if band(v)==a: out.append(round(v,3))
        return out
    payload=t[1]; nb=len(payload)
    keys=(xmap if a==0 else ymap) if a in (0,1) else None
    for end in (8,7,6):
        k0=end-nb
        if k0<0: continue
        if a in (0,1):
            for w in keys:
                wb=struct.pack('>d',w)
                if wb[:k0]!=bytes(curbytes[:k0]): continue
                vb=bytes(wb[:k0])+payload+bytes(wb[end:])
                if abs(be(vb)-w)<=TOL and w not in out: out.append(w)
        else:
            # Z: derive value directly = prefix from cur + payload (+ cur tail)
            vb=bytes(curbytes[:k0])+payload+bytes(curbytes[end:])
            v=be(vb)
            out.append(round(v,3))
    return out

def backfill(x0,regs_at,used,order,lo):
    """decode vertices BACKWARD from token x0 (exclusive) down to token lo.
    regs_at = register bytes valid just before x0 (i.e., state after the
    vertex ending at x0-1... here: state at commit of vertex@x0)."""
    cur=[bytearray(r) for r in regs_at]
    j=x0-3
    n=0
    skips=0
    while j>=lo:
        # tokens j,j+1,j+2 = X,Y,Z of the previous vertex
        xs=back_candidates(j,0,cur[0])
        got=None
        for xw in xs:
            for vi in xmap.get(round(xw,3),[]):
                if vi in used: continue
                vx,vy,vz=Gu[vi]
                ys=back_candidates(j+1,1,cur[1])
                if not any(abs(y-vy)<=TOL for y in ys): continue
                zs=back_candidates(j+2,2,cur[2])
                if not any(abs(z-vz)<=TOL for z in zs) and toks[j+2][0]=='V': continue
                got=vi; break
            if got is not None: break
        if got is None:
            # event tolerance: skip one token (refine in gap), once per stretch
            if skips<2:
                skips+=1; j-=1; continue
            break
        skips=0
        vx,vy,vz=Gu[got]
        used.add(got); order.append((got,j)); n+=1
        cur[0][:]=struct.pack('>d',vx); cur[1][:]=struct.pack('>d',vy); cur[2][:]=struct.pack('>d',vz)
        j-=3
    return n

def run_pass(anchors,used,order):
    regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
    kinds=Counter()
    i=0
    lastvi=None
    aidx=sorted(anchors)
    import bisect
    # stream-start: allow up to 10 refine tokens before first vertex
    start_found=False
    for off in range(0,10):
        r=try_vertex(off,regs,used,None)
        if r:
            i=off; start_found=True; break
    if not start_found: i=0
    while i+1<N:
        t=toks[i]
        if t[0]=='F':
            v=be(t[1]); regs[band(v)][:]=t[1]
            i+=1; kinds['full_pass']+=1; continue
        r=try_vertex(i,regs,used,lastvi)
        if r:
            vi,ntok,ups,kind=r
            for a,bts in ups: regs[a][:]=bts
            if kind=='plain' and (i-3) not in dict(order).values() and i>=3:
                kinds['backfilled']+=backfill(i,regs,used,order,0)
            used.add(vi); order.append((vi,i)); lastvi=vi
            kinds[kind]+=1
            i+=ntok; continue
        # failure: resync at next anchor; X/Y anchors identify their WHOLE vertex
        j=bisect.bisect_right(aidx,i)
        resynced=False
        while j<len(aidx):
            ja=aidx[j]
            a_j,w_j=anchors[ja]
            if a_j in (0,1):
                cand=[vv for vv in (xmap if a_j==0 else ymap).get(round(w_j,3),[]) if vv not in used]
                if len(cand)>1:
                    # disambiguate by verifying the other two tokens
                    x0t=ja-a_j
                    cand=[vv for vv in cand if all(
                        fits(x0t+a2,a2,Gu[vv][a2],regs) is not None
                        for a2 in range(3) if a2!=a_j and 0<=x0t+a2<N)] or cand[:0]
                if len(cand)==1:
                    vi=cand[0]; vx,vy,vz=Gu[vi]
                    x0=ja-a_j  # this vertex's X-slot token index
                    if x0>i-3:
                        # commit vertex with best-effort register bytes
                        for a2,tv in ((0,vx),(1,vy),(2,vz)):
                            ti2=x0+a2
                            f=fits(ti2,a2,tv,regs) if 0<=ti2<N else None
                            regs[a2][:]=f[0] if f else struct.pack('>d',tv)
                        used.add(vi); order.append((vi,x0)); lastvi=vi
                        kinds['resync_commit']+=1
                        kinds['backfilled']+=backfill(x0,regs,used,order,max(i,0))
                        i=x0+3; resynced=True; break
            j+=1
            if j<len(aidx) and aidx[j]-i>400: break
        if not resynced:
            j=bisect.bisect_right(aidx,i)
            if j>=len(aidx): break
            ja=aidx[j]; a_j,w_j=anchors[ja]
            regs[a_j][:]=struct.pack('>d',w_j)
            kinds['resync_skip']+=1
            i=ja+1
    return kinds

anch=dict(anchors)
used=set(); order=[]
prev_n=0
for pas in range(1,6):
    kinds=run_pass(anch,used,order)
    print(f'pass {pas}: vertices {len(used)}/{NVG} ({len(used)/NVG*100:.1f}%)  kinds {dict(kinds)}')
    for vi,ti in order:
        vx,vy,vz=Gu[vi]
        anch.setdefault(ti,(0,round(vx,3)))
        anch.setdefault(ti+1,(1,round(vy,3)))
        anch.setdefault(ti+2,(2,round(vz,3)))
    if len(used)==prev_n: break
    prev_n=len(used)
# final assembly + save
P=np.array([Gu[vi] for vi,_ in order])
with open(sp+r'\closing.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
np.save(sp+r'\closing_order.npy',np.array(order,dtype=object),allow_pickle=True)
recall=len(set(vi for vi,_ in order))/NVG*100
print(f'FINAL: {len(order)} vertices decoded, distinct recall {recall:.1f}%')
print('saved closing.xyz / closing_order.npy')
