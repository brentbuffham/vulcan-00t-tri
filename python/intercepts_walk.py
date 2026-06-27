#!/usr/bin/env python3
"""Walker v4: PROPER variable-length framing [tag?][sep][count][payload(count+1)].
tag = 0x2x (not a sep); sep has (b&7)==7; count in 0..6 -> payload = count+1 bytes,
spliced onto the high (8-(count+1)) bytes of prev same-axis. FULL = 8 double bytes
(40/41/C0/C1). Record length is 3+count+1 (with tag) or 2+count+1 (no tag), which
explains the 7- and 15-byte gaps. Axis of a delta = the missing vertex slot whose
splice lands nearest its prev (NOT min over splice-length -> not the degenerate cheat).
Neighbour jump is a VALIDATOR: report the jump distribution and every outlier."""
import sys, struct
import numpy as np
from collections import Counter
f=sys.argv[1] if len(sys.argv)>1 else r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
THRESH=float(sys.argv[2]) if len(sys.argv)>2 else 25.0
out=sys.argv[3] if len(sys.argv)>3 else None
d=open(f,'rb').read()
hdr=struct.unpack('<15i',d[0:60]); geo_end=hdr[11] if 8352<hdr[11]<=len(d) else len(d)
# coord section ENDS where the e0 03 face block begins (faces are not coords!)
face_start=next((i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03), geo_end)
geo_end=min(geo_end, face_start)
print(f'coord section: 8326 .. {geo_end} (face block starts @{face_start})')
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def full_here(o):
    if o+8>geo_end or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
def is_sep(b): return (b&7)==7
def is_tag(b): return b in (0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f)
pos=8326; prevb=[None,None,None]; prevv=[None,None,None]
filled={}; verts=[]; nfull=ndelta=nesc=0; jumps=[]; fails=[]; lens=Counter()
def flush():
    global filled
    if len(filled)==3: verts.append((filled[0],filled[1],filled[2]))
    filled={}
while pos < geo_end-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); ax=band(v)
        if ax in filled: flush()
        filled[ax]=v; prevb[ax]=d[pos:pos+8]; prevv[ax]=v; nfull+=1; pos+=8
        if len(filled)==3: flush()
        continue
    # delta? parse [tag?][sep][count][payload]
    p=pos
    if is_tag(d[p]) and p+1<geo_end and is_sep(d[p+1]): p+=1   # consume tag
    if p<geo_end and is_sep(d[p]) and p+1<geo_end:
        sep=d[p]; count=d[p+1]
        if count<=6 and p+2+count+1<=geo_end:
            nb=count+1; payload=d[p+2:p+2+nb]; rec_end=p+2+nb
            miss=[a for a in range(3) if a not in filled and prevb[a] is not None]
            cand=miss if miss else [a for a in range(3) if prevb[a] is not None]
            best=None
            for a in cand:
                newb=bytes(prevb[a][:8-nb])+payload
                val=be(newb); jp=abs(val-prevv[a])
                if best is None or jp<best[0]: best=(jp,a,val,newb)
            if best is not None:
                jp,a,val,newb=best; lens[rec_end-pos]+=1
                if jp>500.0:
                    # cascade guard: reject obviously-corrupt record (don't poison prev)
                    nesc+=1; pos=rec_end; continue
                ndelta+=1; jumps.append(jp)
                if jp>THRESH: fails.append((pos,d[pos:rec_end].hex(),a,prevv[a],val,jp))
                filled[a]=val; prevb[a]=newb; prevv[a]=val
                pos=rec_end
                if len(filled)==3: flush()
                continue
    nesc+=1; pos+=1
P=np.array(verts); J=np.array(jumps)
print(f'fulls={nfull:,} deltas={ndelta:,} escapes={nesc:,} vertices={len(P):,}')
print(f'record lengths: {dict(lens)}')
if len(J):
    print(f'delta neighbour-jump: median={np.median(J):.3f} p90={np.percentile(J,90):.2f} p99={np.percentile(J,99):.2f} max={J.max():.1f}')
    print(f'outliers >{THRESH}m: {len(fails):,} / {ndelta:,}')
for fp,fh,fa,pv,nv,jm in fails[:15]:
    print(f'  @{fp} ax{fa} rec={fh} prev={pv:.3f} new={nv:.3f} jump={jm:.1f}')
if len(P):
    print(f' bbox X[{P[:,0].min():.2f},{P[:,0].max():.2f}] Y[{P[:,1].min():.2f},{P[:,1].max():.2f}] Z[{P[:,2].min():.2f},{P[:,2].max():.2f}]')
    if out: np.savetxt(out,P,fmt='%.4f',delimiter=','); print(' wrote',out)
