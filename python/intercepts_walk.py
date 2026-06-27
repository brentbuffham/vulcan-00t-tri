#!/usr/bin/env python3
"""Walker v2 for FULL-heavy 'old format' (intercepts). KEY: coords are 8-byte units
(gaps between fulls are multiples of 8). Each unit = FULL (8 raw double bytes, first
byte 40/41/C0/C1) OR DELTA ([tag?][sep][count][payload], 8 bytes; sep has (b&7)==7).
Lone escape bytes break 8-alignment -> detect & skip 1 to re-align. FULL axis = band;
DELTA fills the missing slot. Validate by band-consistency + bbox (no GT)."""
import sys, struct
import numpy as np
f=sys.argv[1] if len(sys.argv)>1 else r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
out=sys.argv[2] if len(sys.argv)>2 else None
d=open(f,'rb').read()
hdr=struct.unpack('<15i',d[0:60]); geo_end=hdr[11] if 8352<hdr[11]<=len(d) else len(d)
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v)
    return 2 if a<5000 else (0 if a<100000 else 1)
def full_here(o):
    if o+8>geo_end or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
def delta_here(o):
    b=d[o]; return b==0x20 or b==0x21 or (b&7)==7
pos=8326; prev=[None,None,None]; filled={}; verts=[]; nfull=ndelta=nesc=0
def flush():
    global filled
    if len(filled)==3: verts.append((filled[0],filled[1],filled[2]))
    filled={}
while pos < geo_end-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); ax=band(v)
        if ax in filled: flush()
        filled[ax]=v; prev[ax]=d[pos:pos+8]; nfull+=1; pos+=8
        if len(filled)==3: flush()
    elif delta_here(pos) and pos+8<=geo_end:
        unit=d[pos:pos+8]; ndelta+=1
        miss=[a for a in range(3) if a not in filled]
        ax=miss[0] if miss else band(be(unit))
        pv=prev[ax]
        # best-effort: splice last 5 payload bytes onto high 3 of prev (refine w/ GT)
        if pv is not None:
            newb=bytes(pv[:3])+unit[3:8]
            filled[ax]=be(newb); prev[ax]=newb
        pos+=8
        if len(filled)==3: flush()
    else:
        nesc+=1; pos+=1
P=np.array(verts)
print(f'fulls={nfull:,} deltas={ndelta:,} escapes={nesc:,}  vertices={len(P):,}')
if len(P):
    okx=np.mean((np.abs(P[:,0])>5000)&(np.abs(P[:,0])<100000))*100
    oky=np.mean(np.abs(P[:,1])>=100000)*100
    okz=np.mean(np.abs(P[:,2])<5000)*100
    print(f' band-consistency  X={okx:.1f}%  Y={oky:.1f}%  Z={okz:.1f}%')
    print(f' bbox X[{P[:,0].min():.2f},{P[:,0].max():.2f}] Y[{P[:,1].min():.2f},{P[:,1].max():.2f}] Z[{P[:,2].min():.2f},{P[:,2].max():.2f}]')
    for v in P[:6]: print(f'   {v[0]:.3f} {v[1]:.3f} {v[2]:.3f}')
    if out: np.savetxt(out,P,fmt='%.4f',delimiter=','); print(' wrote',out)
