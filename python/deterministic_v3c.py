#!/usr/bin/env python3
"""DETERMINISTIC v3c — SOLE PARSER (no ground truth in the decode loop).
v3b + FRAMING FIX: FULL-precedence tokenizer.
  precedence at each position:
    1. sane 8-byte FULL                     -> FULL
    2. byte>=0x20 & sane FULL at pos+1      -> escape byte + FULL (W11-13 at scale)
    3. p<0x20                               -> V-token, nb=(p&7)+1, but payload is
       TRUNCATED if a sane FULL starts inside it (W5 sane-sequel)
    4. 0xE0..0xFF                           -> E-token (3 bytes)
    5. else                                 -> T-token (2 bytes)
decode: strict cycle, every V advances +1; FULL occupies its band slot and sets
phase=band+1; k0 from T1 formula; noT -> k0 by nb default (4->3, 5->3, 6->2).
GT used ONLY for scoring at the end."""
import struct
import numpy as np
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
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
def full_at(pos):
    if pos+8<=face_start and d[pos] in (0x40,0x41,0xC0,0xC1):
        v=be(d[pos:pos+8])
        if sane(v): return v
    return None
toks=[];pos=8350;lastT=None
nesc=0;ntrunc=0
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    v=full_at(pos)
    if v is not None:
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        nesc+=1; lastT=None; pos+=1; continue  # escape byte; FULL next loop
    if b<0x20:
        nb=(b&7)+1
        # truncate payload if a sane FULL starts inside it
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None:
                end=j; ntrunc+=1; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b)); lastT=None; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
N=len(toks)
nf=sum(1 for t in toks if t[0]=='F')
print(f'tokens {N} (FULLs {nf}, escapes {nesc}, truncated payloads {ntrunc})')
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,8-nb if nb<8 else 0)
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
ph=0
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
stats={'full':0,'delta':0,'oob':0,'skip':0}
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]
        if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        ph=(a+1)%3; stats['full']+=1; continue
    payload=t[1]; nb=len(payload)
    if nb==0: stats['skip']+=1; continue
    a=ph
    k0=k0_rule(t[2],nb)
    end=k0+nb
    if end>8: k0=max(0,8-nb); end=k0+nb
    vb=bytes(regs[a][:k0])+payload+bytes(regs[a][end:])
    v=be(vb)
    if not np.isfinite(v) or band(v)!=a:
        alt=5-k0
        e2=alt+nb
        if 0<=alt and e2<=8:
            vb2=bytes(regs[a][:alt])+payload+bytes(regs[a][e2:])
            if np.isfinite(be(vb2)) and band(be(vb2))==a:
                vb=vb2
            else: stats['oob']+=1
        else: stats['oob']+=1
    regs[a][:]=vb
    stats['delta']+=1
    if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
    ph=(ph+1)%3
print('stats',stats)
P=np.array(pts)
from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
tree=cKDTree(Gu)
dist,_=tree.query(P)
print(f'v3c GT-FREE decode: {len(P)} vertices (GT {len(Gu)})')
for tol in (0.002,0.01,0.1,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(sp+r'\det_v3c.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote det_v3c.xyz')
