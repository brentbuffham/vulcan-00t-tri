#!/usr/bin/env python3
"""Annotated dump of the first ~60 tokens for hand-decoding:
offset, raw bytes, tokenizer parse, answer-key (axis, value), GT vertex id.
Also the GT values of the first 20 vertices in emission order (closing_order)."""
import struct, json
import numpy as np
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(oot,'rb').read()
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
# old tokenizer with positions
toks=[];pos=8350;lastT=None;lastTpos=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None,pos)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b,pos)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
L=json.load(open(sp+r'\commit_labels.json'))
lab={l['tok']:l for l in L}
order=np.load(sp+r'\closing_order.npy',allow_pickle=True)
G=np.loadtxt(sp+r'\intercepts_gt.csv',delimiter=',')
Gu=np.unique(G,axis=0)
o=sorted([(ti,vi) for vi,ti in order],key=lambda x:x[0])
print('first 20 vertices (tokidx, vid, X, Y, Z):')
for ti,vi in o[:20]:
    x,y,z=Gu[vi]
    print(f'  tok{ti:<4} v{vi:<5} {x:.3f} {y:.3f} {z:.3f}')
print('\nseeds:')
for a,off in ((0,8326),(1,8334),(2,8342)):
    print(f'  {"XYZ"[a]} {d[off:off+8].hex()} = {be(d[off:off+8]):.6f}')
print('\ntokens 0..59:')
for i,t in enumerate(toks[:60]):
    l=lab.get(i)
    ann=''
    if l:
        ann=f'ax{l["axis"]} {l["role"]}/{l["flag"]}'
        if l.get('fb'): ann+=f' -> {be(bytes.fromhex(l["fb"])):.4f}'
    if t[0]=='F':
        print(f'tok{i:<3} @{t[4]} FULL {bytes(t[1]).hex()} = {be(t[1]):.4f}  T={t[2]}  {ann}')
    else:
        T=t[2]
        Ts=f'{T[0]:02x}{T[1]:02x}' if T else '----'
        print(f'tok{i:<3} @{t[4]} V p={t[3]:02x} T={Ts} pay={bytes(t[1]).hex():<16} {ann}')
# raw bytes 8350..8560 for reference
print('\nraw:')
for off in range(8350,8570,16):
    print(f'{off:6d}: {d[off:off+16].hex(" ")}')
