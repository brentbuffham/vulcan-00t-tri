#!/usr/bin/env python3
"""Dump the first N coord records with TAG/SEP/COUNT/payload so we can SEE the
per-vertex structure (is it [0x20][0x20][0x60]? variable? where do vertices break?).
For each record show the spliced value if applied to X, Y, or Z (band tells which
axis it 'fits'), plus the delta from each axis's current value (continuity hint)."""
import sys, struct
oot=sys.argv[1]; N=int(sys.argv[2]) if len(sys.argv)>2 else 60
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read()
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
print(f'seed  X={cur[0]:.3f} Y={cur[1]:.3f} Z={cur[2]:.3f}')
pos=8328+24; last_tag=None; pending_seps=[]; cnt=0
while pos<len(d) and cnt<N:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        kind='FULL' if (payload and payload[0] in FULL_IND) else 'DELTA'
        # candidate values per axis
        if kind=='FULL':
            vx=be(payload+b'\x00'*(8-nb)); vy=vx; vz=vx
        else:
            vx=be(bytes(prev[0][:8-nb])+payload); vy=be(bytes(prev[1][:8-nb])+payload); vz=be(bytes(prev[2][:8-nb])+payload)
        tg=f'{last_tag:02x}' if last_tag is not None else '--'
        seps=' '.join(f'{s:02x}' for s in pending_seps) or '-'
        # which axis does each candidate fall near (band)?
        bx='X' if 60340<vx<60825 else '.'
        by='Y' if 213950<vy<214690 else '.'
        bz='Z' if 512<vz<542 else '.'
        print(f'[{cnt:3d}] @{pos} tag={tg} sep=[{seps}] nb={nb} pl={payload.hex()} {kind:5s} '
              f'| X={vx:11.3f}{bx} Y={vy:12.3f}{by} Z={vz:9.3f}{bz}')
        pending_seps=[]; cnt+=1; pos=npos
    elif is_sep(b): pending_seps.append(b); pos+=1
    elif (b&0xE0) in TAG_CLASSES: last_tag=b; pos+=1
    else: pos+=1
