#!/usr/bin/env python3
"""Verify the Kaitai findings on intercepts: seed@8326, geom_start@8366, DELTA =
'20 17'+6 bytes spliced low6 onto high2 of prev same-axis. Dump hex + decode seed +
first records, compare to user's V1=(657.526,55980.425,163004.546)."""
import struct
f=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(f,'rb').read()
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
print('raw 8320..8440:')
for o in range(8320,8440,16):
    print(f'  {o} (0x{o:04x}): '+' '.join(f'{b:02x}' for b in d[o:o+16]))
print('\nseed @8326 (3 BE doubles):')
for i,o in enumerate((8326,8334,8342)):
    print(f'  axis{i} @{o}: {be(d[o:o+8]):.4f}  bytes={d[o:o+8].hex()}')
# try delta: low6 onto high2 of prev. prev X = seed X bytes.
prevX=bytearray(d[8326:8334])
print('\nseed X bytes:',prevX.hex(),'=',be(prevX))
# scan from 8366, show records as [b0 b1 b2 ...]
print('\nrecords from 8366 (best-effort [tag sep cnt payload]):')
pos=8366
for k in range(14):
    tag=d[pos]; sep=d[pos+1]; cnt=d[pos+2]; nb=cnt+1
    pl=d[pos+3:pos+3+nb]
    print(f'  @{pos} tag={tag:02x} sep={sep:02x} cnt={cnt:02x} nb={nb} pl={pl.hex()}')
    pos+=3+nb
