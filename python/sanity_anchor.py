#!/usr/bin/env python3
"""Find the REAL coordinate base. Scan 8240..8400 for IEEE-BE doubles in the X/Y/Z
bands (X~60k, Y~214k, Z~510-542). Report offsets. Then nearest-GT distance of the
seed triple. Tells us if 8328 seeds are vertex0 or a bbox corner / wrong offset."""
import sys, struct, pickle
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
gtv=np.array(list(GT),dtype=np.float64)/100.0
d=open(oot,'rb').read()
def beat(off): return struct.unpack('>d', d[off:off+8])[0]
def leat(off): return struct.unpack('<d', d[off:off+8])[0]
print('scan 8240..8400 for in-band IEEE doubles (BE and LE):')
for off in range(8240,8400):
    for tag,fn in (('BE',beat),('LE',leat)):
        try: v=fn(off)
        except: continue
        if 60300<v<60850 or 213900<v<214750 or 510<v<543:
            band='X' if v<61000 else ('Y' if v>213000 else 'Z')
            print(f'  @{off} {tag} = {v:.4f}  band~{band}')
# seed triple nearest GT
seed=np.array([beat(8328),beat(8336),beat(8344)])
print('\nseed(8328 BE) =',[round(x,4) for x in seed])
dist=np.sqrt(((gtv-seed)**2).sum(1)); i=dist.argmin()
print(f'  nearest GT vert = {gtv[i]}  dist={dist[i]:.5f}')
# also test: is there a GT vertex extremely close to a slightly different seed read?
for off3 in [(8328,8336,8344)]:
    pass
# How many GT verts within 1.0 of seed (is seed inside the cloud?)
print(f'  GT verts within 1.0m of seed: {(dist<1.0).sum()}')
print(f'  GT verts within 5.0m of seed: {(dist<5.0).sum()}')
