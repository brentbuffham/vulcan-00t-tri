#!/usr/bin/env python3
"""Build a set of ground-truth vertex keys (x,y,z rounded to 0.01, packed)
so the decoder can measure recall/precision."""
import sys, pickle
csv=sys.argv[1]; out=sys.argv[2]
S=set()
with open(csv,'rb') as f:
    buf=b''
    while True:
        ch=f.read(1<<22)
        if not ch: break
        buf=(buf+ch).replace(b'\r',b'\n'); parts=buf.split(b'\n'); buf=parts.pop()
        for line in parts:
            if not line: continue
            try:
                a,b,c=line.split(b','); x=float(a); y=float(b); z=float(c)
            except Exception: continue
            S.add((round(x*100), round(y*100), round(z*100)))
with open(out,'wb') as f: pickle.dump(S,f,protocol=4)
print(f'GT vertex keys: {len(S):,}  -> {out}')
