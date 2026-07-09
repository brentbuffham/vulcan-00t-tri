#!/usr/bin/env python3
"""Phase 4: raw hex windows of the small-payload ref00 groups. Question: is
'00 xx' (xx<0x20) really a low-byte splice ref, or a mis-framed field (e.g.
'00 hh ll' 3-byte big-endian, or the xx belongs to the following record)?"""
import struct
RAW = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(RAW, 'rb').read()

# group positions from phase-3 (gi -> pos found by retokenizing quickly)
import pickle
groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))
targets = [87, 126, 176, 241, 2428, 2454, 2511, 3205, 3215, 3219, 3220,
           4193, 4210, 4228, 5189, 1152, 1316, 3787, 46]
for gi in targets:
    g = groups[gi]
    p = g['pos']
    nxtp = groups[gi+1]['pos'] if gi+1 < len(groups) else p+40
    hx = d[p:nxtp].hex()
    # split into spaced bytes
    sp = ' '.join(hx[i:i+2] for i in range(0, len(hx), 2))
    print(f'g{gi:<5d} pos={p} len={nxtp-p}  refs={g["refs"]}')
    print(f'   {sp}')
