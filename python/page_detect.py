#!/usr/bin/env python3
"""Detect fixed-size page framing across .00t files.

Hypothesis: the file is divided into fixed 2048-byte pages. Each page opens
with a 2-byte marker, the rest is payload (zero-filled when unused).
"""
import sys, os

files = sys.argv[1:] or [
    'tri-crack-solid', 'tri-crack-linear', 'tri-crack-prism',
    'tri-crack-fan', 'cube', 'tri-crack-BigGrid', 'tri-crack-SPHERE',
]

for stem in files:
    path = f'exampleFiles/{stem}.00t'
    if not os.path.exists(path):
        continue
    data = open(path, 'rb').read()
    n = len(data)
    # Find the first zero-run >= 1024 (start of the paged region)
    # then walk in 2048 strides reporting the 2-byte marker at each boundary.
    # Locate page0: scan for the first long zero run.
    first_big_zero = None
    i = 0
    while i < n:
        if data[i] == 0:
            j = i
            while j < n and data[j] == 0:
                j += 1
            if j - i >= 1024:
                first_big_zero = i
                break
            i = j
        else:
            i += 1
    print(f'== {stem} ==  size={n}  ({n/2048:.2f} pages)')
    if first_big_zero is None:
        print('  no large zero run found\n'); continue
    # marker sits 2 bytes before the zero run
    p = first_big_zero - 2
    print(f'  first page marker near offset {p}')
    # walk pages
    off = p
    pages = 0
    while off + 2 <= n and pages < 12:
        marker = data[off:off+2].hex()
        # how much of this 2048-page is zero?
        page = data[off+2:off+2048]
        nz = page.count(0)
        frac = nz / max(len(page), 1)
        print(f'   page {pages}: off={off:6d} marker={marker} zero={frac*100:5.1f}%')
        off += 2048
        pages += 1
    # is the paged region an exact multiple boundary?
    print(f'  bytes after first marker: {n - p}  (/2048 = {(n-p)/2048:.3f})\n')
