import struct, numpy as np
d = open(r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t', 'rb').read(); n = len(d)
occ = [i for i in range(8326, n - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = n
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90:
        face_start = occ[k]; break
def be(p): return struct.unpack('>d', d[p:p + 8])[0]
seeds = [abs(be(8326)), abs(be(8334)), abs(be(8342))]
print('seeds X/Y/Z:', [round(s, 2) for s in seeds])
# collect FULL-tagged doubles, assign to nearest seed by RATIO, gather min/max per axis
buckets = {0: [], 1: [], 2: []}
pos = 8350
while pos + 8 <= face_start:
    if d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = abs(be(pos))
        if np.isfinite(v) and v > 0:
            ratios = [max(v, s) / min(v, s) for s in seeds]
            a = int(np.argmin(ratios))
            if ratios[a] < 1.5:  # within 1.5x of a seed = plausibly that axis (GT-free)
                buckets[a].append(v)
    pos += 1
for a, name in enumerate('XYZ'):
    b = np.array(buckets[a])
    if len(b):
        print(f'{name}: n={len(b):4d}  file-derived range [{b.min():.2f} .. {b.max():.2f}]')
print('hardcoded:  X[50000..60000]  Y[160000..166000]  Z[500..1000]')
