"""HONEST accounting of the faces decode. Separate the two numbers I conflated:
  (a) connectivity accuracy WHERE checkable, and
  (b) coverage as a fraction of the full 5724-face mesh.
"""
import json
import numpy as np

df = json.load(open('decoded_faces.json'))
tris = df['tris']; good = np.array(df['good']); scor = np.array(df['scor'])
F = np.load('faces_gt.npy')
NF = len(F)

ntri = len(tris)
nscor = int(scor.sum())
ngood = int((good & scor).sum())
nwrong = int((~good.astype(bool) & scor.astype(bool)).sum())
nunscor = int((~scor.astype(bool)).sum())

print('FULL GT mesh faces:              %d' % NF)
print('Decoded triangles emitted:       %d  (%.1f%% of mesh by count)' % (ntri, 100*ntri/NF))
print('  scorable (3 slots mapped):     %d' % nscor)
print('    correct connectivity:        %d  (green)' % ngood)
print('    wrong connectivity:          %d  (red)' % nwrong)
print('  unscorable (unmapped slot):    %d  (grey/hidden)' % nunscor)
print()
print('(a) accuracy WHERE CHECKABLE:    %d/%d = %.1f%%' % (ngood, nscor, 100*ngood/nscor))
print('(b) correct faces / FULL mesh:   %d/%d = %.1f%%  <-- honest "how much decoded"'
      % (ngood, NF, 100*ngood/NF))
print('    (and that ignores duplicates: distinct GT faces hit below)')

# distinct GT faces actually hit (dedup) -- true coverage
import pickle
map11, _ = pickle.load(open('map11.pkl', 'rb'))
faceset = {}
for i, f in enumerate(F):
    faceset[tuple(sorted(f))] = i
hit = set()
for t, g in zip(tris, good):
    if not g:
        continue
    gs = tuple(sorted(map11[s] for s in t))
    if gs in faceset:
        hit.add(faceset[gs])
print('    distinct GT faces correctly emitted: %d/%d = %.1f%%'
      % (len(hit), NF, 100*len(hit)/NF))
