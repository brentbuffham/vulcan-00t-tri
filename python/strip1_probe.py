"""Probe refs_v2.pkl structure for strip re-clustering (RESUME-2026-07-11 step 1)."""
import pickle, collections

d = pickle.load(open('refs_v2.pkl', 'rb'))
print(type(d))
if isinstance(d, dict):
    for k, v in d.items():
        try:
            print(k, type(v).__name__, 'len', len(v))
        except TypeError:
            print(k, type(v).__name__, repr(v)[:100])
    # peek first items of each
    for k, v in d.items():
        try:
            it = list(v)[:5] if not isinstance(v, dict) else list(v.items())[:5]
            print('  peek', k, ':', it)
        except Exception as e:
            pass
elif isinstance(d, list):
    print('list len', len(d))
    for x in d[:10]:
        print(' ', x)
