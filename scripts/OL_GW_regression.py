"""
Regression harness for the agent loop.

Runs the parser on every file in exampleFiles/, computes vertex-match scores
against DXFs (where available) AND coverage against ground_truth.GT entries
(for cube1-3 + cube.00t).

Returns a structured result the agent can compare before/after.
"""
import sys, os, json
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'python'))

from OL_GW_ground_truth import GT, SOLVED_THRESHOLDS, coverage as gt_coverage  # noqa: E402


_DXF_CACHE = {}

def _load_dxf_vertices(dxf_path):
    """Lightweight DXF 3DFACE reader — returns list of unique (x, y, z) verts.
    Cached: DXF files don't change during a brute-force run, so read once."""
    if dxf_path in _DXF_CACHE:
        return _DXF_CACHE[dxf_path]
    if not Path(dxf_path).exists():
        _DXF_CACHE[dxf_path] = None
        return None
    try:
        import ezdxf
    except ImportError:
        _DXF_CACHE[dxf_path] = None
        return None
    doc = ezdxf.readfile(dxf_path)
    msp = doc.modelspace()
    seen = []
    for e in msp:
        if e.dxftype() == '3DFACE':
            for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2]:
                key = (round(p[0], 4), round(p[1], 4), round(p[2], 4))
                if key not in seen:
                    seen.append(key)
    _DXF_CACHE[dxf_path] = seen
    return seen


def _vertex_match(parsed, dxf, tol=1.0):
    """Count how many DXF verts are in parsed verts."""
    matched = 0
    for d in dxf:
        for v in parsed:
            if (abs(v[0] - d[0]) < tol and abs(v[1] - d[1]) < tol
                    and abs(v[2] - d[2]) < tol):
                matched += 1
                break
    return matched


def _value_match(parsed_verts, expected_corners, tol=1.5):
    """Count how many distinct expected coord VALUES (per axis) appear anywhere
    in the parsed verts. More sensitive than corner-tuple matching: if Y=157420
    appears in any vertex, that's a hit even if X/Z are wrong on that vertex."""
    if not expected_corners:
        return None, None
    expected_xs = sorted({c[0] for c in expected_corners})
    expected_ys = sorted({c[1] for c in expected_corners})
    expected_zs = sorted({c[2] for c in expected_corners})

    parsed_xs = {v[0] for v in parsed_verts}
    parsed_ys = {v[1] for v in parsed_verts}
    parsed_zs = {v[2] for v in parsed_verts}

    def hit_count(expected, parsed):
        return sum(1 for e in expected if any(abs(p - e) < tol for p in parsed))

    matched = (hit_count(expected_xs, parsed_xs)
               + hit_count(expected_ys, parsed_ys)
               + hit_count(expected_zs, parsed_zs))
    total = len(expected_xs) + len(expected_ys) + len(expected_zs)
    return matched, total


def run_full_regression() -> Dict[str, Any]:
    """Parse every example file and return a dict of {basename: scores}."""
    import oot_parser_v2 as P
    results = {}
    example_dir = Path(__file__).parent.parent / 'exampleFiles'
    for oot_path in sorted(example_dir.glob('*.00t')):
        name = oot_path.stem
        try:
            res = P.parse_oot_v2(str(oot_path))
        except Exception as e:
            results[name] = {
                'error': str(e),
                'verts': 0, 'faces': 0,
                'dxf_match': None, 'gt_coverage': None,
                'value_match': None, 'value_total': None,
                'header_verts': None, 'header_faces': None,
            }
            continue
        # DXF match
        dxf_match = None
        dxf_total = None
        # Try multiple casing variants for the DXF
        for dxf_name in [
            f'{name}.dxf',
            f'{name}.DXF',
            name.replace('SPHERE', 'Sphere') + '.dxf',
            name.replace('Hexhole', 'HexHole') + '.dxf',
            name.replace('L-SHAPE', 'L-Shape') + '.dxf',
            name.replace('BigGrid', 'big-grid') + '.dxf',
        ]:
            dxf_path = example_dir / dxf_name
            if dxf_path.exists():
                dxf_verts = _load_dxf_vertices(str(dxf_path))
                if dxf_verts is not None:
                    dxf_match = _vertex_match(res.vertices, dxf_verts)
                    dxf_total = len(dxf_verts)
                    break
        # Ground truth coverage (cubes/skyscraper)
        gt_cov = None
        value_match, value_total = None, None
        if name in GT and GT[name] is not None:
            gt_cov = gt_coverage(res.vertices, GT[name])
            value_match, value_total = _value_match(res.vertices, GT[name])
        results[name] = {
            'verts': len(res.vertices),
            'faces': len(res.faces),
            'header_verts': res.n_verts_header,
            'header_faces': res.n_faces_header,
            'dxf_match': dxf_match,
            'dxf_total': dxf_total,
            'gt_coverage': gt_cov,
            'gt_total': len(GT[name]) if name in GT and GT[name] else None,
            'value_match': value_match,
            'value_total': value_total,
        }
    return results


def is_regression(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Return regression info: any file whose tracked score DROPPED."""
    regressions = []
    for name in after:
        if name not in before:
            continue
        for metric in ('dxf_match', 'gt_coverage', 'value_match'):
            b = before[name].get(metric)
            a = after[name].get(metric)
            if b is not None and a is not None and a < b:
                regressions.append({
                    'file': name, 'metric': metric, 'before': b, 'after': a,
                })
    return regressions


def is_improvement(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Return improvement info: which scores increased."""
    improvements = []
    for name in after:
        if name not in before:
            continue
        for metric in ('dxf_match', 'gt_coverage', 'value_match'):
            b = before[name].get(metric)
            a = after[name].get(metric)
            if b is not None and a is not None and a > b:
                improvements.append({
                    'file': name, 'metric': metric, 'before': b, 'after': a,
                })
    return improvements


def summarize(scores: Dict[str, Any]) -> str:
    """Compact human-readable summary."""
    lines = []
    for name in sorted(scores):
        s = scores[name]
        if 'error' in s:
            lines.append(f'  {name}: ERROR {s["error"]}')
            continue
        dxf_str = f'dxf={s["dxf_match"]}/{s["dxf_total"]}' if s['dxf_match'] is not None else 'dxf=-'
        gt_str = f'gt={s["gt_coverage"]}/{s["gt_total"]}' if s['gt_coverage'] is not None else ''
        val_str = f'val={s["value_match"]}/{s["value_total"]}' if s.get('value_match') is not None else ''
        lines.append(f'  {name:35} {s["verts"]:4}v {s["faces"]:4}f  {dxf_str:12} {gt_str:8} {val_str}')
    return '\n'.join(lines)


if __name__ == '__main__':
    scores = run_full_regression()
    print(summarize(scores))
    print(f'\nJSON:\n{json.dumps(scores, indent=2)}')
