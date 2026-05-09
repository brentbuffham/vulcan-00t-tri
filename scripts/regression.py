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

from ground_truth import GT, SOLVED_THRESHOLDS, coverage as gt_coverage  # noqa: E402


def _load_dxf_vertices(dxf_path):
    """Lightweight DXF 3DFACE reader — returns list of unique (x, y, z) verts."""
    if not Path(dxf_path).exists():
        return None
    try:
        import ezdxf
    except ImportError:
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
        if name in GT and GT[name] is not None:
            gt_cov = gt_coverage(res.vertices, GT[name])
        results[name] = {
            'verts': len(res.vertices),
            'faces': len(res.faces),
            'header_verts': res.n_verts_header,
            'header_faces': res.n_faces_header,
            'dxf_match': dxf_match,
            'dxf_total': dxf_total,
            'gt_coverage': gt_cov,
            'gt_total': len(GT[name]) if name in GT and GT[name] else None,
        }
    return results


def is_regression(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Return regression info: which solved-file thresholds dropped."""
    regressions = []
    for name, threshold in SOLVED_THRESHOLDS.items():
        if name not in before or name not in after:
            continue
        before_score = before[name].get('dxf_match')
        after_score = after[name].get('dxf_match')
        if after_score is not None and after_score < threshold:
            regressions.append({
                'file': name,
                'threshold': threshold,
                'before': before_score,
                'after': after_score,
            })
    return regressions


def is_improvement(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Return improvement info: which scores increased."""
    improvements = []
    for name in after:
        if name not in before:
            continue
        # DXF match improvement
        before_dxf = before[name].get('dxf_match')
        after_dxf = after[name].get('dxf_match')
        if before_dxf is not None and after_dxf is not None and after_dxf > before_dxf:
            improvements.append({'file': name, 'metric': 'dxf_match', 'before': before_dxf, 'after': after_dxf})
        # GT coverage improvement
        before_gt = before[name].get('gt_coverage')
        after_gt = after[name].get('gt_coverage')
        if before_gt is not None and after_gt is not None and after_gt > before_gt:
            improvements.append({'file': name, 'metric': 'gt_coverage', 'before': before_gt, 'after': after_gt})
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
        lines.append(f'  {name:35} {s["verts"]:4}v {s["faces"]:4}f  {dxf_str:12} {gt_str}')
    return '\n'.join(lines)


if __name__ == '__main__':
    scores = run_full_regression()
    print(summarize(scores))
    print(f'\nJSON:\n{json.dumps(scores, indent=2)}')
