"""
Safety checks for LLM-proposed code changes.

Enforces the project's anti-shortcut rules:
- No DXF lookup tables
- No `if filename == ...` shortcuts
- No `if n_verts/n_faces == X and Y == Z` signature gates
- No hardcoded DXF coordinate constants emitted as values
"""
import re


# Patterns that indicate forbidden shortcuts. Each is a (regex, reason) pair.
FORBIDDEN_PATTERNS = [
    # filename or path equality checks
    (r'filename\s*==\s*[\'"]', '`filename ==` string equality is a per-file fingerprint'),
    (r'filepath\s*==\s*[\'"]', '`filepath ==` string equality is a per-file fingerprint'),
    (r'\.endswith\s*\([\'"][^\'"]*\.00t', 'filename suffix check is a per-file fingerprint'),
    (r'basename\s*\([^)]*\)\s*==\s*[\'"]', 'basename equality check is a per-file fingerprint'),
    (r'os\.path\.basename', 'do not branch on basename'),
    # n_verts / n_faces signature gates (used to identify cube/sphere/etc by count)
    (r'n_verts(_header)?\s*==\s*\d+\s*and\s*n_faces(_header)?\s*==\s*\d+',
     'n_verts/n_faces signature gate is a per-file fingerprint'),
    (r'n_faces(_header)?\s*==\s*\d+\s*and\s*n_verts(_header)?\s*==\s*\d+',
     'n_verts/n_faces signature gate is a per-file fingerprint'),
    # Suspicious large constant DXF values (cube1's known coords, solid cube, etc.)
    # These indicate hardcoded vertex emission rather than decoding
    (r'\(\s*50\.0?\s*,\s*25\.0?\s*,\s*10\.0?\s*\)', 'hardcoded cube1 corner detected'),
    (r'\(\s*100\.0?\s*,\s*500\.0?\s*,\s*900\.0?\s*\)', 'hardcoded solid cube corner detected'),
    (r'\(\s*27170\b', 'hardcoded cube.00t Easting detected'),
    (r'\(\s*157410\b', 'hardcoded cube.00t Northing detected'),
]


def scan_diff(diff_text: str) -> list:
    """Return a list of (rule, reason, matched_text) for any forbidden patterns
    found in the diff's added lines (+ lines, ignoring - and context lines)."""
    findings = []
    added_lines = []
    for line in diff_text.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            added_lines.append(line[1:])  # strip leading +
    added_text = '\n'.join(added_lines)
    for pattern, reason in FORBIDDEN_PATTERNS:
        for m in re.finditer(pattern, added_text):
            findings.append({
                'pattern': pattern,
                'reason': reason,
                'matched': m.group(0),
            })
    return findings


def is_safe(diff_text: str) -> bool:
    """Return True if no forbidden patterns. Use scan_diff() for details."""
    return len(scan_diff(diff_text)) == 0


if __name__ == '__main__':
    # Self-test
    test_safe = '''
+    if g.value < 100:
+        sm_pred = (prev_g.axis - 1) % 3
'''
    test_unsafe = '''
+    if filename == 'cube1.00t':
+        return [(50, 25, 10), (100, 25, 10)]
'''
    assert is_safe(test_safe), "safe diff should pass"
    assert not is_safe(test_unsafe), "unsafe diff should fail"
    print('safety self-test passed')
    print('forbidden patterns:', len(FORBIDDEN_PATTERNS))
