"""
Ground truth corner coordinates for files in exampleFiles/.

Used by the agent loop to score parser output. Each entry maps a file's
basename (without .00t) to the list of expected (x, y, z) tuples.

For solved files, we read the DXF when available; for cubes 1-3 we compute
from cube1's corners + rotation; cube4/5 currently lack ground truth (user
to provide) and are skipped during scoring.
"""
import math


def rotate_z(corners, theta_deg, cx=75, cy=50):
    t = math.radians(theta_deg)
    c, s = math.cos(t), math.sin(t)
    return [(round(c * (x - cx) - s * (y - cy) + cx, 6),
             round(s * (x - cx) + c * (y - cy) + cy, 6),
             z) for x, y, z in corners]


# cube1: axis-aligned 50³ box (user-confirmed)
CUBE1_CORNERS = [
    (50, 25, 10), (100, 25, 10), (100, 75, 10), (50, 75, 10),
    (50, 25, 60), (100, 25, 60), (100, 75, 60), (50, 75, 60),
]

# cube.00t: skyscraper ~10x10x40 at UTM (user-confirmed)
CUBE_UTM_CORNERS = [
    (27170, 157410, 1000), (27180, 157410, 1000),
    (27180, 157420, 1000), (27170, 157420, 1000),
    (27170, 157410, 1040), (27180, 157410, 1040),
    (27180, 157420, 1040), (27170, 157420, 1040),
]

# tri-crack-solid (original solved cube — known from existing tests)
SOLID_CORNERS = [
    (100, 500, 900), (300, 500, 900), (300, 600, 900), (100, 600, 900),
    (100, 500, 950), (300, 500, 950), (300, 600, 950), (100, 600, 950),
]

# Ground truth dict keyed by file basename
GT = {
    'cube1': CUBE1_CORNERS,
    'cube2': rotate_z(CUBE1_CORNERS, -25),
    'cube3': rotate_z(CUBE1_CORNERS, -75),
    'cube': CUBE_UTM_CORNERS,
    'tri-crack-solid': SOLID_CORNERS,
    # The remaining solved files use DXF as their ground truth via the regression
    # harness — listed here so the agent knows which are scored against DXFs:
    'tri-crack-triangle': None,  # use DXF
    'tri-crack': None,
    'tri-crack-linear': None,
    'tri-crack-fan': None,
    'tri-crack-prism': None,
    'tri-crack-4sides-prism': None,
    'tri-crack-Stepped-pyramid': None,
    'tri-crack-L-SHAPE': None,
    'tri-crack-Hexhole': None,
    'tri-crack-NonRound': None,
    'tri-crack-SPHERE': None,
}


# Required minimum match scores for solved files. A change is considered a
# REGRESSION if any of these drops below the threshold. The agent must NOT
# commit anything that breaks these.
SOLVED_THRESHOLDS = {
    'tri-crack-triangle': 3,    # 3/3 vertex match
    'tri-crack': 4,             # 4/4
    'tri-crack-linear': 7,      # 7/7
    'tri-crack-solid': 8,       # 8/8 (cube)
    'tri-crack-fan': 3,         # 3/6 (partial — current best)
    'tri-crack-prism': 4,       # 4/4
    'tri-crack-4sides-prism': 5, # 5/5
    'tri-crack-Stepped-pyramid': 0,  # 0/20 (unsolved)
    'tri-crack-L-SHAPE': 0,     # 0/12
    'tri-crack-Hexhole': 3,     # 3/12
    'tri-crack-NonRound': 2,    # 2/16
    'tri-crack-SPHERE': 3,      # 3/50 (current best after TEST-058)
}


def coverage(parsed_verts, ground_truth_corners, tol=1.5):
    """Count how many ground-truth corners are covered by parsed_verts."""
    if not ground_truth_corners:
        return None
    covered = 0
    for t in ground_truth_corners:
        for v in parsed_verts:
            if (abs(v[0] - t[0]) < tol and abs(v[1] - t[1]) < tol
                    and abs(v[2] - t[2]) < tol):
                covered += 1
                break
    return covered
