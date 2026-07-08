# PROOF: the .00t coordinate predictor IS the EdgeBreaker gate parallelogram (2026-07-08)

Follow-up to Z_RECONSTRUCTION_HUNT (v11 surface-of-neighbors was a stand-in for
*something*). This pins what: the encoder predicts each vertex from a neighbour
triangle across a shared edge, `pred = A + B - C` (parallelogram), storing the
low byte-window and reconstructing the high byte from that prediction.

Script: `python/parallelogram_proof.py`. GT (DXF faces) used for VERIFICATION
ONLY -- it tests a MECHANISM, never feeds a decoder. Threshold = the Z half-
window 0.0625 m (0.125 m byte-2 unit): a predictor "wins" a site if
`|predZ - trueZ| < 0.0625` (then the nearest-congruent snap recovers the exact
value).

## Result (intercepts)

Global: best-gate parallelogram predicts ALL 2975 vertices' full 3D position
within the half-window **79.3%** of the time (median residual 0.0123 m) -- the
parallelogram residual is small, the signature of a parallelogram-coded mesh.

At the **396 v11 drift sites** (yellow class: X/Y bit-exact, Z drifting):

| predictor of Z | median err | within 0.0625 m |
|---|---|---|
| (a) v11 DECODED (the drift) | 3.7132 m | **0.0%** |
| (b) PLANE oracle (v11 stand-in, 3 XY-nearest) | 0.0131 m | 52.8% |
| (c) **GATE PARALLELOGRAM A+B-C** | 0.0089 m | **97.7%** |

**Decisive check** -- of the **187 sites the plane oracle CANNOT get**, the gate
parallelogram recovers **186 (99.5%)**. The exact class the surface stand-in
misses is precisely the class the true gate triangle nails.

## What it proves (and the honest caveat)

- The .00t coordinates are **EdgeBreaker/parallelogram-predicted against the
  mesh connectivity**. Measured, not assumed.
- v11's surface-of-neighbours was a 53-79% approximation of this predictor.
- **The stuck ~20% of the vertex decode IS the faces.** Not two problems: the
  face traversal hands you the deterministic gate triangle per vertex, and the
  drift closes. Vertices and faces are two views of one spiral traversal.
- CAVEAT: 97.7% is *best-of-incident-gates* -- it proves the correct gate
  *exists* among a vertex's neighbours and predicts near-exactly. Picking *which*
  gate without guessing is exactly what the face-traversal determines. So this
  proves the information is present and connectivity-locked; it does not hand us
  the decode for free.

## The new leverage this unlocks (for the faces attack)

Because coordinates and faces are the SAME traversal, the coordinate stream --
which we already decode ~52% GT-FREE -- becomes a **GT-free oracle for the face
decode**:

- A correct CLERS traversal must visit vertices in the **vertex emission order**
  (forward spiral C-order = the order our coord decoder emits them).
- Each **C** op's gate triangle must **parallelogram-predict the next emitted
  vertex** to within the low-window. This is a GT-free scoring function for a
  hypothesised op-grammar: no DXF needed -- our own decoded vertices score it.

This is the spec input for the Mystery-A (C/R/L/E/S op-grammar) detective work.

See the global `edgebreaker` skill (`references/reverse-engineering.md`) for the
mechanism writeup, and the `vulcan-00t` skill for the container/coord findings.
