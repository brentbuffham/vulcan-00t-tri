# Plane coords (from parser): 100.0, 500.0, 900.0, 600.0, 300.0
# Axis assignments (from parser trace):
# [0] X=100  [1] Y=500  [2] Z=900  [3] Y=600  [4] X=300

# Running state model:
# V0: X=100, Y=500, Z=900 -> [100, 500, 900]
# V1: axis=Y, value=600 -> running = [100, 600, 900] -> vertex [100, 600, 900]
# V2: axis=X, value=300 -> running = [300, 600, 900] -> vertex [300, 600, 900]

# That gives 3 vertices: [100,500,900], [100,600,900], [300,600,900]
# But we need 4! The 4th vertex [300,500,900] is missing.
# It should have Y=500 (the base Y value).

# The C0 tag should create a 4th vertex.
# Plane coord groups have these tags:
# [0] val=100.0  tags=[80:15]
# [1] val=500.0  tags=[60:08]
# [2] val=900.0  tags=[80:07, C0:17]
# [3] val=600.0  tags=[80:0f, C0:17]
# [4] val=300.0  tags=[A0:0f, E0:0f, E0:0f, E0:06]  seps=[17, 47, 17]

# C0 tags:
# Group 2 (Z=900): C0:17 -> hi=1, lo=7 -> slot 1, base Z
# Group 3 (Y=600): C0:17 -> hi=1, lo=7 -> slot 1, base Z

# So slot 1 gets: 
#   From group 2 (axis=Z): slot1[Z] = 900
#   From group 3 (axis=Y): slot1[Y] = 600

# Slot 1 inherits base values for unset axes:
# baseX = 100 (first X), baseY = 500 (first Y), baseZ = 900 (first Z)
# slot1 = [baseX=100, 600, 900] = [100, 600, 900]

# That's ANOTHER [100, 600, 900] - same as V1!
# The 4th vertex [300, 500, 900] is never created.

# Expected: slot 1 should have X=300, Y=500, Z=900
# But C0 tags only assign Z (from group 2) and Y (from group 3) to slot 1.
# X is inherited as baseX=100.

# The issue: baseX should be 300 for slot 1, not 100.
# OR: the C0 tag assignment model is wrong for this case.
# OR: the axis assignment for group 3 is wrong (should be X, not Y)

# Let me verify axis assignments:
# Group 0: axis 0 (X) = 100.0
# Group 1: axis 1 (Y) = 500.0  
# Group 2: axis 2 (Z) = 900.0
# Group 3: first non-C0 tag is 80:0f. 80 class != E0, lo=0xF, hi=0.
#   Rule: "lo=F AND hi=0 -> direction=-1, axis=(axis-1)%3"
#   axis was 2 (Z), so axis = (2-1)%3 = 1 (Y). direction = -1.
#   So group 3 is Y=600. That seems correct.
# Group 4: first non-C0 tag is A0:0f. A0 != E0. lo=0xF, hi=0.
#   Rule: "lo=F AND hi=0 -> direction=-1, axis=(axis-1)%3"
#   axis was 1, direction already -1, so axis=(1-1)%3=0 (X). direction stays -1.
#   So group 4 is X=300. 

# So axis assignments are: X=100, Y=500, Z=900, Y=600, X=300
# Running state: V0=(100,500,900), V1=(100,600,900), V2=(300,600,900)
# C0 slot 1 = [100, 600, 900] (inherits base values, overwritten by C0 assignments)
# Final vertices: [100,500,900], [100,600,900], [300,600,900], [100,600,900]

# The missing vertex [300,500,900] would need:
# X=300 (from the running state at group 4)
# Y=500 (the base Y value)  
# Z=900 (the Z value)

# This vertex is the "opposite corner" of the quad. It needs both X=300 AND Y=500.
# But C0 slot 1 inherits X=100 (base), not X=300 (later value).

# Maybe the C0 slot should inherit the CURRENT running X value, not the base?
# If slot 1 inherits running state at time of assignment:
# At group 2 (Z=900): running = [100, 500, 900]. C0 slot 1 gets running state + Z=900
# At group 3 (Y=600): running = [100, 600, 900]. C0 slot 1 gets Y=600
# Still [100, 600, 900]

# What if C0:17 means something different? hi=1, lo=7.
# Maybe hi=1 doesn't mean "slot 1" but "vertex offset +1"?
# Or lo=7 means "use the running X value at the END of the coord section"?

print("Vertex builder produces wrong 4th vertex")
print("Need [300,500,900] but get [100,600,900]")
print("The C0 slot model needs revision for the plane case")
