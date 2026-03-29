# Plane expected vertices from DXF:
# 0: [100, 500, 900]
# 1: [300, 600, 900]  
# 2: [300, 500, 900]
# 3: [100, 600, 900]

# DXF faces: [0,1,2] and [0,3,1]

# OOT vertices (from parser):
# 0: [100, 500, 900]
# 1: [100, 600, 900]  <- different order than DXF!
# 2: [300, 600, 900]
# 3: [100, 600, 900]  <- duplicate of V1

# The OOT vertex order doesn't match DXF.
# OOT V0=[100,500,900]=DXF V0
# OOT V1=[100,600,900]=DXF V3
# OOT V2=[300,600,900]=DXF V1
# OOT V3=[100,600,900]=DXF V3 (dup)

# The face section refs are 3 and 4 (1-based), meaning vertices 2 and 3 in 0-based.
# OOT V2=[300,600,900] and OOT V3=[100,600,900]

# If initTri = [0,1,2] (default), that's [100,500,900], [100,600,900], [300,600,900]
# The DXF face 1 = V0,V1,V2 = [100,500,900],[300,600,900],[300,500,900]
# The DXF's V2=[300,500,900] doesn't appear in OOT vertices at all!

# OOT has:
# 100,500,900  100,600,900  300,600,900  100,600,900
# DXF has:
# 100,500,900  300,600,900  300,500,900  100,600,900

# OOT is MISSING [300,500,900]! It has a DUPLICATE of [100,600,900] instead.
# This is a vertex builder issue, not a face decoder issue.

print("OOT vertices: [100,500,900], [100,600,900], [300,600,900], [100,600,900]")
print("DXF vertices: [100,500,900], [300,600,900], [300,500,900], [100,600,900]")
print()
print("MISSING from OOT: [300,500,900]")
print("DUPLICATE in OOT: [100,600,900] appears twice")
print()
print("This is a VERTEX BUILDER issue - wrong coordinates being generated")
print("The face decoder can't work correctly with wrong vertices")
