# Quick test: what would the pyramid vertex builder produce with 5 coords?
# Values: 0.0, 200.0, 100.0, 300.0, 412.0
# After garbage filter (coordGroupEnd=5), we have 5 groups
# Axis machine: [0]=X, [1]=Y, [2]=Z, then state machine continues
# nVertsHeader = 20, nFacesHeader = 18

# The axis state machine would assign:
# group 0: axis 0 (X) = 0.0
# group 1: axis 1 (Y) = 200.0
# group 2: axis 2 (Z) = 100.0  
# group 3: depends on tags
# group 4: depends on tags

# With 5 coord values and axis cycling, we'd get 5 axis assignments
# But we need 20 vertices! The C0 tags handle vertex slot assignments.

# The vertex builder uses running state model:
# V0 = first 3 values -> (0.0, 200.0, 100.0)
# V1+ each update one axis of running state

# With only 5 coords, we'd get at most 3 additional vertices (one per coord after V0)
# Total: ~4-5 vertices for 20 expected. Very incomplete.

# This confirms the coord extraction is still insufficient.
# We need MORE coordinate values from the stream.

print("Pyramid coord extraction: 5 values from 116-byte coord section")
print("Need ~20+ values for 20 vertices")
print("Many coordinates are embedded in the tag/separator stream")
print("The zero-literal and skip-byte changes help but don't solve the full problem")
