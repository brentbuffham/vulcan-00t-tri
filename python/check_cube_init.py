# Cube face section starts: 20 00 00 01 20 03 00 02 20 03 00 04 20 03 e0 03
# After 20:00, first element is DATA(01), not a 40 tag.
# So skippedInitMeta would stay false.
# The cube init vertex extraction is unaffected.
print("Cube: after 20:00, first element is DATA(01), not TAG 40")
print("skippedInitMeta stays false - no impact on cube")
print("Fix is safe for cube")
