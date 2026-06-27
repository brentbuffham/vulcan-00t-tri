meta:
  id: vulcan_00t
  title: Maptek Vulcan .00t triangulation (reverse-engineered, PARTIAL)
  file-extension: 00t
  endian: le          # header integers are little-endian...
  encoding: ASCII
doc: |
  Maptek Vulcan triangulation container. Reverse-engineering in progress.

  WHAT IS SOLID:
    * 60-byte header = 15 little-endian int32. First two int32 are the magic
      (EA FB A7 8A) and signature ("vulZ").
    * header[6] = 60 (header size). header[11] = geo_end = end-of-geometry /
      start-of-attributes pointer (0 means "old format", geometry runs to ~EOF).
    * Container is a 2048-byte paged archive; a small directory + ASCII strings
      ("Variant", "Created External", layer names) sit between the header and the
      geometry, which starts near offset 8252-8352.
    * COORDINATE GEOMETRY is a stream of records:  [tag][sep][count][payload]
        - sep is a separator byte with (sep & 7) == 7
        - payload is (count + 1) bytes
        - if payload[0] in {0x40,0x41,0xC0,0xC1}  -> FULL  (8-byte big-endian
          IEEE-754 double, possibly short/zero-padded)
        - else                                    -> DELTA (low bytes spliced onto
          the previous value's high bytes)
      Coordinates stream vertex-major in X, Y, Z order (axis = cycle position).
      NB: ~17% of records are "escape"/long records (count > 6, embedded FULLs,
      0xE0 state-markers) that this grammar does NOT yet fully model -- the record
      walker below will desync at those. That is the open part of the format.

  HOW TO USE in ide.kaitai.io:
    * The header + geo_end always parse correctly.
    * Set `geom_start` (in instances, below) to where you want the record walker to
      begin. Known starts:  heave seed@8328 records@8352 | OB34 seed@8318 |
      SYLVANIA @8352 | SOLID_MM @8352 | intercepts @8352 (geo_end=0).
    * `seed` shows the first 3 coordinates as big-endian doubles (vertex 0).
    * Coordinate values inside payloads are BIG-endian doubles (f8be), unlike the
      little-endian header.

seq:
  - id: magic
    contents: [0xEA, 0xFB, 0xA7, 0x8A]
  - id: signature
    type: str
    size: 4
    doc: '"vulZ"'
  - id: header_fields
    type: u4
    repeat: expr
    repeat-expr: 13
    doc: |
      header[2..14]. Observed constants: [2]=2 [3]=4 [4]=1 [5]=25600 [6]=60(hdr len)
      [7]=0 [8]=alloc/size [9]=0 [10]=2 [11]=geo_end [12]=0 [13]=count [14]=0.

instances:
  # ---- named header values -------------------------------------------------
  header_size:
    value: header_fields[4]      # header[6], always 60
  field8:
    value: header_fields[6]      # header[8] - a size/offset (uncertain)
  geo_end:
    value: header_fields[9]      # header[11] - geometry end / attribute start
    doc: 0 = old format (geometry runs toward EOF)
  count13:
    value: header_fields[11]     # header[13] - an object/record count (uncertain)

  # ---- EDIT THIS per file to point the record walker -----------------------
  geom_start:
    value: 8352
    doc: byte offset where the coord-record stream begins (see HOW TO USE)
  seed_pos:
    value: 8328
    doc: byte offset of vertex 0 (3 consecutive big-endian doubles)

  # ---- vertex 0 (seed) -----------------------------------------------------
  seed:
    pos: seed_pos
    type: seed_xyz

  # ---- raw region split at geo_end ----------------------------------------
  pre_geometry:
    pos: 60
    size: 'geom_start - 60'
    doc: page directory + ASCII strings (Variant / Created External / layers)
  attributes:
    pos: 'geo_end > 0 ? geo_end : _io.size'
    size: 'geo_end > 0 ? _io.size - geo_end : 0'
    doc: attributes + PNG thumbnail (PNG sig 89 50 4E 47 ...). Empty if old format.

  # ---- coordinate record stream -------------------------------------------
  geometry:
    pos: geom_start
    size: '(geo_end > geom_start) ? (geo_end - geom_start) : (_io.size - geom_start)'
    type: record_stream

types:
  seed_xyz:
    seq:
      - id: x
        type: f8be
      - id: y
        type: f8be
      - id: z
        type: f8be

  record_stream:
    seq:
      - id: records
        type: record
        repeat: eos

  record:
    doc: '[tag][sep][count][payload(count+1)]  -- desyncs on escape/long records'
    seq:
      - id: tag
        type: u1
      - id: sep
        type: u1
      - id: count
        type: u1
      - id: payload
        size: 'count + 1'
    instances:
      sep_ok:
        value: '(sep & 7) == 7'
        doc: should be true for a well-framed record
      tag_class:
        value: 'tag & 0xE0'
      is_full:
        value: 'payload[0] == 0x40 or payload[0] == 0x41 or payload[0] == 0xC0 or payload[0] == 0xC1'
        doc: true = FULL (8-byte double), false = DELTA (payload always >=1 byte)
      nbytes:
        value: 'count + 1'
