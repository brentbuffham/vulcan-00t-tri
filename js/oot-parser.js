/**
 * Vulcan .00t Triangulation Parser
 * Extracts vertices, face indices, and metadata from Maptek Vulcan .00t binary files.
 * 
 * Author: Brent Buffham / blastingapps.com
 * Reverse-engineered encoding — coordinates fully cracked, faces partially decoded.
 * 
 * ENCODING SUMMARY:
 *   - File: header (60B) → page chain → "Created External" + "Variant" → data stream → attributes → duplicate → padding
 *   - Coordinates: delta-compressed truncated big-endian IEEE 754 doubles
 *     - Count byte (0x00–0x06): read count+1 data bytes
 *     - FULL value: first data byte is 0x40/0x41 → MSB bytes + zero padding
 *     - DELTA value: keep byte[0] from previous, insert new bytes at [1..count+1], keep trailing bytes from previous
 *   - Separator bytes: any byte where (b & 0x07) === 0x07 AND b >= 0x07 → skip 1
 *   - Tag pairs: all other bytes >= 0x08 → skip 2 (metadata/topology)
 *   - Face section: after "20 00" tag, vertex indices as single-byte data values between "20 03" tags
 * 
 * LIMITATIONS:
 *   - Coordinate decoding works perfectly for values with ≤6 significant bytes in BE double representation
 *     (i.e. round numbers, or coordinates < ~65536 with limited decimal places)
 *   - For coordinates with 7-8 significant bytes (e.g. 32307.853395), the data bytes can collide
 *     with tag byte values, causing misdecoding. A workaround is to use DXF face connectivity
 *     combined with 00t coordinate precision.
 *   - Face connectivity is partially decoded: vertex indices are extracted but full triangle
 *     reconstruction requires understanding the EdgeBreaker-like topology encoding in the tag pairs.
 * 
 * @module oot-parser
 */

/**
 * @typedef {Object} OotParseResult
 * @property {number[][]} vertices - Array of [x, y, z] coordinate triples
 * @property {number[][]} faces - Array of [v0, v1, v2] face index triples (0-based, partially decoded)
 * @property {number[]} coordValues - All decoded coordinate values in stream order
 * @property {number[]} faceVertexIndices - Raw 1-based vertex indices from face section
 * @property {Object} header - File header fields
 * @property {Object} metadata - Extracted metadata (strings, attributes)
 * @property {string[]} warnings - Any parse warnings
 */

/**
 * Check if a byte is a separator (low 3 bits all set, value >= 7).
 * @param {number} b - Byte value
 * @returns {boolean}
 */
function isSeparator(b) {
  return (b & 0x07) === 0x07 && b >= 0x07;
}

/**
 * Read a big-endian IEEE 754 double from a Uint8Array at the given offset.
 * @param {Uint8Array} bytes - 8-byte array
 * @returns {number}
 */
function readBEDouble(bytes) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  for (let i = 0; i < 8; i++) {
    view.setUint8(i, bytes[i] || 0);
  }
  return view.getFloat64(0, false); // big-endian
}

/**
 * Read a little-endian uint32 from buffer at offset.
 * @param {Uint8Array|ArrayBuffer} data
 * @param {number} offset
 * @returns {number}
 */
function readLE32(data, offset) {
  const d = data instanceof Uint8Array ? data : new Uint8Array(data);
  return d[offset] | (d[offset + 1] << 8) | (d[offset + 2] << 16) | (d[offset + 3] << 24);
}

/**
 * Find a byte sequence in a Uint8Array.
 * @param {Uint8Array} data
 * @param {number[]} needle
 * @param {number} [start=0]
 * @returns {number} - Index or -1
 */
function findBytes(data, needle, start = 0) {
  outer:
  for (let i = start; i <= data.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (data[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Find a byte sequence searching backwards.
 * @param {Uint8Array} data
 * @param {number[]} needle
 * @param {number} start
 * @param {number} end
 * @returns {number}
 */
function rfindBytes(data, needle, start, end) {
  outer:
  for (let i = end - needle.length; i >= start; i--) {
    for (let j = 0; j < needle.length; j++) {
      if (data[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Extract ASCII strings from a byte region.
 * @param {Uint8Array} data
 * @param {number} start
 * @param {number} end
 * @returns {Array<{offset: number, text: string}>}
 */
function extractStrings(data, start, end) {
  const strings = [];
  let i = start;
  while (i < end) {
    if (data[i] >= 32 && data[i] < 127) {
      const s = i;
      while (i < end && data[i] >= 32 && data[i] < 127) i++;
      if (i - s >= 4) {
        let text = '';
        for (let j = s; j < i; j++) text += String.fromCharCode(data[j]);
        strings.push({ offset: s, text });
      }
    } else {
      i++;
    }
  }
  return strings;
}

/**
 * Parse a Vulcan .00t triangulation file.
 * 
 * @param {ArrayBuffer} arrayBuffer - The raw file contents
 * @returns {OotParseResult}
 */
export function parseOOT(arrayBuffer) {
  const data = new Uint8Array(arrayBuffer);
  const warnings = [];

  // ── Header ──
  const magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
  const sig = String.fromCharCode(data[4], data[5], data[6], data[7]);

  if (magic !== 0xEAFBA78A || sig !== 'vulZ') {
    warnings.push(`Unexpected magic/signature: 0x${magic.toString(16)} / "${sig}"`);
  }

  const header = {
    magic: `0x${magic.toString(16).toUpperCase()}`,
    signature: sig,
    dataSize: readLE32(data, 32),
    fileSize: data.length,
    firstPagePtr: readLE32(data, 60),
  };

  // ── Find data section ──
  const variantNeedle = [0x56, 0x61, 0x72, 0x69, 0x61, 0x6E, 0x74, 0x00]; // "Variant\0"
  const variantIdx = findBytes(data, variantNeedle);
  if (variantIdx < 0) {
    warnings.push('Could not find Variant marker');
    return { vertices: [], faces: [], coordValues: [], faceVertexIndices: [], header, metadata: {}, warnings };
  }

  const dataStart = variantIdx + 8;

  // Pre-coord header
  const nVertsHeader = data[dataStart + 12];
  const nFacesHeader = data[dataStart + 19];
  header.vertexCount = nVertsHeader;
  header.faceCount = nFacesHeader;

  // ── Find boundaries ──
  // Common attribute suffix: 00 05 40 04 00 0A 20 08 07 SHADED
  const attrSuffix = [0x00, 0x05, 0x40, 0x04, 0x00, 0x0A, 0x20, 0x08, 0x07];
  let attrPos = findBytes(data, attrSuffix, dataStart);
  if (attrPos < 0) attrPos = data.length;

  // Face section marker: last "20 00" before attribute block
  const faceMarker = rfindBytes(data, [0x20, 0x00], dataStart + 30, attrPos);

  // Coord region: from pre-coord header end to face marker (or attr block)
  const coordStart = dataStart + 23; // after the 23-byte pre-coord header
  const coordEnd = faceMarker > 0 ? faceMarker : attrPos;
  const faceStart = faceMarker > 0 ? faceMarker + 2 : -1;
  const faceEnd = attrPos;

  // ── Decode coordinates ──
  const coordValues = [];
  const prev = new Uint8Array(8);
  let pos = 0;
  const coordRegion = data.slice(coordStart, coordEnd);

  while (pos < coordRegion.length) {
    const b = coordRegion[pos];

    if (b <= 0x06) {
      // Count byte
      const count = b;
      const nBytes = count + 1;
      if (pos + 1 + nBytes > coordRegion.length) break;

      const stored = coordRegion.slice(pos + 1, pos + 1 + nBytes);
      const result = new Uint8Array(8);

      if (stored[0] === 0x40 || stored[0] === 0x41 || stored[0] === 0xC0 || stored[0] === 0xC1) {
        // FULL value: stored bytes + zero padding
        for (let i = 0; i < nBytes; i++) result[i] = stored[i];
        // rest stays 0
      } else {
        // DELTA: keep byte[0] from prev, insert new at [1..nBytes], keep trailing from prev
        result[0] = prev[0];
        for (let i = 0; i < nBytes; i++) result[i + 1] = stored[i];
        for (let i = nBytes + 1; i < 8; i++) result[i] = prev[i];
      }

      const val = readBEDouble(result);
      coordValues.push(val);

      // Update prev
      for (let i = 0; i < 8; i++) prev[i] = result[i];

      pos += 1 + nBytes;
    } else if (isSeparator(b)) {
      pos += 1;
    } else if (pos + 1 < coordRegion.length) {
      pos += 2; // tag pair
    } else {
      break;
    }
  }

  // ── Decode face vertex indices ──
  const faceVertexIndices = [];
  if (faceStart > 0 && faceEnd > faceStart) {
    const faceRegion = data.slice(faceStart, faceEnd);
    let fpos = 0;

    while (fpos < faceRegion.length) {
      const b = faceRegion[fpos];

      if (b <= 0x06) {
        const count = b;
        const nBytes = count + 1;
        if (fpos + 1 + nBytes > faceRegion.length) break;

        // Extract vertex indices (single-byte values that are valid indices)
        for (let i = 0; i < nBytes; i++) {
          const v = faceRegion[fpos + 1 + i];
          if (v >= 1 && v <= nVertsHeader) {
            faceVertexIndices.push(v);
          }
        }
        fpos += 1 + nBytes;
      } else if (isSeparator(b)) {
        fpos += 1;
      } else if (fpos + 1 < faceRegion.length) {
        fpos += 2;
      } else {
        break;
      }
    }
  }

  // ── Build vertex triples ──
  // Coordinates are stored as unique values per axis in stream order.
  // The first 3 values form the first vertex (X, Y, Z).
  // Subsequent values are deltas that define new vertices by changing one axis at a time.
  // For simple files this works directly; for complex files the between-coord tags
  // define additional vertices through coordinate combinations.
  const vertices = [];
  if (coordValues.length >= 3) {
    // Simple approach: group as sequential XYZ triples from the unique values
    // This works for simple test files; complex files need the full vertex reconstruction
    let cx = coordValues[0], cy = coordValues[1], cz = coordValues[2];
    vertices.push([cx, cy, cz]);

    // Walk remaining coords — each changes one axis
    for (let i = 3; i < coordValues.length; i++) {
      const v = coordValues[i];
      // Heuristic: determine which axis changed based on value range matching
      if (Math.abs(v - cx) < Math.abs(v - cy) && Math.abs(v - cx) < Math.abs(v - cz)) {
        cx = v; // X changed
      } else if (Math.abs(v - cy) < Math.abs(v - cz)) {
        cy = v; // Y changed  
      } else {
        cz = v; // Z changed
      }
      vertices.push([cx, cy, cz]);
    }
  }

  // ── Build faces ──
  // For now, store the face vertex indices as extracted.
  // Full face reconstruction requires the EdgeBreaker topology decoding.
  // The first face is implicitly (V1, V2, V3) from the first 3 vertices.
  const faces = [];
  if (vertices.length >= 3) {
    // First face: always the first 3 vertices (0-based)
    faces.push([0, 1, 2]);

    // Additional faces from the face section vertex indices
    // These are partially decoded — the full topology needs EdgeBreaker decoding
    // For now, provide the raw indices for external reconstruction
  }

  // ── Metadata ──
  const strings = extractStrings(data, dataStart, Math.min(dataStart + 2000, data.length));
  const metadata = {
    strings: strings.map(s => s.text),
    dataStart: `0x${dataStart.toString(16).toUpperCase()}`,
    coordCount: coordValues.length,
    faceIndexCount: faceVertexIndices.length,
  };

  if (coordValues.length === 0) {
    warnings.push('No coordinates decoded — file may use 7-8 byte coordinates that collide with tag bytes');
  }

  return {
    vertices,
    faces,
    coordValues,
    faceVertexIndices,
    header,
    metadata,
    warnings,
  };
}

/**
 * Convert parsed 00t data to a simple OBJ-format string.
 * Useful for quick visualisation or import into 3D tools.
 * 
 * @param {OotParseResult} result
 * @returns {string}
 */
export function toOBJ(result) {
  const lines = ['# Vulcan .00t export', `# Vertices: ${result.vertices.length}`, `# Faces: ${result.faces.length}`, ''];

  for (const [x, y, z] of result.vertices) {
    lines.push(`v ${x} ${y} ${z}`);
  }

  lines.push('');

  for (const [v0, v1, v2] of result.faces) {
    lines.push(`f ${v0 + 1} ${v1 + 1} ${v2 + 1}`); // OBJ is 1-based
  }

  return lines.join('\n');
}

/**
 * Convert parsed 00t data to CSV strings for vertices and faces.
 * 
 * @param {OotParseResult} result
 * @returns {{vertexCSV: string, faceCSV: string}}
 */
export function toCSV(result) {
  let vertexCSV = 'Index,X,Y,Z\n';
  result.vertices.forEach((v, i) => {
    vertexCSV += `${i},${v[0]},${v[1]},${v[2]}\n`;
  });

  let faceCSV = 'Index,V0,V1,V2\n';
  result.faces.forEach((f, i) => {
    faceCSV += `${i},${f[0]},${f[1]},${f[2]}\n`;
  });

  return { vertexCSV, faceCSV };
}
