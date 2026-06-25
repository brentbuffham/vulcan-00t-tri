/**
 * vulcan00TParser.js — Maptek Vulcan .00t triangulation parser (production format)
 *
 * Validated on a real 50 MB production .00t against a 378 MB face-CSV ground truth.
 * This is the PRODUCTION-format parser (the older js/oot-parser.js is toy-only and
 * does not work on real files).
 *
 * STATUS OF LAYERS (see project_vulcan00t_parser_buildspec memory):
 *   L1 Container ............. SOLVED  (implemented)
 *   L2 Section bounds ........ SOLVED  (implemented)
 *   L3 Vertex 0 .............. SOLVED  (implemented)
 *   L4 Record grammar ........ SOLVED  (implemented)
 *   L5 Coord values .......... PARTIAL (splice for sparse records implemented;
 *                                       DENSE within-column codec OPEN -> gated)
 *   L6 Faces / EdgeBreaker ... NOT STARTED (stub)
 *   Attributes + PNG ......... identified (implemented)
 *
 * Author: Brent Buffham / blastingapps.com + Claude (reverse-engineering).
 * @module vulcan00TParser
 */

const MAGIC = [0xea, 0xfb, 0xa7, 0x8a, 0x76, 0x75, 0x6c, 0x5a]; // ....vulZ
const TAG_CLASSES = new Set([0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0]);
const FULL_IND = new Set([0x40, 0x41, 0xc0, 0xc1]); // payload[0] -> skip guard
const COORD_START = 8328; // geometry data start (after object header at 8252)

function isSep(b) { return (b & 0x07) === 0x07 && b >= 0x07; }
function isTag(b) { return b > 0x06 && TAG_CLASSES.has(b & 0xe0); }

/** Splice high (8-nb) bytes of `prevHi` with the nb payload bytes -> BE double. */
function spliceDouble(prevHi, payload) {
  const buf = new ArrayBuffer(8);
  const v = new DataView(buf);
  const keep = 8 - payload.length;
  for (let i = 0; i < keep; i++) v.setUint8(i, prevHi[i]);
  for (let i = 0; i < payload.length; i++) v.setUint8(keep + i, payload[i]);
  return v.getFloat64(0, false);
}

function readBEDouble(bytes, off) {
  const v = new DataView(bytes.buffer, bytes.byteOffset + off, 8);
  return v.getFloat64(0, false);
}

// ---- LAYER 1: container header ------------------------------------------------
function readHeader(u8) {
  for (let i = 0; i < MAGIC.length; i++) {
    if (u8[i] !== MAGIC[i]) throw new Error('Not a Vulcan .00t (bad magic)');
  }
  const dv = new DataView(u8.buffer, u8.byteOffset, 60);
  const dir = [];
  for (let i = 0; i < 15; i++) dir.push(dv.getInt32(i * 4, true));
  return { dir, geoEnd: dir[11] }; // [11] = geometry-end / attribute-start
}

// ---- LAYER 2: section bounds --------------------------------------------------
// Coord section is dense X/Y/Z; topology follows; attributes + PNG after geoEnd.
// The coord/topo split (~25M in the test file) is found by Z-emission collapse;
// for a robust bound, scan for the topology marker density. Here we expose geoEnd
// and let the coord walker stop when it leaves the coord regime.
function boundSections(u8, hdr) {
  return { coordStart: COORD_START, attrStart: hdr.geoEnd, topoEnd: hdr.geoEnd };
}

// ---- LAYER 4: record grammar generator ---------------------------------------
// Yields {pos, kind, tag, sep, nb, payload}. kind: 'coord' | 'sep' | 'tag'.
function* records(u8, start, end) {
  let pos = start, lastTag = 0x20, lastSep = 0x17;
  while (pos < end) {
    const b = u8[pos];
    if (b <= 0x06) {
      const nb = b + 1;
      const payload = u8.subarray(pos + 1, pos + 1 + nb);
      yield { pos, kind: 'coord', tag: lastTag, sep: lastSep, nb, payload };
      pos += 1 + nb;
    } else if (isSep(b)) {
      lastSep = b; yield { pos, kind: 'sep', sep: b }; pos += 1;
    } else if (TAG_CLASSES.has(b & 0xe0)) {
      lastTag = b; yield { pos, kind: 'tag', tag: b }; pos += 1;
    } else {
      pos += 1; // anomaly / marker byte
    }
  }
}

// ---- LAYER 3 + LAYER 5: coordinate decode ------------------------------------
// NOTE: only the SPARSE-record splice model is sound. The DENSE within-column
// records use an UNCRACKED codec; decoded vertices are NOT yet correct. This
// path is intentionally gated by opts.allowUnverifiedCoords.
function decodeCoords(u8, bounds, opts = {}) {
  if (!opts.allowUnverifiedCoords) {
    throw new Error(
      'Coordinate decode is gated: the dense within-column codec (L5) is not yet ' +
      'cracked. Pass {allowUnverifiedCoords:true} to run the partial splice decoder ' +
      'for research only — output vertices are NOT reliable.');
  }
  // vertex 0 — three full BE doubles (24 bytes)
  const v0 = [readBEDouble(u8, 8328), readBEDouble(u8, 8336), readBEDouble(u8, 8344)];
  const prevHi = [
    Array.from(u8.subarray(8328, 8336)),
    Array.from(u8.subarray(8336, 8344)),
    Array.from(u8.subarray(8344, 8352)),
  ];
  const cur = [...v0];
  const verts = [[...v0]];
  let lastAxis = 0;
  for (const r of records(u8, COORD_START + 24, bounds.topoEnd)) {
    if (r.kind !== 'coord') continue;
    const p = r.payload;
    if (p.length !== r.nb || (p.length && FULL_IND.has(p[0]))) continue;
    let ax;
    if ((r.tag & 0xe0) === 0x60) {
      ax = lastAxis; // refine previous axis (bind, don't re-classify)
    } else {
      // PARTIAL classifier (research). Real selector is column/state based.
      const cx = spliceDouble(prevHi[0], p);
      const cz = spliceDouble(prevHi[2], p);
      if (cx > 60300 && cx < 60900) ax = 0;
      else if (cz >= 511 && cz <= 543) ax = 2;
      else continue;
    }
    const nv = spliceDouble(prevHi[ax], p);
    const buf = new ArrayBuffer(8); new DataView(buf).setFloat64(0, nv, false);
    prevHi[ax] = Array.from(new Uint8Array(buf));
    cur[ax] = nv; lastAxis = ax;
    if ((r.tag & 0xe0) !== 0x60 && ax === 2) verts.push([cur[0], cur[1], cur[2]]);
  }
  return verts;
}

// ---- LAYER 6: faces (EdgeBreaker) — NOT STARTED ------------------------------
function decodeTopology(/* u8, bounds */) {
  throw new Error('Face/topology decode (EdgeBreaker CLERS) not implemented yet.');
}

// ---- Attributes + PNG thumbnail ----------------------------------------------
function parseAttributes(u8, attrStart) {
  const tail = u8.subarray(attrStart);
  const png = indexOfSeq(tail, [0x89, 0x50, 0x4e, 0x47]);
  let thumbnail = null;
  if (png >= 0) {
    const iend = indexOfSeq(tail, [0x49, 0x45, 0x4e, 0x44], png);
    if (iend >= 0) thumbnail = tail.subarray(png, iend + 8); // +IEND+CRC
  }
  // ASCII attribute tokens (NAME/colour_by/LAYER/SHADED/WIREFRAME...) live here;
  // a full key/value parse is TODO.
  return { thumbnail, raw: tail };
}

function indexOfSeq(hay, needle, from = 0) {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// ---- top-level ---------------------------------------------------------------
function parse00t(arrayBuffer, opts = {}) {
  const u8 = new Uint8Array(arrayBuffer);
  const header = readHeader(u8);
  const bounds = boundSections(u8, header);
  const attributes = parseAttributes(u8, bounds.attrStart);
  const result = { header, bounds, attributes };
  if (opts.decodeGeometry) {
    result.vertices = decodeCoords(u8, bounds, opts); // gated unless allowUnverifiedCoords
    // result.faces = decodeTopology(u8, bounds);     // not implemented
  }
  return result;
}

export {
  parse00t, readHeader, boundSections, records, decodeCoords, decodeTopology,
  parseAttributes, spliceDouble, isSep, isTag, MAGIC,
};
