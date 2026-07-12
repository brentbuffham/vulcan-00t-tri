/**
 * vulcan00TParser.js — Maptek Vulcan .00t triangulation parser (production format)
 *
 * The .00t file is a `vulZ` FastLZ-compressed paged container. Decode it by
 * walking an 8-byte-record pointer tree, FastLZ-inflating each page, and
 * reassembling the pages at `page_number * page_size`. The reassembled image
 * is a plain fixed-stride structure:
 *
 *     120-byte header
 *     vertex_count : BE u32 @ 0x48
 *     face_count   : BE u32 @ 0x60
 *     vertices     : N x (3 x BE f64)               absolute coordinates
 *     faces        : M x (3 x BE u32 + 12-byte payload)   1-based index triples
 *     trailing attributes (ASCII tokens, optional PNG thumbnail)
 *
 * There is NO delta/tag coordinate grammar and NO EdgeBreaker face encoding —
 * those were artifacts of reading the compressed byte stream as if it were the
 * data model. Verified against every toy fixture (cube/rotated-cube/triangle/
 * prism/4-sides-prism/fan/hexhole/nonround/sphere/stepped-pyramid) and a
 * 10201-vertex / 20000-face 18-page grid, all with zero missing pages.
 *
 * Ported from the Incline `tri00t.rs` reference decoder.
 *
 * Author: Brent Buffham / blastingapps.com + Claude (reverse-engineering).
 * @module vulcan00TParser
 */

const MAGIC = [0xea, 0xfb, 0xa7, 0x8a, 0x76, 0x75, 0x6c, 0x5a]; // ....vulZ

// Raw (decompressed) image layout.
const RAW_HEADER_LEN = 120;
const RAW_VERTEX_COUNT_OFFSET = 0x48;
const RAW_FACE_COUNT_OFFSET = 0x60;
const RAW_VERTEX_SIZE = 24;
const RAW_FACE_SIZE = 24;

// vulZ container header fields.
const VULZ_PAGE_SIZE_OFFSET = 0x14;
const VULZ_TOTAL_EXPANDED_OFFSET = 0x20;
const VULZ_AUX_OFFSET_OFFSET = 0x2c;
const VULZ_AUX_LEN_OFFSET = 0x34;
const VULZ_WALK_START = 0x3c;

const POINTER_BLOCK_ENTRIES = 0x800 / 8; // 256 (target,0) entries per pointer block
const END_MARKER = 0xfdfcfbfa;           // "fa fb fc fd" end-of-page marker (LE word)
const MAX_PAGE_LEN = 4 << 20;
const MAX_PAGE_TRAILER = 0x4000;

// ---- little / big endian scalar reads ----------------------------------------
function le32(u8, o) {
  return (u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16) | (u8[o + 3] << 24)) >>> 0;
}
function be32(u8, o) {
  return ((u8[o] << 24) | (u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3]) >>> 0;
}
function beF64(u8, o) {
  return new DataView(u8.buffer, u8.byteOffset + o, 8).getFloat64(0, false);
}
function hasRecord(u8, o) { return o + 8 <= u8.length; }

// ---- FastLZ (levels 1 & 2) ----------------------------------------------------
// One stored stream per page. The level is carried in the top three bits of the
// first control byte (0 -> level 1, 1 -> level 2). Level 2 adds a looped
// extended match length and a 16-bit far-distance escape, per reference fastlz.c.
function fastlzDecompress(input) {
  const n = input.length;
  if (n === 0) return new Uint8Array(0);
  const lvl = input[0] >> 5;
  let level2;
  if (lvl === 0) level2 = false;
  else if (lvl === 1) level2 = true;
  else throw new Error(`unsupported FastLZ level ${lvl + 1}`);

  let i = 0;
  let firstOp = true;
  const out = [];
  while (i < n) {
    let control = input[i];
    if (firstOp) { control &= 0x1f; firstOp = false; } // level marker lives here
    i += 1;

    if (control < 32) {
      // literal run
      const len = control + 1;
      const end = i + len;
      if (end > n) throw new Error('FastLZ literal run exceeds page input');
      for (let k = i; k < end; k++) out.push(input[k]);
      i = end;
    } else {
      // back-reference
      let len = control >> 5;
      let ref = (control & 0x1f) << 8;
      if (len === 7) {
        for (;;) {
          if (i >= n) throw new Error('FastLZ missing extended match length');
          const code = input[i]; i += 1;
          len += code;
          if (!level2 || code !== 255) break;
        }
      }
      if (i >= n) throw new Error('FastLZ missing match offset byte');
      const code = input[i]; i += 1;
      ref += code;
      if (level2 && code === 255 && (control & 0x1f) === 0x1f) {
        if (i + 2 > n) throw new Error('FastLZ missing far match offset');
        ref = (input[i] << 8) + input[i + 1] + 8191;
        i += 2;
      }
      len += 2;
      if (ref >= out.length) throw new Error('FastLZ match reference before output start');
      const start = out.length - ref - 1;
      const refEnd = start + len;
      for (let k = start; k < refEnd; k++) out.push(out[k]); // overlap-safe byte copy
    }
    if (out.length > MAX_PAGE_LEN) throw new Error('FastLZ page larger than expected');
  }
  return Uint8Array.from(out);
}

// ---- vulZ pointer-tree walk ---------------------------------------------------
class VulzWalk {
  constructor(u8, pageSize, totalPages) {
    this.u8 = u8;
    this.pageSize = pageSize;
    this.totalPages = totalPages;
    this.data = new Uint8Array(totalPages * pageSize);
    this.covered = new Array(totalPages).fill(false);
    this.treeCovered = new Array(totalPages).fill(false);
    this.placedAt = new Map();   // page-record offset -> slot
    this.nextSequential = 0;
    this.visited = new Set();
    this.decodedPages = 0;
    this.mismatchedLen = null;
    this.outOfRangeSlot = null;
  }

  pageHeader(o) {
    const u8 = this.u8;
    if (o + 8 > u8.length) return null;
    const storedLen = le32(u8, o);
    const advance = le32(u8, o + 4);
    const payloadEnd = o + 8 + storedLen;
    if (advance !== 0 && storedLen <= MAX_PAGE_LEN && advance >= storedLen &&
        advance <= storedLen + MAX_PAGE_TRAILER && payloadEnd <= u8.length) {
      return { storedLen, advance, payloadStart: o + 8, payloadEnd };
    }
    return null;
  }

  isPageHeader(o) { return this.pageHeader(o) !== null; }

  decodePage(o) {
    const h = this.pageHeader(o);
    if (h === null) return null;
    let payload;
    try {
      payload = fastlzDecompress(this.u8.subarray(h.payloadStart, h.payloadEnd));
    } catch { return null; }
    let number = 0;
    if (h.payloadEnd + 4 <= this.u8.length) {
      const word = le32(this.u8, h.payloadEnd);
      if (word !== END_MARKER) number = word;
    }
    return { payload, number, advance: h.advance };
  }

  walkData(start) {
    const stack = [start];
    while (stack.length) {
      const o = stack.pop();
      if (!hasRecord(this.u8, o)) continue;
      if (this.visited.has(o)) {
        // Run-scanned earlier; the tree names it, so its slot is authoritative.
        if (this.placedAt.has(o)) this.treeCovered[this.placedAt.get(o)] = true;
        continue;
      }
      this.visited.add(o);
      const second = o + 8 <= this.u8.length ? le32(this.u8, o + 4) : 0;
      if (second === 0) this.pushPointerBlock(o, stack);
      else this.walkPageRun(o);
    }
  }

  pushPointerBlock(o, stack) {
    const targets = [];
    for (let e = 0; e < POINTER_BLOCK_ENTRIES; e++) {
      const eo = o + e * 8;
      if (!hasRecord(this.u8, eo)) break;
      const target = le32(this.u8, eo);
      const second = le32(this.u8, eo + 4);
      if (second !== 0) break; // ran off the pointer entries into other data
      if (target !== 0 && hasRecord(this.u8, target)) targets.push(target);
    }
    for (let k = targets.length - 1; k >= 0; k--) stack.push(targets[k]); // block order
  }

  walkPageRun(o) {
    let fromTree = true;
    for (;;) {
      const page = this.decodePage(o);
      if (page === null) return;
      this.decodedPages += 1;
      if (page.payload.length !== this.pageSize && this.mismatchedLen === null) {
        this.mismatchedLen = page.payload.length;
      }
      if (page.payload.length === this.pageSize) {
        const slot = page.number === 0 ? this.nextSequential : page.number;
        if (slot < this.totalPages) {
          if (fromTree || !this.treeCovered[slot]) {
            const st = slot * this.pageSize;
            const end = Math.min(st + this.pageSize, this.data.length);
            this.data.set(page.payload.subarray(0, end - st), st);
            this.covered[slot] = true;
            this.treeCovered[slot] = this.treeCovered[slot] || fromTree;
            this.placedAt.set(o, slot);
          }
          this.nextSequential = slot + 1;
        } else if (this.outOfRangeSlot === null) {
          this.outOfRangeSlot = slot;
        }
      }
      o = o + 8 + page.advance;
      if (!hasRecord(this.u8, o) || !this.isPageHeader(o)) return;
      if (this.visited.has(o)) return;
      this.visited.add(o);
      fromTree = false;
    }
  }
}

/** Decode a vulZ container into its logical image. Throws if a page is missing. */
function decodeVulz(u8) {
  if (u8.length < 0x40) throw new Error('vulZ container too short');
  const pageSize = le32(u8, VULZ_PAGE_SIZE_OFFSET);
  if (pageSize < 1024 || pageSize > MAX_PAGE_LEN) {
    throw new Error(`vulZ: implausible page size ${pageSize}`);
  }
  const totalLen = le32(u8, VULZ_TOTAL_EXPANDED_OFFSET) +
    le32(u8, VULZ_TOTAL_EXPANDED_OFFSET + 4) * 0x100000000;
  if (totalLen === 0) throw new Error('vulZ: zero total expanded length');
  const totalPages = Math.ceil(totalLen / pageSize);

  const walk = new VulzWalk(u8, pageSize, totalPages);
  walk.walkData(VULZ_WALK_START);

  const missing = walk.covered.reduce((acc, hit) => acc + (hit ? 0 : 1), 0);
  if (missing > 0) {
    throw new Error(
      `vulZ container stores only ${totalPages - missing} of ${totalPages} pages ` +
      `(page_size=${pageSize}, decoded=${walk.decodedPages}` +
      (walk.mismatchedLen !== null ? `, a page decoded to ${walk.mismatchedLen} bytes` : '') +
      (walk.outOfRangeSlot !== null ? `, a page addressed slot ${walk.outOfRangeSlot} past the image` : '') +
      ')');
  }
  return { data: walk.data.subarray(0, totalLen), pageSize, totalPages };
}

// ---- raw (decompressed) image parse ------------------------------------------
function detectIndexBase(faces, vertexCount) {
  let min = Infinity, max = 0;
  for (const f of faces) for (const idx of f) { if (idx < min) min = idx; if (idx > max) max = idx; }
  if (faces.length === 0) return 'zero';
  if (min === 0 && max < vertexCount) return 'zero';
  if (min >= 1 && max <= vertexCount) return 'one'; // Vulcan's native convention
  throw new Error(`face indices out of range: min=${min} max=${max} vertices=${vertexCount}`);
}

function parseRaw(u8) {
  if (u8.length < RAW_HEADER_LEN) throw new Error('raw image shorter than header');
  const vertexCount = be32(u8, RAW_VERTEX_COUNT_OFFSET);
  const faceCount = be32(u8, RAW_FACE_COUNT_OFFSET);
  if (vertexCount === 0 || faceCount === 0) {
    throw new Error(`invalid raw counts: vertices=${vertexCount} faces=${faceCount}`);
  }
  const faceStart = RAW_HEADER_LEN + vertexCount * RAW_VERTEX_SIZE;
  const trailerStart = faceStart + faceCount * RAW_FACE_SIZE;
  if (trailerStart > u8.length) {
    throw new Error(`raw image truncated: needs ${trailerStart} bytes, has ${u8.length}`);
  }

  const vertices = new Array(vertexCount);
  for (let n = 0; n < vertexCount; n++) {
    const o = RAW_HEADER_LEN + n * RAW_VERTEX_SIZE;
    const x = beF64(u8, o), y = beF64(u8, o + 8), z = beF64(u8, o + 16);
    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(z)) {
      throw new Error('vertex section contains non-finite coordinates');
    }
    vertices[n] = [x, y, z];
  }

  const rawFaces = new Array(faceCount);
  for (let n = 0; n < faceCount; n++) {
    const o = faceStart + n * RAW_FACE_SIZE;
    rawFaces[n] = [be32(u8, o), be32(u8, o + 4), be32(u8, o + 8)];
  }

  const indexBase = detectIndexBase(rawFaces, vertexCount);
  const shift = indexBase === 'one' ? 1 : 0;
  const faces = rawFaces.map(([a, b, c]) => [a - shift, b - shift, c - shift]);

  const bounds = boundsOf(vertices);
  const trailingAttributes = u8.subarray(trailerStart);
  return { vertexCount, faceCount, vertices, faces, indexBase, bounds, trailingAttributes };
}

function boundsOf(vertices) {
  const min = [Infinity, Infinity, Infinity];
  const max = [-Infinity, -Infinity, -Infinity];
  for (const v of vertices) for (let i = 0; i < 3; i++) {
    if (v[i] < min[i]) min[i] = v[i];
    if (v[i] > max[i]) max[i] = v[i];
  }
  return { min, max };
}

// ---- attributes + PNG thumbnail ----------------------------------------------
function indexOfSeq(hay, needle, from = 0) {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function parseAttributes(trailing) {
  let thumbnail = null;
  const png = indexOfSeq(trailing, [0x89, 0x50, 0x4e, 0x47]); // PNG signature
  if (png >= 0) {
    const iend = indexOfSeq(trailing, [0x49, 0x45, 0x4e, 0x44], png); // IEND
    if (iend >= 0) thumbnail = trailing.subarray(png, iend + 8); // +IEND+CRC
  }
  return { thumbnail, raw: trailing };
}

// ---- container header (diagnostic) -------------------------------------------
function readHeader(u8) {
  for (let i = 0; i < MAGIC.length; i++) {
    if (u8[i] !== MAGIC[i]) throw new Error('Not a Vulcan .00t (bad magic)');
  }
  return {
    pageSize: le32(u8, VULZ_PAGE_SIZE_OFFSET),
    totalExpanded: le32(u8, VULZ_TOTAL_EXPANDED_OFFSET) +
      le32(u8, VULZ_TOTAL_EXPANDED_OFFSET + 4) * 0x100000000,
    auxOffset: le32(u8, VULZ_AUX_OFFSET_OFFSET),
    auxLen: le32(u8, VULZ_AUX_LEN_OFFSET),
  };
}

// ---- top-level ---------------------------------------------------------------
/**
 * Parse a .00t file into vertices + faces.
 * @param {ArrayBuffer|Uint8Array} input
 * @returns {{magicOk, header, vertexCount, faceCount, vertices, faces,
 *            indexBase, bounds, attributes}}
 *   vertices: Array<[x,y,z]> (absolute doubles)
 *   faces:    Array<[a,b,c]> (zero-based indices into vertices)
 */
function parse00t(input) {
  const u8 = input instanceof Uint8Array ? input : new Uint8Array(input);
  const magicOk = MAGIC.every((m, i) => u8[i] === m);

  // vulZ containers are compressed; older/flat files are already raw.
  const image = magicOk ? decodeVulz(u8).data : u8;
  const raw = parseRaw(image);
  const attributes = parseAttributes(raw.trailingAttributes);

  return {
    magicOk,
    header: magicOk ? readHeader(u8) : null,
    vertexCount: raw.vertexCount,
    faceCount: raw.faceCount,
    vertices: raw.vertices,
    faces: raw.faces,
    indexBase: raw.indexBase,
    bounds: raw.bounds,
    attributes,
  };
}

/** Lightweight summary (counts, bounds, first vertex) without keeping geometry. */
function inspect(input) {
  const u8 = input instanceof Uint8Array ? input : new Uint8Array(input);
  const out = { fileSize: u8.length };
  out.magicOk = MAGIC.every((m, i) => u8[i] === m);
  if (!out.magicOk) {
    // Not a vulZ container — may still be a flat raw image; try to parse it.
    try {
      const raw = parseRaw(u8);
      out.vertexCount = raw.vertexCount;
      out.faceCount = raw.faceCount;
      out.bounds = raw.bounds;
      out.vertex0 = raw.vertices[0];
      out.indexBase = raw.indexBase;
    } catch (e) { out.error = e.message; }
    return out;
  }
  try {
    const decoded = decodeVulz(u8);
    out.header = readHeader(u8);
    out.pages = decoded.totalPages;
    const raw = parseRaw(decoded.data);
    out.vertexCount = raw.vertexCount;
    out.faceCount = raw.faceCount;
    out.bounds = raw.bounds;
    out.vertex0 = raw.vertices[0];
    out.indexBase = raw.indexBase;
    out.attributes = parseAttributes(raw.trailingAttributes);
  } catch (e) { out.error = e.message; }
  return out;
}

export {
  parse00t, inspect,
  decodeVulz, fastlzDecompress, parseRaw, detectIndexBase,
  readHeader, parseAttributes, boundsOf, MAGIC,
};
