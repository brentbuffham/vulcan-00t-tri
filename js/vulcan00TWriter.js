/**
 * vulcan00TWriter.js — write Maptek Vulcan .00t triangulations (raw layout)
 *
 * Emits the decompressed "raw image" form of the .00t geometry: a 120-byte
 * header, big-endian counts, big-endian f64 vertex triples, and big-endian
 * u32 face-index triples (written 1-based, Vulcan's canonical convention).
 * Output round-trips through vulcan00TParser.js `parse00t()`.
 *
 * NOTE: this produces the UNCOMPRESSED raw variant (no vulZ/FastLZ container).
 * The reference reader accepts it directly. Wrapping the image back into a
 * vulZ FastLZ container is a separate step and is not implemented here.
 *
 * See 00T_FORMAT.md for the full format specification.
 *
 * @module vulcan00TWriter
 */

const RAW_HEADER_LEN = 120;
const RAW_VERTEX_COUNT_OFFSET = 0x48;
const RAW_FACE_COUNT_OFFSET = 0x60;
const RAW_VERTEX_SIZE = 24;
const RAW_FACE_SIZE = 24;
const U32_MAX = 0xffffffff;

/**
 * Serialize a triangulation to a .00t raw image.
 *
 * @param {Object} mesh
 * @param {Array<[number,number,number]>} mesh.vertices  absolute XYZ coordinates
 * @param {Array<[number,number,number]>} mesh.faces     ZERO-based index triples
 * @param {Array<Uint8Array>} [mesh.facePayloads]        optional 12-byte per-face payloads
 * @param {Uint8Array} [mesh.header]                     optional 120-byte header to preserve
 *                                                       (counts are overwritten)
 * @param {Uint8Array} [mesh.trailingAttributes]         optional bytes appended after faces
 * @returns {ArrayBuffer}
 */
function write00t(mesh) {
  const { vertices, faces } = mesh;
  const facePayloads = mesh.facePayloads || null;
  const trailing = mesh.trailingAttributes || new Uint8Array(0);

  if (!Array.isArray(vertices) || !Array.isArray(faces)) {
    throw new Error('write00t: mesh.vertices and mesh.faces must be arrays');
  }
  const vertexCount = vertices.length;
  const faceCount = faces.length;
  if (vertexCount === 0 || faceCount === 0) {
    throw new Error(`write00t: empty mesh (vertices=${vertexCount} faces=${faceCount})`);
  }
  if (vertexCount > U32_MAX || faceCount > U32_MAX) {
    throw new Error('write00t: vertex/face count exceeds u32 range');
  }

  // validate coordinates
  for (let i = 0; i < vertexCount; i++) {
    const v = vertices[i];
    if (!v || v.length < 3 || !Number.isFinite(v[0]) || !Number.isFinite(v[1]) || !Number.isFinite(v[2])) {
      throw new Error(`write00t: vertex ${i} is not a finite [x,y,z]`);
    }
  }
  // validate indices (zero-based, in range)
  for (let i = 0; i < faceCount; i++) {
    const f = faces[i];
    if (!f || f.length < 3) throw new Error(`write00t: face ${i} is not an [a,b,c]`);
    for (let k = 0; k < 3; k++) {
      const idx = f[k];
      if (!Number.isInteger(idx) || idx < 0 || idx >= vertexCount) {
        throw new Error(`write00t: face ${i} index ${idx} out of range [0,${vertexCount})`);
      }
    }
  }

  const totalLen =
    RAW_HEADER_LEN + vertexCount * RAW_VERTEX_SIZE + faceCount * RAW_FACE_SIZE + trailing.length;
  const buf = new ArrayBuffer(totalLen);
  const u8 = new Uint8Array(buf);
  const dv = new DataView(buf);

  // header (preserve caller's if provided, else zero-filled) with counts stamped in
  if (mesh.header && mesh.header.length >= RAW_HEADER_LEN) {
    u8.set(mesh.header.subarray(0, RAW_HEADER_LEN), 0);
  }
  dv.setUint32(RAW_VERTEX_COUNT_OFFSET, vertexCount, false); // big-endian
  dv.setUint32(RAW_FACE_COUNT_OFFSET, faceCount, false);

  // vertices: three big-endian f64
  let off = RAW_HEADER_LEN;
  for (let i = 0; i < vertexCount; i++) {
    const v = vertices[i];
    dv.setFloat64(off, v[0], false);
    dv.setFloat64(off + 8, v[1], false);
    dv.setFloat64(off + 16, v[2], false);
    off += RAW_VERTEX_SIZE;
  }

  // faces: three big-endian u32 (1-based) + 12-byte payload
  for (let i = 0; i < faceCount; i++) {
    const f = faces[i];
    dv.setUint32(off, f[0] + 1, false);
    dv.setUint32(off + 4, f[1] + 1, false);
    dv.setUint32(off + 8, f[2] + 1, false);
    if (facePayloads && facePayloads[i]) {
      u8.set(facePayloads[i].subarray(0, 12), off + 12);
    }
    off += RAW_FACE_SIZE;
  }

  // trailing attributes
  if (trailing.length) u8.set(trailing, off);

  return buf;
}

export { write00t };
