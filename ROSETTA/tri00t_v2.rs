// tri00t_v2.rs — Vulcan .00t reference decoder, v2 (stale-page slot fix).
//
// Identical to tri00t.rs except the vulZ page-tree walk no longer lets a stale
// orphan page (an old copy of a rewritten page, left physically in the file and
// reachable via an `advance` chain) steal the sequential slot that a later
// tree-named live page owns. v1 assigned zero-numbered pages from ONE global
// `next_sequential` cursor in walk order, so a run that walked into an orphan
// advanced the cursor and pushed a genuine tree-named page out of range — it was
// then dropped, silently corrupting the geometry. Observed on a re-saved solid
// (SOLID_MM_O31A_0504_8123.00t): 741 vtx / 1475 faces, of which ~1067 faces
// decoded out of range, even though Vulcan itself reads the file fine.
//
// Fix: anchor each run's slot counter to the TREE-NAMING INDEX of its start page
// (the order pages are listed by the pointer tree's leaf blocks). Tree-named
// pages therefore always land in their own slot; only run-scanned continuations
// flow on from there. Flat/older files (root points straight at a contiguous
// run, so the start page is not individually tree-named) and the
// `ignore_numbers` recovery fall back to the global cursor, preserving v1
// behaviour for every non-stale file. See STALE_PAGE_FIX.md.
//
// v1's two recoveries do NOT cover this case: the page-size retry needs
// `missing_pages == total_pages`, and the sequential retry needs
// `missing_pages > 0 && decoded_pages == total_pages` and is deliberately gated
// away from stale-copy files. A stale-page file fills every slot (with one wrong
// page), so `missing_pages == 0` and neither fires — the corruption is silent.

use std::{
    error::Error,
    fmt, fs,
    io::{self, Write},
    path::Path,
};

const RAW_HEADER_LEN: usize = 120;
const RAW_VERTEX_COUNT_OFFSET: usize = 0x48;
const RAW_FACE_COUNT_OFFSET: usize = 0x60;
const RAW_VERTEX_SIZE: usize = 24;
const RAW_FACE_SIZE: usize = 24;
const VULZ_PAGE_SIZE_OFFSET: usize = 0x14;
const VULZ_TOTAL_EXPANDED_OFFSET: usize = 0x20;
const VULZ_AUX_OFFSET_OFFSET: usize = 0x2c;
const VULZ_AUX_LEN_OFFSET: usize = 0x34;
const VULZ_WALK_START: usize = 0x3c;
/// Typical decoded page size; only used as an allocation hint.
const VULZ_PAGE_EXPANDED_LEN: usize = 25_600;

pub const VULZ_MAGIC: &[u8; 8] = b"\xea\xfb\xa7\x8avulZ";

#[derive(Debug, PartialEq)]
pub struct Triangulation {
    vertices: Vec<Vertex>,
    faces: Vec<Face>,
    bounds: Bounds,
    index_base: IndexBase,
    raw_header: Vec<u8>,
    trailing_attributes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Vertex {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Face {
    indices: [u32; 3],
    payload: [u8; 12],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Triangle {
    pub face_index: usize,
    pub vertex_indices: [usize; 3],
    pub vertices: [Vertex; 3],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bounds {
    pub min: Vertex,
    pub max: Vertex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexBase {
    Zero,
    One,
}

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    ShortFile {
        needed: usize,
        actual: usize,
    },
    UnexpectedEof {
        offset: usize,
        needed: usize,
    },
    Overflow(&'static str),
    InvalidRawCounts {
        vertices: usize,
        faces: usize,
    },
    InvalidCoordinates,
    InvalidFaceIndices {
        min: u32,
        max: u32,
        vertex_count: usize,
    },
    InvalidVulzPage {
        offset: usize,
        message: String,
    },
    Allocation {
        section: &'static str,
        bytes: usize,
    },
    MissingVulzPages {
        missing: usize,
        total: usize,
        /// Page size from the header (`0x14`).
        page_size: usize,
        /// Page records the walk decoded (0 = the pointer tree was not walked).
        decoded_pages: usize,
        /// An example decoded page length that disagreed with `page_size`.
        mismatched_len: Option<usize>,
        /// An example page slot at or past `total` that a page addressed.
        out_of_range_slot: Option<usize>,
    },
}

impl Triangulation {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ReadError> {
        let bytes = fs::read(path).map_err(ReadError::Io)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReadError> {
        if bytes.starts_with(VULZ_MAGIC) {
            let raw = decode_vulz_bytes(bytes)?;
            return read_raw_triangulation(&raw);
        }

        read_raw_triangulation(bytes)
    }

    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    pub fn face_count(&self) -> usize {
        self.faces.len()
    }

    pub fn vertices(&self) -> &[Vertex] {
        &self.vertices
    }

    pub fn face(&self, index: usize) -> Option<Face> {
        self.faces.get(index).copied()
    }

    pub fn bounds(&self) -> Bounds {
        self.bounds
    }

    pub fn face_vertex_indices(&self, face_index: usize) -> Option<[usize; 3]> {
        self.face(face_index)
            .map(|face| face.indices_zero_based(self.index_base))
    }

    pub fn triangle(&self, face_index: usize) -> Option<Triangle> {
        let face = self.face(face_index)?;
        let vertex_indices = face.indices_zero_based(self.index_base);
        let vertices = [
            self.vertices.get(vertex_indices[0]).copied()?,
            self.vertices.get(vertex_indices[1]).copied()?,
            self.vertices.get(vertex_indices[2]).copied()?,
        ];

        Some(Triangle {
            face_index,
            vertex_indices,
            vertices,
        })
    }

    pub fn triangles(&self) -> impl Iterator<Item = Triangle> + '_ {
        (0..self.faces.len()).filter_map(|index| self.triangle(index))
    }

    pub fn face_vertex_indices_iter(&self) -> impl Iterator<Item = [usize; 3]> + '_ {
        self.faces
            .iter()
            .map(|face| face.indices_zero_based(self.index_base))
    }

    /// Construct a triangulation from a computed vertex list and face index triples.
    /// Face indices must be zero-based and within bounds. The raw header is populated
    /// with the counts so the result can be round-tripped through `write_mesh_with_progress`.
    pub fn from_vertices_and_faces(
        vertices: Vec<Vertex>,
        faces: Vec<[u32; 3]>,
    ) -> Result<Self, ReadError> {
        let vertex_count = vertices.len();
        let face_count = faces.len();
        if vertex_count == 0 || face_count == 0 {
            return Err(ReadError::InvalidRawCounts {
                vertices: vertex_count,
                faces: face_count,
            });
        }
        let vertex_count_u32 = u32::try_from(vertex_count)
            .map_err(|_| ReadError::Overflow("generated vertex count"))?;
        let face_count_u32 =
            u32::try_from(face_count).map_err(|_| ReadError::Overflow("generated face count"))?;
        if vertices
            .iter()
            .any(|vertex| !vertex.x.is_finite() || !vertex.y.is_finite() || !vertex.z.is_finite())
        {
            return Err(ReadError::InvalidCoordinates);
        }
        let (min_index, max_index) = faces
            .iter()
            .flatten()
            .fold((u32::MAX, 0u32), |(min, max), &index| {
                (min.min(index), max.max(index))
            });
        if max_index >= vertex_count_u32 {
            return Err(ReadError::InvalidFaceIndices {
                min: min_index,
                max: max_index,
                vertex_count,
            });
        }
        let bounds = Bounds::from_vertices(&vertices);
        let mut raw_header = vec![0u8; RAW_HEADER_LEN];
        raw_header[RAW_VERTEX_COUNT_OFFSET..RAW_VERTEX_COUNT_OFFSET + 4]
            .copy_from_slice(&vertex_count_u32.to_be_bytes());
        raw_header[RAW_FACE_COUNT_OFFSET..RAW_FACE_COUNT_OFFSET + 4]
            .copy_from_slice(&face_count_u32.to_be_bytes());
        let faces = faces
            .into_iter()
            .map(|indices| Face {
                indices,
                payload: [0; 12],
            })
            .collect();
        Ok(Self {
            vertices,
            faces,
            bounds,
            index_base: IndexBase::Zero,
            raw_header,
            trailing_attributes: Vec::new(),
        })
    }

    /// Write the triangulation in Vulcan `.00t` layout, invoking `progress`
    /// with a completion fraction in `0.0..=1.0` as vertices and faces are
    /// written. Pass `&mut |_| {}` when progress is not needed.
    pub fn write_00t_with_progress(
        &self,
        writer: &mut impl Write,
        progress: &mut dyn FnMut(f32),
    ) -> io::Result<()> {
        const PROGRESS_STRIDE: usize = 4096;
        let mut header = if self.raw_header.len() == RAW_HEADER_LEN {
            self.raw_header.clone()
        } else {
            vec![0; RAW_HEADER_LEN]
        };
        header[RAW_VERTEX_COUNT_OFFSET..RAW_VERTEX_COUNT_OFFSET + 4]
            .copy_from_slice(&(self.vertex_count() as u32).to_be_bytes());
        header[RAW_FACE_COUNT_OFFSET..RAW_FACE_COUNT_OFFSET + 4]
            .copy_from_slice(&(self.face_count() as u32).to_be_bytes());

        writer.write_all(&header)?;
        let vertex_count = self.vertex_count().max(1);
        let face_count = self.face_count().max(1);
        for (i, vertex) in self.vertices.iter().enumerate() {
            for value in vertex.as_array() {
                writer.write_all(&value.to_be_bytes())?;
            }
            if i % PROGRESS_STRIDE == 0 {
                progress(0.5 * i as f32 / vertex_count as f32);
            }
        }
        for (i, (face, indices)) in self
            .faces
            .iter()
            .zip(self.face_vertex_indices_iter())
            .enumerate()
        {
            // Vulcan's native convention is one-based. Always emit that
            // canonical form so a generated zero-based mesh which happens not
            // to reference vertex zero cannot be misdetected when reloaded.
            for index in indices {
                let one_based = u32::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "00t face index exceeds the format limit",
                        )
                    })?;
                writer.write_all(&one_based.to_be_bytes())?;
            }
            writer.write_all(&face.payload)?;
            if i % PROGRESS_STRIDE == 0 {
                progress(0.5 + 0.5 * i as f32 / face_count as f32);
            }
        }
        writer.write_all(&self.trailing_attributes)?;
        progress(1.0);
        Ok(())
    }
}

impl Vertex {
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub const fn as_array(self) -> [f64; 3] {
        [self.x, self.y, self.z]
    }
}

impl Face {
    pub fn indices_zero_based(self, index_base: IndexBase) -> [usize; 3] {
        match index_base {
            IndexBase::Zero => [
                self.indices[0] as usize,
                self.indices[1] as usize,
                self.indices[2] as usize,
            ],
            IndexBase::One => [
                (self.indices[0] - 1) as usize,
                (self.indices[1] - 1) as usize,
                (self.indices[2] - 1) as usize,
            ],
        }
    }
}

impl Bounds {
    pub fn from_vertices(vertices: &[Vertex]) -> Self {
        let mut min = Vertex::new(f64::INFINITY, f64::INFINITY, f64::INFINITY);
        let mut max = Vertex::new(f64::NEG_INFINITY, f64::NEG_INFINITY, f64::NEG_INFINITY);

        for vertex in vertices {
            min.x = min.x.min(vertex.x);
            min.y = min.y.min(vertex.y);
            min.z = min.z.min(vertex.z);
            max.x = max.x.max(vertex.x);
            max.y = max.y.max(vertex.y);
            max.z = max.z.max(vertex.z);
        }

        Self { min, max }
    }

    pub fn center(self) -> Vertex {
        Vertex::new(
            (self.min.x + self.max.x) * 0.5,
            (self.min.y + self.max.y) * 0.5,
            (self.min.z + self.max.z) * 0.5,
        )
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(err) => write!(f, "{err}"),
            ReadError::ShortFile { needed, actual } => {
                write!(
                    f,
                    "file is too short: needed {needed} bytes, found {actual}"
                )
            }
            ReadError::UnexpectedEof { offset, needed } => write!(
                f,
                "unexpected end of file at 0x{offset:x}; needed {needed} bytes"
            ),
            ReadError::Overflow(section) => write!(f, "{section} section overflow"),
            ReadError::InvalidRawCounts { vertices, faces } => {
                write!(f, "invalid raw counts: vertices={vertices} faces={faces}")
            }
            ReadError::InvalidCoordinates => {
                write!(f, "vertex section contains non-finite coordinates")
            }
            ReadError::InvalidFaceIndices {
                min,
                max,
                vertex_count,
            } => {
                write!(
                    f,
                    "face indices are outside the vertex range: min={min} max={max} vertices={vertex_count}"
                )
            }
            ReadError::InvalidVulzPage { offset, message } => {
                write!(f, "invalid vulZ page at 0x{offset:x}: {message}")
            }
            ReadError::Allocation { section, bytes } => {
                write!(f, "could not allocate {bytes} bytes for {section}")
            }
            ReadError::MissingVulzPages {
                missing,
                total,
                page_size,
                decoded_pages,
                mismatched_len,
                out_of_range_slot,
            } => {
                write!(
                    f,
                    "vulZ container stores only {} of {total} pages (page_size={page_size}, decoded {decoded_pages} page records",
                    total - missing
                )?;
                if let Some(len) = mismatched_len {
                    write!(
                        f,
                        ", but a page decoded to {len} bytes ≠ page_size {page_size} — the header's page-size field disagrees with the data"
                    )?;
                } else if *decoded_pages == 0 {
                    write!(
                        f,
                        ", none — the pointer tree at 0x{VULZ_WALK_START:x} was not walkable"
                    )?;
                }
                if let Some(slot) = out_of_range_slot {
                    write!(
                        f,
                        ", a page addressed slot {slot} past the image — page numbers are being misread"
                    )?;
                }
                write!(f, ")")
            }
        }
    }
}

impl Error for ReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ReadError::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// Fully decode a vulZ container; errors if any logical page is absent
/// (triangulations are stored contiguously, so a hole means corruption).
pub fn decode_vulz_bytes(bytes: &[u8]) -> Result<Vec<u8>, ReadError> {
    let archive = decode_vulz_archive(bytes)?;
    if archive.missing_pages > 0 {
        return Err(ReadError::MissingVulzPages {
            missing: archive.missing_pages,
            total: archive.total_pages,
            page_size: archive.page_size,
            decoded_pages: archive.decoded_pages,
            mismatched_len: archive.mismatched_len,
            out_of_range_slot: archive.out_of_range_slot,
        });
    }
    Ok(archive.data)
}

fn read_raw_triangulation(bytes: &[u8]) -> Result<Triangulation, ReadError> {
    if bytes.len() < RAW_HEADER_LEN {
        return Err(ReadError::ShortFile {
            needed: RAW_HEADER_LEN,
            actual: bytes.len(),
        });
    }

    let vertex_count = read_be_u32(bytes, RAW_VERTEX_COUNT_OFFSET)? as usize;
    let face_count = read_be_u32(bytes, RAW_FACE_COUNT_OFFSET)? as usize;

    if vertex_count == 0 || face_count == 0 {
        return Err(ReadError::InvalidRawCounts {
            vertices: vertex_count,
            faces: face_count,
        });
    }

    let vertex_bytes = vertex_count
        .checked_mul(RAW_VERTEX_SIZE)
        .ok_or(ReadError::Overflow("vertex"))?;
    let face_bytes = face_count
        .checked_mul(RAW_FACE_SIZE)
        .ok_or(ReadError::Overflow("face"))?;
    let face_start = RAW_HEADER_LEN
        .checked_add(vertex_bytes)
        .ok_or(ReadError::Overflow("vertex"))?;
    let trailer_start = face_start
        .checked_add(face_bytes)
        .ok_or(ReadError::Overflow("face"))?;

    if trailer_start > bytes.len() {
        return Err(ReadError::InvalidRawCounts {
            vertices: vertex_count,
            faces: face_count,
        });
    }

    let mut vertices = Vec::with_capacity(vertex_count);
    for n in 0..vertex_count {
        let offset = RAW_HEADER_LEN + n * RAW_VERTEX_SIZE;
        vertices.push(Vertex::new(
            read_be_f64(bytes, offset)?,
            read_be_f64(bytes, offset + 8)?,
            read_be_f64(bytes, offset + 16)?,
        ));
    }

    if !vertices
        .iter()
        .all(|vertex| vertex.x.is_finite() && vertex.y.is_finite() && vertex.z.is_finite())
    {
        return Err(ReadError::InvalidCoordinates);
    }

    let mut faces = Vec::with_capacity(face_count);
    for n in 0..face_count {
        let offset = face_start + n * RAW_FACE_SIZE;
        faces.push(Face {
            indices: [
                read_be_u32(bytes, offset)?,
                read_be_u32(bytes, offset + 4)?,
                read_be_u32(bytes, offset + 8)?,
            ],
            payload: bytes[offset + 12..offset + RAW_FACE_SIZE]
                .try_into()
                .expect("validated face record length"),
        });
    }

    let index_base = detect_index_base(&faces, vertex_count)?;

    Ok(Triangulation {
        bounds: Bounds::from_vertices(&vertices),
        vertices,
        faces,
        index_base,
        raw_header: bytes[..RAW_HEADER_LEN].to_vec(),
        trailing_attributes: bytes[trailer_start..].to_vec(),
    })
}

/// A decoded vulZ container.
///
/// `data` is the logical database image: each compressed page carries its
/// logical page number in the first trailer word (zero in older files, which
/// store pages strictly sequentially) and is placed at `number * page_size`.
/// Stale page versions can remain in the file; the pointer tree names each
/// page's current copy, so table-referenced pages override run-scanned ones.
/// `missing_pages` counts slots no page was recovered for.
///
/// `aux` is the auxiliary stream outside the page-numbered space (in design
/// databases: the PNG layer-preview gallery, which also carries layer names).
pub(crate) struct VulzArchive {
    pub data: Vec<u8>,
    pub aux: Vec<u8>,
    pub missing_pages: usize,
    pub total_pages: usize,
    /// Page size taken from the header (`0x14`).
    pub page_size: usize,
    /// Number of page records the walk decoded (diagnostic).
    pub decoded_pages: usize,
    /// An example decoded page length that did not match `page_size`, if any
    /// (diagnostic — points at a page-size field that disagrees with the data).
    pub mismatched_len: Option<usize>,
    /// An example page slot at or past `total_pages`, if any page addressed
    /// one (diagnostic — points at page numbers the walk misreads).
    pub out_of_range_slot: Option<usize>,
}

/// Largest stored/decoded page size considered plausible.
const MAX_VULZ_PAGE_LEN: usize = 4 << 20;
/// Largest gap between a page's stored data and the next page header
/// (page-number word, end marker, zero padding).
const MAX_VULZ_PAGE_TRAILER: usize = 0x4000;
/// Per-import ceilings for header-declared logical data. The combined limit
/// ensures the main image and auxiliary gallery cannot each consume the full
/// budget.
const MAX_VULZ_TOTAL_LEN: usize = 512 << 20;
const MAX_VULZ_AUX_LEN: usize = 128 << 20;
const MAX_VULZ_EXPANDED_BYTES: usize = 512 << 20;

/// Number of 8-byte entries in one vulZ pointer block.
const VULZ_POINTER_BLOCK_ENTRIES: usize = 0x800 / 8;

/// The `fa fb fc fd` end-of-page marker, as the little-endian word it reads
/// as when a trailer omits the page-number word.
const VULZ_END_MARKER: u32 = 0xfdfc_fbfa;

/// Decode a vulZ container by walking its pointer tree.
///
/// The file is a tree of 8-byte records. A record whose `second` word is zero
/// starts a pointer block: up to [`VULZ_POINTER_BLOCK_ENTRIES`] entries
/// `(target, 0)`, each pointing at another pointer block or at a page. A
/// record with `second != 0` is a page header `(stored_len, advance)`
/// followed by one FastLZ stream and a trailer carrying the logical page
/// number; `advance` spans the stored data plus the trailer, so pages written
/// back-to-back form runs that can also be walked at `offset + 8 + advance`.
///
/// The tree is authoritative: its leaf tables map every logical page to its
/// current copy (stale versions of rewritten pages remain in the file but are
/// not referenced). Run-scanning is kept for older/flat files whose root
/// points straight at the first page of a contiguous run; pages found only by
/// run-scanning never override tree-referenced ones.
///
/// The aux stream (offset in the header at [`VULZ_AUX_OFFSET_OFFSET`]) heads
/// its own small pointer tree and is walked first, so the data walk never
/// swallows gallery pages.
pub(crate) fn decode_vulz_archive(bytes: &[u8]) -> Result<VulzArchive, ReadError> {
    if bytes.len() < 0x40 {
        return Err(ReadError::ShortFile {
            needed: 0x40,
            actual: bytes.len(),
        });
    }
    let page_size = read_le_u32(bytes, VULZ_PAGE_SIZE_OFFSET)? as usize;
    if !(1024..=MAX_VULZ_PAGE_LEN).contains(&page_size) {
        return Err(ReadError::InvalidVulzPage {
            offset: VULZ_PAGE_SIZE_OFFSET,
            message: format!("implausible page size {page_size}"),
        });
    }
    let total_len_u64 = u64::from(read_le_u32(bytes, VULZ_TOTAL_EXPANDED_OFFSET)?)
        | (u64::from(read_le_u32(bytes, VULZ_TOTAL_EXPANDED_OFFSET + 4)?) << 32);
    if total_len_u64 == 0 || total_len_u64 > MAX_VULZ_TOTAL_LEN as u64 {
        return Err(ReadError::InvalidVulzPage {
            offset: VULZ_TOTAL_EXPANDED_OFFSET,
            message: format!(
                "total expanded length {total_len_u64} exceeds the import limit of {MAX_VULZ_TOTAL_LEN} bytes"
            ),
        });
    }
    let total_len = usize::try_from(total_len_u64).map_err(|_| ReadError::InvalidVulzPage {
        offset: VULZ_TOTAL_EXPANDED_OFFSET,
        message: format!("total expanded length {total_len_u64} is not addressable"),
    })?;
    let aux_offset = read_le_u32(bytes, VULZ_AUX_OFFSET_OFFSET)? as usize;
    let aux_len = read_le_u32(bytes, VULZ_AUX_LEN_OFFSET)? as usize;
    if aux_len > MAX_VULZ_AUX_LEN {
        return Err(ReadError::InvalidVulzPage {
            offset: VULZ_AUX_LEN_OFFSET,
            message: format!(
                "auxiliary expanded length {aux_len} exceeds the import limit of {MAX_VULZ_AUX_LEN} bytes"
            ),
        });
    }
    let expanded_len = total_len
        .checked_add(aux_len)
        .ok_or(ReadError::Overflow("vulZ expanded"))?;
    if expanded_len > MAX_VULZ_EXPANDED_BYTES {
        return Err(ReadError::InvalidVulzPage {
            offset: VULZ_TOTAL_EXPANDED_OFFSET,
            message: format!(
                "combined expanded length {expanded_len} exceeds the import limit of {MAX_VULZ_EXPANDED_BYTES} bytes"
            ),
        });
    }
    if aux_len > 0
        && !aux_offset
            .checked_add(8)
            .is_some_and(|end| end <= bytes.len())
    {
        return Err(ReadError::InvalidVulzPage {
            offset: VULZ_AUX_OFFSET_OFFSET,
            message: format!("auxiliary stream offset 0x{aux_offset:x} is outside the file"),
        });
    }

    let mut archive = walk_vulz(
        bytes, page_size, total_len, aux_offset, aux_len, false, None,
    )?;

    // Self-validating recovery for a header whose page-size field disagrees
    // with the actual page length (seen on some company 00t exports the tree
    // rewrite regressed): if the walk decoded pages but placed none because
    // every page decoded to a consistent other length, retry with that length
    // as the page size. Only accepted if the retry then covers every page, so
    // a wrong guess can never produce a worse result than the diagnostic error.
    if archive.missing_pages == archive.total_pages
        && let Some(actual) = archive.mismatched_len
        && actual != page_size
        && (1024..=MAX_VULZ_PAGE_LEN).contains(&actual)
    {
        let buffers = (archive.data, archive.aux);
        let retry = walk_vulz(
            bytes,
            actual,
            total_len,
            aux_offset,
            aux_len,
            false,
            Some(buffers),
        )?;
        if retry.missing_pages == 0 {
            return Ok(retry);
        }
        // Preserve the old fallback result for callers which inspect partial
        // archives, but rebuild it into the retry's buffers instead of
        // retaining two potentially huge logical images at once.
        archive = walk_vulz(
            bytes,
            page_size,
            total_len,
            aux_offset,
            aux_len,
            false,
            Some((retry.data, retry.aux)),
        )?;
    }

    // Self-validating recovery for trailer words that are not logical page
    // numbers (seen on a company topo whose pages addressed slots far past
    // the image): when the walk decoded exactly one record per logical page
    // — the tree referenced precisely the current page set, nothing stale —
    // but some page addressed an out-of-range slot, the numbers are not
    // trustworthy while the walk order is (leaf tables enumerate pages in
    // logical order). Retry placing pages sequentially in walk order,
    // accepted only if that covers every page. The exact-count requirement
    // keeps this away from files with stale copies, where sequential
    // placement could silently shift content.
    if archive.missing_pages > 0
        && archive.out_of_range_slot.is_some()
        && archive.decoded_pages == archive.total_pages
    {
        let retry = walk_vulz(
            bytes,
            page_size,
            total_len,
            aux_offset,
            aux_len,
            true,
            Some((archive.data, archive.aux)),
        )?;
        if retry.missing_pages == 0 {
            return Ok(retry);
        }
        archive = walk_vulz(
            bytes,
            page_size,
            total_len,
            aux_offset,
            aux_len,
            false,
            Some((retry.data, retry.aux)),
        )?;
    }

    Ok(archive)
}

/// Run the pointer-tree walk with a fixed page size and return the assembled
/// archive. Split out so [`decode_vulz_archive`] can retry with a different
/// page size when the header's field disagrees with the data, or with
/// `ignore_numbers` when the trailer words are not logical page numbers
/// (pages then place sequentially in walk order).
fn walk_vulz(
    bytes: &[u8],
    page_size: usize,
    total_len: usize,
    aux_offset: usize,
    aux_len: usize,
    ignore_numbers: bool,
    reuse: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<VulzArchive, ReadError> {
    let total_pages = total_len
        .checked_add(page_size - 1)
        .ok_or(ReadError::Overflow("vulZ page count"))?
        / page_size;
    let (mut data, mut aux) = reuse.unwrap_or_default();
    data.clear();
    if data.capacity() < total_len {
        data.try_reserve_exact(total_len)
            .map_err(|_| ReadError::Allocation {
                section: "vulZ logical image",
                bytes: total_len,
            })?;
    }
    data.resize(total_len, 0);
    let covered = try_false_vec(total_pages, "vulZ page coverage")?;
    let tree_covered = try_false_vec(total_pages, "vulZ tree page coverage")?;
    let mut walk = VulzWalk {
        bytes,
        page_size,
        total_pages,
        data,
        covered,
        tree_covered,
        placed_at: std::collections::HashMap::new(),
        tree_index: std::collections::HashMap::new(),
        tree_index_counter: 0,
        next_sequential: 0,
        visited: std::collections::HashSet::new(),
        decoded_pages: 0,
        mismatched_len: None,
        out_of_range_slot: None,
        ignore_numbers,
    };

    aux.clear();
    if aux_offset != 0 {
        walk.walk_aux(aux_offset, &mut aux, aux_len)?;
    }
    walk.walk_data(VULZ_WALK_START);

    aux.truncate(aux_len);
    let VulzWalk {
        data,
        covered,
        decoded_pages,
        mismatched_len,
        out_of_range_slot,
        ..
    } = walk;
    let missing_pages = covered.iter().filter(|&&hit| !hit).count();
    Ok(VulzArchive {
        data,
        aux,
        missing_pages,
        total_pages,
        page_size,
        decoded_pages,
        mismatched_len,
        out_of_range_slot,
    })
}

fn try_false_vec(count: usize, section: &'static str) -> Result<Vec<bool>, ReadError> {
    let mut out = Vec::new();
    out.try_reserve_exact(count)
        .map_err(|_| ReadError::Allocation {
            section,
            bytes: count.div_ceil(8),
        })?;
    out.resize(count, false);
    Ok(out)
}

/// One page decoded off a vulZ record: its payload plus the trailer number.
struct VulzPage {
    payload: Vec<u8>,
    number: usize,
    advance: usize,
}

struct VulzWalk<'a> {
    bytes: &'a [u8],
    page_size: usize,
    total_pages: usize,
    data: Vec<u8>,
    /// A page was placed in this slot.
    covered: Vec<bool>,
    /// The slot's page was referenced by the pointer tree (authoritative);
    /// run-scanned pages never overwrite it.
    tree_covered: Vec<bool>,
    /// Page-record offset -> slot it was placed in, to promote a run-scanned
    /// page to tree-covered when a pointer later references it directly.
    placed_at: std::collections::HashMap<usize, usize>,
    /// v2: page-record offset -> its slot in tree-naming order (the order the
    /// pointer tree's leaf blocks list pages). A run's slot counter starts from
    /// its start page's index here, so a stale orphan page reached by `advance`
    /// cannot consume the slot a later tree-named page owns.
    tree_index: std::collections::HashMap<usize, usize>,
    tree_index_counter: usize,
    next_sequential: usize,
    visited: std::collections::HashSet<usize>,
    /// Diagnostics: how many page records decoded during the walk (regardless
    /// of whether they were placed), and — if any decoded to a length other
    /// than `page_size` — one example length. These let a total decode failure
    /// tell a page-size mismatch (`decoded_pages > 0`, `mismatched_len` set)
    /// apart from an unwalkable pointer tree (`decoded_pages == 0`).
    decoded_pages: usize,
    mismatched_len: Option<usize>,
    /// An example page slot at or past `total_pages`, if any page addressed
    /// one (diagnostic — points at page numbers the walk misreads).
    out_of_range_slot: Option<usize>,
    /// Place every page sequentially in walk order, ignoring the trailer
    /// words (retry mode for files whose words are not logical page numbers).
    ignore_numbers: bool,
}

impl VulzWalk<'_> {
    fn page_header(&self, offset: usize) -> Option<(usize, usize, usize, usize)> {
        let header_end = offset.checked_add(8)?;
        let header = self.bytes.get(offset..header_end)?;
        let stored_len = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let advance = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let payload_end = header_end.checked_add(stored_len)?;
        let max_advance = stored_len.checked_add(MAX_VULZ_PAGE_TRAILER)?;
        (advance != 0
            && stored_len <= MAX_VULZ_PAGE_LEN
            && advance >= stored_len
            && advance <= max_advance
            && payload_end <= self.bytes.len())
        .then_some((stored_len, advance, header_end, payload_end))
    }

    /// Cheaply test whether `offset` looks like a page header (the same checks
    /// as [`Self::decode_page`] minus the FastLZ decompression). A pointer
    /// block reads as `(target, 0)`, so its zero `advance` word fails here —
    /// which lets a page run tell a following page from a following table.
    fn is_page_header(&self, offset: usize) -> bool {
        self.page_header(offset).is_some()
    }

    /// Read and decompress the page record at `offset`, or `None` if the
    /// bytes there do not form a plausible page.
    fn decode_page(&self, offset: usize) -> Option<VulzPage> {
        let (_stored_len, advance, payload_start, payload_end) = self.page_header(offset)?;
        let payload = fastlz_decompress(&self.bytes[payload_start..payload_end]).ok()?;
        // Some containers put the end marker directly after the stored data,
        // with no page-number word; reading the marker as a number would send
        // every page past the logical image, so such pages place sequentially.
        let number = self
            .bytes
            .get(payload_end..payload_end.checked_add(4)?)
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .filter(|&word| word != VULZ_END_MARKER)
            .unwrap_or(0) as usize;
        Some(VulzPage {
            payload,
            number,
            advance,
        })
    }

    /// Walk the data pointer tree from `start`, placing pages by their
    /// logical number (zero-numbered pages place sequentially in walk order,
    /// as older flat files store them).
    fn walk_data(&mut self, start: usize) {
        let mut stack = vec![start];
        while let Some(offset) = stack.pop() {
            if !has_vulz_record(self.bytes, offset) {
                continue;
            }
            if !self.visited.insert(offset) {
                // Already decoded during a run scan; the tree names it, so
                // its slot becomes authoritative.
                if let Some(&slot) = self.placed_at.get(&offset) {
                    self.tree_covered[slot] = true;
                }
                continue;
            }
            let second = offset
                .checked_add(4)
                .and_then(|at| read_le_u32(self.bytes, at).ok())
                .unwrap_or(0) as usize;
            if second == 0 {
                self.push_pointer_block(offset, &mut stack, true); // data walk records tree index
            } else {
                self.walk_page_run(offset);
            }
        }
    }

    /// Queue the entries of the pointer block at `offset` in walk order.
    ///
    /// `record_tree_index` is set only for the DATA walk: the aux stream (PNG
    /// gallery) is a separate page space and must not consume data slot indices.
    fn push_pointer_block(&mut self, offset: usize, stack: &mut Vec<usize>, record_tree_index: bool) {
        let mut targets = Vec::new();
        for entry in 0..VULZ_POINTER_BLOCK_ENTRIES {
            let Some(entry_offset) = entry
                .checked_mul(8)
                .and_then(|relative| offset.checked_add(relative))
            else {
                break;
            };
            if !has_vulz_record(self.bytes, entry_offset) {
                break;
            }
            let target = read_le_u32(self.bytes, entry_offset).unwrap_or(0) as usize;
            let second = entry_offset
                .checked_add(4)
                .and_then(|at| read_le_u32(self.bytes, at).ok())
                .unwrap_or(0);
            if second != 0 {
                // Ran off the pointer entries into other data.
                break;
            }
            if target != 0 && has_vulz_record(self.bytes, target) {
                targets.push(target);
            }
        }
        // v2: record the tree-naming order of page-header targets. A page's
        // record carries a non-zero `second` word (its `advance`); a nested
        // pointer block's `second` is zero. Its index here is the authoritative
        // slot when trailer page-numbers are absent, which is what stops a stale
        // orphan page in an advance-chain from stealing a live page's slot.
        if record_tree_index {
            for &target in &targets {
                let is_page = target
                    .checked_add(4)
                    .and_then(|at| read_le_u32(self.bytes, at).ok())
                    .is_some_and(|second| second != 0);
                if is_page && !self.tree_index.contains_key(&target) {
                    self.tree_index.insert(target, self.tree_index_counter);
                    self.tree_index_counter += 1;
                }
            }
        }
        // LIFO stack: reverse so entries are visited in block order.
        stack.extend(targets.into_iter().rev());
    }

    /// Decode the page at `offset` (already marked visited) and the
    /// back-to-back pages following it. The first page is tree-referenced;
    /// the rest are run-scanned and yield to tree-referenced copies.
    fn walk_page_run(&mut self, mut offset: usize) {
        let mut from_tree = true;
        // v2: anchor this run's slot counter to the tree-naming index of its
        // START page, not the single global `next_sequential`. A tree-named page
        // then always lands in its own slot; run-scanned continuations flow on
        // from there. Flat/older files (start page not individually tree-named)
        // and the `ignore_numbers` recovery fall back to the global cursor.
        let mut run_slot = if self.ignore_numbers {
            self.next_sequential
        } else {
            self.tree_index
                .get(&offset)
                .copied()
                .unwrap_or(self.next_sequential)
        };
        loop {
            let Some(page) = self.decode_page(offset) else {
                return;
            };
            self.decoded_pages += 1;
            if page.payload.len() != self.page_size && self.mismatched_len.is_none() {
                self.mismatched_len = Some(page.payload.len());
            }
            if page.payload.len() == self.page_size {
                let slot = if self.ignore_numbers || page.number == 0 {
                    run_slot
                } else {
                    page.number
                };
                // Sample files carry one spare page past the stated total;
                // anything beyond the logical image is ignored (and must not
                // advance the sequential cursor, or one bad number would push
                // every following zero-numbered page out of range too).
                if slot < self.total_pages {
                    if from_tree || !self.tree_covered[slot] {
                        let Some(start) = slot.checked_mul(self.page_size) else {
                            return;
                        };
                        let end = start.saturating_add(self.page_size).min(self.data.len());
                        let Some(destination) = self.data.get_mut(start..end) else {
                            return;
                        };
                        destination.copy_from_slice(&page.payload[..destination.len()]);
                        self.covered[slot] = true;
                        self.tree_covered[slot] |= from_tree;
                        self.placed_at.insert(offset, slot);
                    }
                    run_slot = slot.saturating_add(1);
                    self.next_sequential = self.next_sequential.max(slot.saturating_add(1));
                } else if self.out_of_range_slot.is_none() {
                    self.out_of_range_slot = Some(slot);
                }
            }
            let Some(next_offset) = page
                .advance
                .checked_add(8)
                .and_then(|advance| offset.checked_add(advance))
            else {
                return;
            };
            offset = next_offset;
            // End the run without claiming its terminating offset unless that
            // offset is itself another page. A run's end frequently lands on a
            // pointer/table block that the tree directory also points at (its
            // leaf lists the pages of the *next* group); marking it visited here
            // would make walk_data skip that whole subtree and drop every page
            // it references. Leaving it unvisited lets the tree traverse it.
            if !has_vulz_record(self.bytes, offset) || !self.is_page_header(offset) {
                return;
            }
            if !self.visited.insert(offset) {
                return;
            }
            from_tree = false;
        }
    }

    /// Walk the aux pointer tree from `start`, concatenating page payloads in
    /// walk order until `aux_len` bytes are collected. Aux pages are not part
    /// of the numbered page space and may be shorter than a data page.
    fn walk_aux(
        &mut self,
        start: usize,
        aux: &mut Vec<u8>,
        aux_len: usize,
    ) -> Result<(), ReadError> {
        let mut stack = vec![start];
        while let Some(offset) = stack.pop() {
            if aux.len() >= aux_len || !has_vulz_record(self.bytes, offset) {
                continue;
            }
            if !self.visited.insert(offset) {
                continue;
            }
            let second = offset
                .checked_add(4)
                .and_then(|at| read_le_u32(self.bytes, at).ok())
                .unwrap_or(0) as usize;
            if second == 0 {
                self.push_pointer_block(offset, &mut stack, false); // aux space: not data slots
                continue;
            }
            let mut run_offset = offset;
            while let Some(page) = self.decode_page(run_offset) {
                let remaining = aux_len.saturating_sub(aux.len());
                let copy_len = remaining.min(page.payload.len());
                aux.try_reserve_exact(copy_len)
                    .map_err(|_| ReadError::Allocation {
                        section: "vulZ auxiliary stream",
                        bytes: aux_len,
                    })?;
                aux.extend_from_slice(&page.payload[..copy_len]);
                let Some(next_offset) = page
                    .advance
                    .checked_add(8)
                    .and_then(|advance| run_offset.checked_add(advance))
                else {
                    break;
                };
                run_offset = next_offset;
                if aux.len() >= aux_len
                    || !has_vulz_record(self.bytes, run_offset)
                    || !self.visited.insert(run_offset)
                {
                    break;
                }
            }
        }
        Ok(())
    }
}

fn has_vulz_record(bytes: &[u8], offset: usize) -> bool {
    offset.checked_add(8).is_some_and(|end| end <= bytes.len())
}

/// Decompress one FastLZ stream (as Vulcan stores per page). The level is
/// carried in the top three bits of the first control byte — 0 for level 1,
/// 1 for level 2 (used for less-compressible/newer content). Level 2 extends
/// level 1 with a looped extended match length and a 16-bit far-distance
/// escape, per the reference `fastlz.c`.
fn fastlz_decompress(input: &[u8]) -> Result<Vec<u8>, ReadError> {
    let Some(&first) = input.first() else {
        return Ok(Vec::new());
    };
    let level2 = match first >> 5 {
        0 => false,
        1 => true,
        other => {
            return Err(ReadError::InvalidVulzPage {
                offset: 0,
                message: format!("unsupported FastLZ level {}", other + 1),
            });
        }
    };

    let mut input_offset = 0;
    let mut output = Vec::with_capacity(VULZ_PAGE_EXPANDED_LEN);
    let mut first_op = true;

    while input_offset < input.len() {
        let op_offset = input_offset;
        let mut control = input[input_offset];
        if first_op {
            // The level marker lives in the first op's top bits; the op
            // itself is always a literal run.
            control &= 0x1f;
            first_op = false;
        }
        input_offset += 1;

        if control < 32 {
            let len = control as usize + 1;
            let end = input_offset
                .checked_add(len)
                .ok_or_else(|| ReadError::InvalidVulzPage {
                    offset: op_offset,
                    message: "literal run length overflows".to_string(),
                })?;
            if end > input.len() {
                return Err(ReadError::InvalidVulzPage {
                    offset: op_offset,
                    message: "literal run exceeds page input".to_string(),
                });
            }
            if output.len().saturating_add(len) > MAX_VULZ_PAGE_LEN {
                return Err(ReadError::InvalidVulzPage {
                    offset: op_offset,
                    message: "expanded page is larger than expected".to_string(),
                });
            }
            output.extend_from_slice(&input[input_offset..end]);
            input_offset = end;
        } else {
            let mut len = (control >> 5) as usize;
            let mut reference_offset = ((control & 0x1f) as usize) << 8;

            if len == 7 {
                loop {
                    if input_offset >= input.len() {
                        return Err(ReadError::InvalidVulzPage {
                            offset: op_offset,
                            message: "missing extended match length".to_string(),
                        });
                    }
                    let code = input[input_offset];
                    input_offset += 1;
                    len = len.checked_add(code as usize).ok_or_else(|| {
                        ReadError::InvalidVulzPage {
                            offset: op_offset,
                            message: "extended match length overflows".to_string(),
                        }
                    })?;
                    // Reject attacker-controlled expansion while reading the
                    // length bytes, before reserving or copying any match.
                    if output.len().saturating_add(len).saturating_add(2) > MAX_VULZ_PAGE_LEN {
                        return Err(ReadError::InvalidVulzPage {
                            offset: op_offset,
                            message: "expanded page is larger than expected".to_string(),
                        });
                    }
                    if !level2 || code != 255 {
                        break;
                    }
                }
            }

            if input_offset >= input.len() {
                return Err(ReadError::InvalidVulzPage {
                    offset: op_offset,
                    message: "missing match offset byte".to_string(),
                });
            }

            let code = input[input_offset];
            input_offset += 1;
            reference_offset += code as usize;

            if level2 && code == 255 && control & 0x1f == 0x1f {
                // Far match: distance is a 16-bit value biased past the
                // 13-bit range of the short form.
                if input_offset + 2 > input.len() {
                    return Err(ReadError::InvalidVulzPage {
                        offset: op_offset,
                        message: "missing far match offset".to_string(),
                    });
                }
                let hi = input[input_offset] as usize;
                let lo = input[input_offset + 1] as usize;
                input_offset += 2;
                reference_offset = (hi << 8) + lo + 8191;
            }

            len = len
                .checked_add(2)
                .ok_or_else(|| ReadError::InvalidVulzPage {
                    offset: op_offset,
                    message: "match length overflows".to_string(),
                })?;

            let expanded_len =
                output
                    .len()
                    .checked_add(len)
                    .ok_or_else(|| ReadError::InvalidVulzPage {
                        offset: op_offset,
                        message: "expanded page length overflows".to_string(),
                    })?;
            if expanded_len > MAX_VULZ_PAGE_LEN {
                return Err(ReadError::InvalidVulzPage {
                    offset: op_offset,
                    message: "expanded page is larger than expected".to_string(),
                });
            }

            if reference_offset >= output.len() {
                return Err(ReadError::InvalidVulzPage {
                    offset: op_offset,
                    message: "match reference is before output start".to_string(),
                });
            }

            let start = output.len() - reference_offset - 1;
            let reference_end =
                start
                    .checked_add(len)
                    .ok_or_else(|| ReadError::InvalidVulzPage {
                        offset: op_offset,
                        message: "match reference length overflows".to_string(),
                    })?;
            for reference_index in start..reference_end {
                if reference_index >= output.len() {
                    return Err(ReadError::InvalidVulzPage {
                        offset: op_offset,
                        message: "match reference exceeded output".to_string(),
                    });
                }
                output.push(output[reference_index]);
            }
        }

        if output.len() > MAX_VULZ_PAGE_LEN {
            return Err(ReadError::InvalidVulzPage {
                offset: op_offset,
                message: "expanded page is larger than expected".to_string(),
            });
        }
    }

    Ok(output)
}

fn detect_index_base(faces: &[Face], vertex_count: usize) -> Result<IndexBase, ReadError> {
    let max_index = faces
        .iter()
        .flat_map(|face| face.indices)
        .max()
        .unwrap_or(0);
    let min_index = faces
        .iter()
        .flat_map(|face| face.indices)
        .min()
        .unwrap_or(0);

    if min_index == 0 && max_index < vertex_count as u32 {
        Ok(IndexBase::Zero)
    } else if min_index >= 1 && max_index <= vertex_count as u32 {
        // `max_index == vertex_count` can only be 1-based; when the mesh never
        // references index 0 *or* the last vertex, both interpretations are
        // in-range. Vulcan writes 1-based indices, so prefer that, but a
        // zero-based mesh that happens to skip both boundary vertices would be
        // misread here — leave a trace for diagnosing shifted geometry.
        if max_index < vertex_count as u32 {
            log::warn!(
                "00t face indices are ambiguous (min {min_index}, max {max_index}, \
                 {vertex_count} vertices; neither vertex 0 nor the last vertex is referenced); \
                 assuming 1-based per the Vulcan convention"
            );
        }
        Ok(IndexBase::One)
    } else {
        Err(ReadError::InvalidFaceIndices {
            min: min_index,
            max: max_index,
            vertex_count,
        })
    }
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, ReadError> {
    let end = offset
        .checked_add(4)
        .ok_or(ReadError::Overflow("u32 byte range"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or(ReadError::UnexpectedEof { offset, needed: 4 })?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, ReadError> {
    let end = offset
        .checked_add(4)
        .ok_or(ReadError::Overflow("u32 byte range"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or(ReadError::UnexpectedEof { offset, needed: 4 })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_be_f64(bytes: &[u8], offset: usize) -> Result<f64, ReadError> {
    let end = offset
        .checked_add(8)
        .ok_or(ReadError::Overflow("f64 byte range"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or(ReadError::UnexpectedEof { offset, needed: 8 })?;
    Ok(f64::from_be_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}
