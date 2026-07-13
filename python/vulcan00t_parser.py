#!/usr/bin/env python3
"""
vulcan00t_parser.py — Maptek Vulcan .00t triangulation parser (production format).

THE NEW PARSER (Python). Port of the reference decoder ``ROSETTA/tri00t.rs`` and
its JS twin ``js/vulcan00TParser.js``. A .00t file is a ``vulZ`` FastLZ-compressed,
paged container; decompress it and the geometry underneath is plain fixed-stride
binary:

    120-byte header
    vertex_count : BE u32 @ 0x48
    face_count   : BE u32 @ 0x60
    vertices     : N x (3 x BE f64)                 absolute coordinates
    faces        : M x (3 x BE u32 + 12-byte payload)   1-based index triples
    trailing attributes (ASCII tokens, optional PNG thumbnail)

There is NO delta/tag coordinate grammar and NO EdgeBreaker/CLERS face encoding —
those were artifacts of reading the compressed stream as the data model. See
``00T_FORMAT.md``. The container header is little-endian; the geometry fields
inside the decompressed image are big-endian.

All pre-2026-07-13 Python parser work (``oot_parser_v2.py`` and the delta / axis /
EdgeBreaker research scripts) is RETIRED and superseded by this file. Depends only
on the standard library.

Author: Brent Buffham / blastingapps.com + Claude (reverse-engineering).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

VULZ_MAGIC = b"\xea\xfb\xa7\x8avulZ"

RAW_HEADER_LEN = 120
RAW_VERTEX_COUNT_OFFSET = 0x48
RAW_FACE_COUNT_OFFSET = 0x60
RAW_VERTEX_SIZE = 24
RAW_FACE_SIZE = 24

VULZ_PAGE_SIZE_OFFSET = 0x14
VULZ_TOTAL_EXPANDED_OFFSET = 0x20
VULZ_AUX_OFFSET_OFFSET = 0x2C
VULZ_AUX_LEN_OFFSET = 0x34
VULZ_WALK_START = 0x3C
VULZ_PAGE_EXPANDED_LEN = 25_600

VULZ_POINTER_BLOCK_ENTRIES = 0x800 // 8
VULZ_END_MARKER = 0xFDFCFBFA

MAX_VULZ_PAGE_LEN = 4 << 20
MAX_VULZ_PAGE_TRAILER = 0x4000
MAX_VULZ_TOTAL_LEN = 512 << 20
MAX_VULZ_AUX_LEN = 128 << 20
MAX_VULZ_EXPANDED_BYTES = 512 << 20


class ReadError(Exception):
    """Any structural failure decoding a .00t container or its geometry."""


# ── low-level readers ────────────────────────────────────────────────────────
def _read_be_u32(b: bytes, off: int) -> int:
    if off + 4 > len(b):
        raise ReadError(f"unexpected EOF at 0x{off:x}; needed 4 bytes")
    return struct.unpack_from(">I", b, off)[0]


def _read_le_u32(b: bytes, off: int) -> int:
    if off + 4 > len(b):
        raise ReadError(f"unexpected EOF at 0x{off:x}; needed 4 bytes")
    return struct.unpack_from("<I", b, off)[0]


def _read_be_f64(b: bytes, off: int) -> float:
    if off + 8 > len(b):
        raise ReadError(f"unexpected EOF at 0x{off:x}; needed 8 bytes")
    return struct.unpack_from(">d", b, off)[0]


# ── FastLZ ────────────────────────────────────────────────────────────────────
def fastlz_decompress(data: bytes) -> bytes:
    """Decompress one FastLZ stream (level 1 or 2), as Vulcan stores per page.

    The level is the top three bits of the first control byte (0 -> level 1,
    1 -> level 2). Level 2 adds a looped extended match length and a 16-bit
    far-distance escape, per the reference ``fastlz.c``.
    """
    if not data:
        return b""
    level = data[0] >> 5
    if level == 0:
        level2 = False
    elif level == 1:
        level2 = True
    else:
        raise ReadError(f"unsupported FastLZ level {level + 1}")

    out = bytearray()
    i = 0
    first_op = True
    n = len(data)
    while i < n:
        op = i
        control = data[i]
        if first_op:
            control &= 0x1F
            first_op = False
        i += 1

        if control < 32:  # literal run
            length = control + 1
            end = i + length
            if end > n:
                raise ReadError(f"literal run exceeds page input at 0x{op:x}")
            if len(out) + length > MAX_VULZ_PAGE_LEN:
                raise ReadError("expanded page larger than expected")
            out += data[i:end]
            i = end
        else:  # back-reference match
            length = control >> 5
            ref = (control & 0x1F) << 8
            if length == 7:
                while True:
                    if i >= n:
                        raise ReadError("missing extended match length")
                    code = data[i]
                    i += 1
                    length += code
                    if len(out) + length + 2 > MAX_VULZ_PAGE_LEN:
                        raise ReadError("expanded page larger than expected")
                    if not level2 or code != 255:
                        break
            if i >= n:
                raise ReadError("missing match offset byte")
            code = data[i]
            i += 1
            ref += code
            if level2 and code == 255 and (control & 0x1F) == 0x1F:
                if i + 2 > n:
                    raise ReadError("missing far match offset")
                hi, lo = data[i], data[i + 1]
                i += 2
                ref = (hi << 8) + lo + 8191
            length += 2
            if len(out) + length > MAX_VULZ_PAGE_LEN:
                raise ReadError("expanded page larger than expected")
            if ref >= len(out):
                raise ReadError("match reference is before output start")
            start = len(out) - ref - 1
            for k in range(start, start + length):
                out.append(out[k])
        if len(out) > MAX_VULZ_PAGE_LEN:
            raise ReadError("expanded page larger than expected")
    return bytes(out)


# ── vulZ container walk ────────────────────────────────────────────────────────
@dataclass
class VulzArchive:
    data: bytes
    aux: bytes
    missing_pages: int
    total_pages: int
    page_size: int
    decoded_pages: int


def _has_record(b: bytes, off: int) -> bool:
    return off + 8 <= len(b)


class _Walk:
    def __init__(self, b: bytes, page_size: int, total_pages: int, ignore_numbers: bool):
        self.b = b
        self.page_size = page_size
        self.total_pages = total_pages
        self.ignore_numbers = ignore_numbers
        self.data = bytearray(total_pages * page_size)
        self.covered = [False] * total_pages
        self.tree_covered = [False] * total_pages
        self.placed_at: dict[int, int] = {}
        self.next_sequential = 0
        self.visited: set[int] = set()
        self.decoded_pages = 0

    def _page_header(self, off: int):
        if off + 8 > len(self.b):
            return None
        stored_len = struct.unpack_from("<I", self.b, off)[0]
        advance = struct.unpack_from("<I", self.b, off + 4)[0]
        payload_start = off + 8
        payload_end = payload_start + stored_len
        if (advance != 0 and stored_len <= MAX_VULZ_PAGE_LEN and advance >= stored_len
                and advance <= stored_len + MAX_VULZ_PAGE_TRAILER and payload_end <= len(self.b)):
            return stored_len, advance, payload_start, payload_end
        return None

    def _is_page_header(self, off: int) -> bool:
        return self._page_header(off) is not None

    def _decode_page(self, off: int):
        hdr = self._page_header(off)
        if hdr is None:
            return None
        _stored, advance, ps, pe = hdr
        try:
            payload = fastlz_decompress(self.b[ps:pe])
        except ReadError:
            return None
        number = 0
        if pe + 4 <= len(self.b):
            word = struct.unpack_from("<I", self.b, pe)[0]
            if word != VULZ_END_MARKER:
                number = word
        return payload, number, advance

    def walk_data(self, start: int) -> None:
        stack = [start]
        while stack:
            off = stack.pop()
            if not _has_record(self.b, off):
                continue
            if off in self.visited:
                slot = self.placed_at.get(off)
                if slot is not None:
                    self.tree_covered[slot] = True
                continue
            self.visited.add(off)
            second = _read_le_u32(self.b, off + 4) if off + 8 <= len(self.b) else 0
            if second == 0:
                self._push_block(off, stack)
            else:
                self._walk_run(off)

    def _push_block(self, off: int, stack: list) -> None:
        targets = []
        for entry in range(VULZ_POINTER_BLOCK_ENTRIES):
            eo = off + entry * 8
            if not _has_record(self.b, eo):
                break
            target = _read_le_u32(self.b, eo)
            second = _read_le_u32(self.b, eo + 4) if eo + 8 <= len(self.b) else 0
            if second != 0:
                break
            if target != 0 and _has_record(self.b, target):
                targets.append(target)
        stack.extend(reversed(targets))

    def _walk_run(self, off: int) -> None:
        from_tree = True
        while True:
            page = self._decode_page(off)
            if page is None:
                return
            payload, number, advance = page
            self.decoded_pages += 1
            if len(payload) == self.page_size:
                slot = self.next_sequential if (self.ignore_numbers or number == 0) else number
                if slot < self.total_pages:
                    if from_tree or not self.tree_covered[slot]:
                        start = slot * self.page_size
                        end = min(start + self.page_size, len(self.data))
                        self.data[start:end] = payload[: end - start]
                        self.covered[slot] = True
                        if from_tree:
                            self.tree_covered[slot] = True
                        self.placed_at[off] = slot
                    self.next_sequential = slot + 1
            off = off + advance + 8
            if not _has_record(self.b, off) or not self._is_page_header(off):
                return
            if off in self.visited:
                return
            self.visited.add(off)
            from_tree = False

    def walk_aux(self, start: int, aux_len: int) -> bytes:
        aux = bytearray()
        stack = [start]
        while stack:
            off = stack.pop()
            if len(aux) >= aux_len or not _has_record(self.b, off):
                continue
            if off in self.visited:
                continue
            self.visited.add(off)
            second = _read_le_u32(self.b, off + 4) if off + 8 <= len(self.b) else 0
            if second == 0:
                self._push_block(off, stack)
                continue
            run = off
            while True:
                page = self._decode_page(run)
                if page is None:
                    break
                payload, _n, advance = page
                copy_len = min(aux_len - len(aux), len(payload))
                aux += payload[:copy_len]
                run = run + advance + 8
                if (len(aux) >= aux_len or not _has_record(self.b, run) or run in self.visited):
                    break
                self.visited.add(run)
        return bytes(aux[:aux_len])


def decode_vulz_archive(b: bytes) -> VulzArchive:
    if len(b) < 0x40:
        raise ReadError(f"file too short: {len(b)} bytes")
    page_size = _read_le_u32(b, VULZ_PAGE_SIZE_OFFSET)
    if not (1024 <= page_size <= MAX_VULZ_PAGE_LEN):
        raise ReadError(f"implausible page size {page_size}")
    total_len = _read_le_u32(b, VULZ_TOTAL_EXPANDED_OFFSET) \
        | (_read_le_u32(b, VULZ_TOTAL_EXPANDED_OFFSET + 4) << 32)
    if total_len == 0 or total_len > MAX_VULZ_TOTAL_LEN:
        raise ReadError(f"total expanded length {total_len} out of range")
    aux_offset = _read_le_u32(b, VULZ_AUX_OFFSET_OFFSET)
    aux_len = _read_le_u32(b, VULZ_AUX_LEN_OFFSET)
    if aux_len > MAX_VULZ_AUX_LEN:
        raise ReadError(f"aux length {aux_len} out of range")
    if total_len + aux_len > MAX_VULZ_EXPANDED_BYTES:
        raise ReadError("combined expanded length out of range")

    def run(page_size_: int, ignore_numbers: bool) -> VulzArchive:
        total_pages = (total_len + page_size_ - 1) // page_size_
        w = _Walk(b, page_size_, total_pages, ignore_numbers)
        aux = w.walk_aux(aux_offset, aux_len) if aux_offset else b""
        w.walk_data(VULZ_WALK_START)
        missing = sum(1 for hit in w.covered if not hit)
        return VulzArchive(bytes(w.data[:total_len]), aux, missing,
                           total_pages, page_size_, w.decoded_pages)

    archive = run(page_size, False)
    # Recovery: trailer words that are not logical page numbers -> place
    # sequentially in walk order (accepted only if it then covers every page).
    if archive.missing_pages > 0:
        retry = run(page_size, True)
        if retry.missing_pages == 0:
            return retry
    return archive


def decode_vulz_bytes(b: bytes) -> bytes:
    archive = decode_vulz_archive(b)
    if archive.missing_pages > 0:
        raise ReadError(
            f"vulZ container stores only {archive.total_pages - archive.missing_pages} "
            f"of {archive.total_pages} pages (page_size={archive.page_size}, "
            f"decoded {archive.decoded_pages} records)")
    return archive.data


# ── raw geometry ───────────────────────────────────────────────────────────────
@dataclass
class Triangulation:
    vertices: List[Tuple[float, float, float]]
    faces: List[Tuple[int, int, int]]          # zero-based
    index_base: str                            # "zero" | "one"
    bounds_min: Tuple[float, float, float]
    bounds_max: Tuple[float, float, float]
    magic_ok: bool = True
    trailing_attributes: bytes = b""
    thumbnail: Optional[bytes] = field(default=None)

    @property
    def vertex_count(self) -> int:
        return len(self.vertices)

    @property
    def face_count(self) -> int:
        return len(self.faces)


def _detect_index_base(raw_faces: List[Tuple[int, int, int]], vertex_count: int) -> str:
    lo = min((i for f in raw_faces for i in f), default=0)
    hi = max((i for f in raw_faces for i in f), default=0)
    if lo == 0 and hi < vertex_count:
        return "zero"
    if lo >= 1 and hi <= vertex_count:
        return "one"  # Vulcan's native convention
    raise ReadError(f"face indices out of range: min={lo} max={hi} vertices={vertex_count}")


def _bounds(vertices):
    if not vertices:
        return (0.0, 0.0, 0.0), (0.0, 0.0, 0.0)
    mn = [float("inf")] * 3
    mx = [float("-inf")] * 3
    for v in vertices:
        for k in range(3):
            mn[k] = min(mn[k], v[k])
            mx[k] = max(mx[k], v[k])
    return tuple(mn), tuple(mx)


def _find_seq(hay: bytes, needle: bytes, start: int = 0) -> int:
    return hay.find(needle, start)


def parse_raw(image: bytes, magic_ok: bool = True) -> Triangulation:
    if len(image) < RAW_HEADER_LEN:
        raise ReadError(f"raw image too short: {len(image)} < {RAW_HEADER_LEN}")
    vertex_count = _read_be_u32(image, RAW_VERTEX_COUNT_OFFSET)
    face_count = _read_be_u32(image, RAW_FACE_COUNT_OFFSET)
    if vertex_count == 0 or face_count == 0:
        raise ReadError(f"invalid raw counts: vertices={vertex_count} faces={face_count}")

    face_start = RAW_HEADER_LEN + vertex_count * RAW_VERTEX_SIZE
    trailer_start = face_start + face_count * RAW_FACE_SIZE
    if trailer_start > len(image):
        raise ReadError(
            f"raw image truncated: needs {trailer_start} bytes, has {len(image)}")

    vertices = []
    for k in range(vertex_count):
        off = RAW_HEADER_LEN + k * RAW_VERTEX_SIZE
        x, y, z = struct.unpack_from(">ddd", image, off)
        vertices.append((x, y, z))

    raw_faces = []
    for k in range(face_count):
        off = face_start + k * RAW_FACE_SIZE
        a, b_, c = struct.unpack_from(">III", image, off)
        raw_faces.append((a, b_, c))

    index_base = _detect_index_base(raw_faces, vertex_count)
    shift = 1 if index_base == "one" else 0
    faces = [(a - shift, b_ - shift, c - shift) for (a, b_, c) in raw_faces]

    trailing = image[trailer_start:]
    thumbnail = None
    png = _find_seq(trailing, b"\x89PNG")
    if png >= 0:
        iend = _find_seq(trailing, b"IEND", png)
        if iend >= 0:
            thumbnail = trailing[png:iend + 8]

    mn, mx = _bounds(vertices)
    return Triangulation(vertices, faces, index_base, mn, mx,
                         magic_ok=magic_ok, trailing_attributes=trailing,
                         thumbnail=thumbnail)


# ── public API ──────────────────────────────────────────────────────────────────
def parse_00t(data: bytes) -> Triangulation:
    """Parse a .00t file (vulZ container or already-flat raw image)."""
    magic_ok = data[:8] == VULZ_MAGIC
    image = decode_vulz_bytes(data) if magic_ok else data
    return parse_raw(image, magic_ok=magic_ok)


def parse_00t_file(path: str) -> Triangulation:
    with open(path, "rb") as fh:
        return parse_00t(fh.read())


def inspect(data: bytes) -> dict:
    """Lightweight summary without keeping the geometry around."""
    out = {"file_size": len(data), "magic_ok": data[:8] == VULZ_MAGIC}
    try:
        tri = parse_00t(data)
        out.update(vertex_count=tri.vertex_count, face_count=tri.face_count,
                   index_base=tri.index_base, vertex0=tri.vertices[0],
                   bounds_min=tri.bounds_min, bounds_max=tri.bounds_max)
    except ReadError as exc:
        out["error"] = str(exc)
    return out


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python vulcan00t_parser.py <file.00t> [file.00t ...]")
        raise SystemExit(2)
    for p in sys.argv[1:]:
        try:
            t = parse_00t_file(p)
            print(f"{p}: {t.vertex_count} verts, {t.face_count} faces, "
                  f"index_base={t.index_base}, v0={t.vertices[0]}")
        except (OSError, ReadError) as exc:
            print(f"{p}: ERROR {exc}")
