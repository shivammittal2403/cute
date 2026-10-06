"""traceatlas.ingestion.magic_detector - Content-signature (magic byte) detection.

Never trusts filenames: identifies formats from leading bytes and structural
signatures. Returns a list of candidate (format, mime, confidence, signature)
tuples; multiple candidates are allowed and reconciled upstream.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MagicMatch:
    format: str
    mime: str
    confidence: float
    signature: str


# Prefix-based signatures: (offset, magic bytes, format, mime, confidence, label)
_PREFIX_SIGS: tuple[tuple[int, bytes, str, str, float, str], ...] = (
    (0, b"%PDF", "pdf", "application/pdf", 0.98, "%PDF header"),
    (0, b"PK\x03\x04", "zip", "application/zip", 0.9, "ZIP local file header"),
    (0, b"PK\x05\x06", "zip", "application/zip", 0.9, "ZIP empty archive"),
    (0, b"PK\x07\x08", "zip", "application/zip", 0.85, "ZIP spanned"),
    (0, b"\x1f\x8b", "gzip", "application/gzip", 0.97, "gzip magic"),
    (0, b"BZh", "bzip2", "application/x-bzip2", 0.97, "bzip2 magic"),
    (0, b"\xfd7zXZ\x00", "xz", "application/x-xz", 0.98, "xz stream"),
    (0, b"\x04\x22\x4d\x18", "lz4", "application/x-lz4", 0.95, "lz4 frame"),
    (0, b"(\xb5/\xfd", "zstd", "application/zstd", 0.95, "zstd frame"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "application/x-7z-compressed", 0.98, "7z signature"),
    (0, b"Rar!\x1a\x07", "rar", "application/vnd.rar", 0.97, "RAR signature"),
    (0, b"\x89PNG\r\n\x1a\n", "png", "image/png", 0.99, "PNG signature"),
    (0, b"\xff\xd8\xff", "jpeg", "image/jpeg", 0.97, "JPEG SOI"),
    (0, b"GIF87a", "gif", "image/gif", 0.98, "GIF87a"),
    (0, b"GIF89a", "gif", "image/gif", 0.98, "GIF89a"),
    (0, b"BM", "bmp", "image/bmp", 0.55, "BMP header (weak prefix)"),
    (0, b"II*\x00", "tiff", "image/tiff", 0.9, "TIFF LE"),
    (0, b"MM\x00*", "tiff", "image/tiff", 0.9, "TIFF BE"),
    (0, b"OggS", "ogg", "audio/ogg", 0.97, "Ogg capture pattern"),
    (0, b"fLaC", "flac", "audio/flac", 0.97, "FLAC marker"),
    (0, b"ID3", "mp3", "audio/mpeg", 0.9, "MP3 ID3 tag"),
    (0, b"\xff\xfb", "mp3", "audio/mpeg", 0.75, "MP3 frame sync"),
    (0, b"\xff\xf3", "mp3", "audio/mpeg", 0.75, "MP3 frame sync"),
    (0, b"RIFF", "riff", "application/octet-stream", 0.6, "RIFF chunk"),
    (0, b"\x1aE\xdf\xa3", "matroska", "video/x-matroska", 0.95, "EBML/MKV"),
    (0, b"\x00\x00\x01\xba", "mpeg", "video/mpeg", 0.9, "MPEG program stream"),
    (0, b"\x00\x00\x01\xb3", "mpeg", "video/mpeg", 0.9, "MPEG sequence header"),
    (0, b"\x7fELF", "elf", "application/x-executable", 0.99, "ELF binary"),
    (0, b"MZ", "pe", "application/x-dosexec", 0.6, "MZ/DOS header"),
    (0, b"SQLite format 3\x00", "sqlite", "application/vnd.sqlite3", 0.99, "SQLite header"),
    (0, b"\x00\x00,\x00", "warcs", "application/warc", 0.4, "weak (WARC?)"),
    (0, b"\x4d\x49\x4c\x56", "mil-std", "application/octet-stream", 0.9, "MIL-STD header"),
    (0, b"PAR2", "par2", "application/octet-stream", 0.8, "PAR2"),
    (0, b"!<arch>\ndebian-binary", "deb", "application/vnd.debian.binary-package", 0.95, "deb ar"),
    (0, b"%TSD-Header", "truecrypt", "application/octet-stream", 0.9, "TrueCrypt header"),
    (0, b"\xed\xab\xee\xdb", "rpm", "application/x-rpm", 0.97, "RPM lead"),
    (0, b"\xca\xfe\xba\xbe", "class_or_fatmacho", "application/octet-stream", 0.7, "CAFEBABE"),
    (0, b"ustar", "tar", "application/x-tar", 0.95, "ustar magic @257"),
)

# offset-tagged special checks handled separately below.

_TEXTUAL_HINTS: tuple[tuple[re.Pattern[bytes], str, str, float, str], ...] = (
    (re.compile(rb"^\s*<\?xml\b", re.I), "xml", "text/xml", 0.9, "XML declaration"),
    (re.compile(rb"^\s*<!DOCTYPE\s+html", re.I), "html", "text/html", 0.85, "HTML doctype"),
    (re.compile(rb"^\s*<html\b", re.I), "html", "text/html", 0.8, "html root"),
    (re.compile(rb"^\s*(FROM|MBOXRD|From ) .*", re.I), "mbox", "application/mbox", 0.55,
     "mbox From_ line"),
    (re.compile(rb"^HTTP/[01]\.\d \d{3}", re.I), "http-response", "message/http", 0.9,
     "HTTP status line"),
)

_WARC_RE = re.compile(rb"^WARC/1\.")
_STIX_RE = re.compile(rb'"spec_version"\s*:\s*"2\.\d')
_GEOJSON_HINT = re.compile(rb'"type"\s*:\s*"(FeatureCollection|Feature)"')


def detect_magic(head: bytes, *, size_hint: int | None = None) -> list[MagicMatch]:
    """Return content-signature matches for the first bytes of a file."""
    out: list[MagicMatch] = []
    if not head:
        return out

    for offset, sig, fmt, mime, conf, label in _PREFIX_SIGS:
        if offset == 0 and head.startswith(sig):
            out.append(MagicMatch(fmt, mime, conf, label))
        elif offset > 0 and len(head) > offset + len(sig) and head[offset:offset + len(sig)] == sig:
            out.append(MagicMatch(fmt, mime, conf, label))

    # tar: ustar magic at offset 257
    if head[257:262] == b"ustar":
        out.append(MagicMatch("tar", "application/x-tar", 0.97, "ustar @257"))

    # RIFF family refinement
    if head.startswith(b"RIFF") and len(head) >= 12:
        sub = head[8:12]
        mapping = {b"WAVE": ("wav", "audio/wav", "RIFF WAVE"),
                   b"AVI ": ("avi", "video/x-msvideo", "RIFF AVI"),
                   b"WEBP": ("webp", "image/webp", "RIFF WEBP"),
                   b"ANIM": ("webp", "image/webp", "RIFF WEBP anim")}
        if sub in mapping:
            fmt, mime, label = mapping[sub]
            out.append(MagicMatch(fmt, mime, 0.97, label))

    # ISO-BMFF family: ....ftyp
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"3gp4", b"3gp5", b"3gp6"):
            out.append(MagicMatch("3gp", "video/3gpp", 0.95, "ftyp 3GP"))
        elif brand in (b"M4A ", b"M4B ", b"mp42", b"isom", b"iso2", b"avc1", b"mp4v", b"MSNV"):
            mime = "audio/mp4" if brand in (b"M4A ", b"M4B ") else "video/mp4"
            fmt = "m4a" if mime == "audio/mp4" else "mp4"
            out.append(MagicMatch(fmt, mime, 0.9, f"ftyp {brand.decode(errors='replace')}"))
        else:
            out.append(MagicMatch("iso-bmff", "video/mp4", 0.7, "ftyp generic"))

    # HEIC/HEIF via ftyp brands
    if len(head) >= 12 and head[4:8] == b"ftyp" and head[8:12] in (b"heic", b"heix", b"mif1", b"msf1"):
        out.append(MagicMatch("heic", "image/heic", 0.9, "ftyp HEIC/HEIF"))

    # WARC / STIX / GeoJSON textual markers
    if _WARC_RE.match(head):
        out.append(MagicMatch("warc", "application/warc", 0.98, "WARC/1.x version record"))
    if _STIX_RE.search(head[:4096]):
        out.append(MagicMatch("stix2", "application/stix+json", 0.95, "STIX spec_version field"))
    if _GEOJSON_HINT.search(head[:4096]):
        out.append(MagicMatch("geojson", "application/geo+json", 0.9, "GeoJSON type member"))

    # JSON shape check (must be before generic text hints)
    stripped = head.lstrip()
    if stripped[:1] in (b"{", b"["):
        out.append(MagicMatch("json", "application/json", 0.6, "JSON-shaped start"))
    elif stripped[:5] == b"<?xml" or stripped[:1] == b"<":
        pass

    for rx, fmt, mime, conf, label in _TEXTUAL_HINTS:
        if rx.search(head[:4096]):
            out.append(MagicMatch(fmt, mime, conf, label))

    # mbox From_ line at very start (stronger signal than generic hint)
    if head.startswith(b"From "):
        out.append(MagicMatch("mbox", "application/mbox", 0.85, "mbox From_ separator"))

    # PCAP / PCAPNG
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        out.append(MagicMatch("pcap", "application/vnd.tcpdump.pcap", 0.98, "libpcap magic"))
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        out.append(MagicMatch("pcapng", "application/vnd.tcpdump.pcapng", 0.98, "PCAPNG SHB"))

    # OLE compound file (doc/xls/ppt/mdb legacy)
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        out.append(MagicMatch("ole", "application/x-ole-storage", 0.9, "OLE CFB header"))

    # EVTX
    if head[:8] == b"ElfFile\x00":
        out.append(MagicMatch("evtx", "application/evtx", 0.97, "EVTX header"))

    # DuckDB
    if head[16:24] == b"DUCK\x00\x00\x00\x00":
        out.append(MagicMatch("duckdb", "application/x-duckdb", 0.97, "DuckDB magic @16"))

    # Parquet / ORC / Avro container markers
    if head[:4] == b"PAR1":
        out.append(MagicMatch("parquet", "application/vnd.apache.parquet", 0.97, "PAR1"))
    if head[:3] == b"ORC":
        out.append(MagicMatch("orc", "application/x-orc", 0.9, "ORC"))
    if head[:4] == b"Obj\x01":
        out.append(MagicMatch("avro", "application/avro", 0.95, "Avro object container"))
    if head[:6] in (b"ARROW1", b"ARROW2"):
        out.append(MagicMatch("arrow", "application/vnd.apache.arrow.file", 0.95, "Arrow file"))
    if head[:4] == b"FEAT" or (head[2:6] == b"ARRO" and head[:2] == b"\xff\xff"):
        out.append(MagicMatch("feather", "application/vnd.apache.feather", 0.85, "Feather"))

    # GeoPackage (sqlite with gpkg metadata) — refine later via structure probe
    # MBTiles likewise.

    # Executable heuristics → quarantine flag source
    for m in list(out):
        if m.format in ("elf", "pe", "class_or_fatmacho"):
            out.append(MagicMatch(m.format + "_exec", m.mime, m.confidence,
                                  m.signature + " [executable]"))

    # Deduplicate by format keeping max confidence
    best: dict[str, MagicMatch] = {}
    for m in out:
        cur = best.get(m.format)
        if cur is None or m.confidence > cur.confidence:
            best[m.format] = m
    return sorted(best.values(), key=lambda m: -m.confidence)


def looks_binary(head: bytes) -> bool:
    """NUL-byte heuristic over a sample window."""
    return b"\x00" in head[:8192]
