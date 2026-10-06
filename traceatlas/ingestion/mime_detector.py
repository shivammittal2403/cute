"""traceatlas.ingestion.mime_detector - MIME type detection (stdlib mimetypes + registry).

Combines the OS mimetypes registry with an internal high-signal table so
results are deterministic across hosts (CI boxes often lack /etc/mime.types).
Used both to *supply* a MIME for detected formats and to compare against a
client-claimed MIME (which is never trusted, only recorded).
"""
from __future__ import annotations

import mimetypes
from typing import Optional

# High-signal overrides — deterministic regardless of host config.
_INTERNAL: dict[str, str] = {
    ".txt": "text/plain", ".log": "text/plain", ".md": "text/markdown",
    ".rst": "text/x-rst", ".rtf": "application/rtf", ".ini": "text/plain",
    ".cfg": "text/plain", ".conf": "text/plain", ".env": "text/plain",
    ".properties": "text/x-java-properties",
    ".json": "application/json", ".jsonl": "application/x-ndjson",
    ".ndjson": "application/x-ndjson", ".json5": "application/json5",
    ".yaml": "application/yaml", ".yml": "application/yaml",
    ".toml": "application/toml", ".xml": "application/xml",
    ".html": "text/html", ".htm": "text/html", ".xhtml": "application/xhtml+xml",
    ".csv": "text/csv", ".tsv": "text/tab-separated-values", ".psv": "text/csv",
    ".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".xls": "application/vnd.ms-excel", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".ppt": "application/vnd.ms-powerpoint", ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".pdf": "application/pdf", ".epub": "application/epub+zip",
    ".mobi": "application/x-mobipocket-ebook", ".djvu": "image/vnd.djvu",
    ".eml": "message/rfc822", ".msg": "application/vnd.ms-outlook",
    ".mbox": "application/mbox", ".pst": "application/vnd.ms-outlook-pst",
    ".ost": "application/vnd.ms-outlook-pst", ".vcf": "text/vcard", ".ics": "text/calendar",
    ".zip": "application/zip", ".tar": "application/x-tar", ".tgz": "application/gzip",
    ".gz": "application/gzip", ".bz2": "application/x-bzip2", ".xz": "application/x-xz",
    ".7z": "application/x-7z-compressed", ".rar": "application/vnd.rar",
    ".zst": "application/zstd", ".lz4": "application/x-lz4",
    ".sqlite": "application/vnd.sqlite3", ".db": "application/vnd.sqlite3",
    ".duckdb": "application/x-duckdb", ".dbf": "application/x-dbf",
    ".mdb": "application/x-msaccess", ".accdb": "application/x-msaccess",
    ".sql": "application/sql", ".parquet": "application/vnd.apache.parquet",
    ".arrow": "application/vnd.apache.arrow.file", ".feather": "application/vnd.apache.feather",
    ".avro": "application/avro", ".orc": "application/x-orc",
    ".graphml": "application/graphml+xml", ".gexf": "application/gexf+xml",
    ".gml": "text/x-gml", ".dot": "text/vnd.graphviz", ".gv": "text/vnd.graphviz",
    ".rdf": "application/rdf+xml", ".owl": "application/rdf+xml",
    ".ttl": "text/turtle", ".nt": "application/n-triples",
    ".stix": "application/stix+json", ".cef": "text/plain", ".leef": "text/plain",
    ".syslog": "text/plain", ".evtx": "application/evtx",
    ".pcap": "application/vnd.tcpdump.pcap", ".pcapng": "application/vnd.tcpdump.pcapng",
    ".zeek": "application/x-ndjson", ".sigmalist": "application/yaml",
    ".sigma": "application/yaml", ".yar": "text/plain", ".yara": "text/plain",
    ".rules": "text/plain",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".webp": "image/webp", ".gif": "image/gif", ".tif": "image/tiff",
    ".tiff": "image/tiff", ".bmp": "image/bmp", ".heic": "image/heic",
    ".heif": "image/heif", ".svg": "image/svg+xml", ".cr2": "image/x-canon-cr2",
    ".nef": "image/x-nikon-nef", ".arw": "image/x-sony-arw",
    ".mp4": "video/mp4", ".mov": "video/quicktime", ".avi": "video/x-msvideo",
    ".mkv": "video/x-matroska", ".webm": "video/webm", ".mpeg": "video/mpeg",
    ".mpg": "video/mpeg", ".m4v": "video/mp4", ".3gp": "video/3gpp",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".flac": "audio/flac",
    ".aac": "audio/aac", ".m4a": "audio/mp4", ".ogg": "audio/ogg",
    ".opus": "audio/opus", ".amr": "audio/amr",
    ".geojson": "application/geo+json", ".kml": "application/vnd.google-earth.kml+xml",
    ".kmz": "application/vnd.google-earth.kmz", ".gpx": "application/gpx+xml",
    ".gpkg": "application/geopackage+sqlite3", ".shp": "application/x-shapefile",
    ".tif_geo": "image/geotiff", ".mbtiles": "application/x-mbtiles",
    ".osm": "application/xml", ".pbf": "application/x-protobuf",
    ".wkt": "text/plain", ".wkb": "application/octet-stream",
    ".warc": "application/warc", ".warc.gz": "application/warc-gzip",
    ".wacz": "application/wacz+zip", ".mhtml": "multipart/related", ".mht": "multipart/related",
    ".har": "application/json", ".patch": "text/x-diff", ".diff": "text/x-diff",
    ".bundle": "application/x-git-bundle", ".spdx": "text/plain",
    ".sarif": "application/sarif+json", ".cdx.json": "application/vnd.cyclonedx+json",
    ".tf7z": "application/x-7z-compressed",
}

# Reverse: mime -> canonical extension (first wins)
_MIME_TO_EXT: dict[str, str] = {v: k for k, v in reversed(list(_INTERNAL.items()))}


def guess_mime_for_extension(ext: str) -> Optional[str]:
    ext = ext.lower()
    if not ext.startswith("."):
        ext = "." + ext
    if ext in _INTERNAL:
        return _INTERNAL[ext]
    return mimetypes.guess_type(f"x{ext}")[0]


def extension_for_mime(mime: str) -> Optional[str]:
    return _MIME_TO_EXT.get(mime.lower())


def normalize_mime(value: str | None) -> str | None:
    """Lowercase, strip params; map common aliases onto our canonical set."""
    if not value:
        return None
    v = value.split(";", 1)[0].strip().lower()
    aliases = {
        "text/yaml": "application/yaml",
        "application/x-yaml": "application/yaml",
        "application/x-ndjson": "application/x-ndjson",
        "text/json": "application/json",
        "application/x-sqlite3": "application/vnd.sqlite3",
        "text/x-python": "text/x-python",
        "application/octet-stream": "application/octet-stream",
        "text/xml": "application/xml",
        "text/csv; charset=utf-8": "text/csv",
    }
    return aliases.get(v, v or None)


def detect_mime_from_name(filename: str | None) -> Optional[str]:
    """Extension-based MIME suggestion — advisory only, never authoritative."""
    if not filename:
        return None
    lowered = filename.lower()
    # double extensions we care about
    for dbl in (".warc.gz", ".cdx.json", ".tar.gz", ".tar.bz2", ".tar.xz"):
        if lowered.endswith(dbl):
            return _INTERNAL.get(dbl) or guess_mime_for_extension(dbl)
    idx = lowered.rfind(".")
    if idx <= 0:
        return None
    return guess_mime_for_extension(lowered[idx:])
