"""traceatlas.ingestion.extension_detector - Filename-extension evidence.

Extension data is advisory ONLY: it contributes a candidate but content-based
detection always outranks it, and disagreement raises FORMAT_MISMATCH upstream.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from .mime_detector import guess_mime_for_extension

# extension -> canonical format token (must match parser supported_extensions)
_EXT_TO_FORMAT: dict[str, str] = {
    ".txt": "text", ".log": "log", ".md": "markdown", ".rst": "text",
    ".rtf": "rtf", ".ini": "keyvalue", ".cfg": "keyvalue", ".conf": "keyvalue",
    ".env": "keyvalue", ".properties": "keyvalue",
    ".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".json5": "json5",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml",
    ".xml": "xml", ".html": "html", ".htm": "html", ".xhtml": "html",
    ".csv": "csv", ".tsv": "tsv", ".psv": "psv",
    ".docx": "docx", ".odt": "odt", ".doc": "ole_doc",
    ".xlsx": "xlsx", ".xlsm": "xlsx", ".xls": "ole_xls", ".ods": "ods",
    ".pptx": "pptx", ".ppt": "ole_ppt", ".odp": "odp",
    ".pdf": "pdf", ".epub": "epub", ".mobi": "mobi", ".djvu": "djvu",
    ".eml": "eml", ".msg": "msg", ".mbox": "mbox", ".pst": "pst", ".ost": "pst",
    ".vcf": "vcf", ".ics": "ics",
    ".zip": "zip", ".tar": "tar", ".tgz": "tar.gz", ".gz": "gzip",
    ".bz2": "bzip2", ".xz": "xz", ".7z": "7z", ".rar": "rar",
    ".zst": "zstd", ".lz4": "lz4",
    ".sqlite": "sqlite", ".db": "sqlite", ".duckdb": "duckdb", ".dbf": "dbf",
    ".mdb": "mdb", ".accdb": "mdb", ".sql": "sqldump",
    ".parquet": "parquet", ".arrow": "arrow", ".feather": "feather",
    ".avro": "avro", ".orc": "orc",
    ".graphml": "graphml", ".gexf": "gexf", ".gml": "gml", ".dot": "dot", ".gv": "dot",
    ".rdf": "rdf", ".owl": "rdf", ".ttl": "turtle", ".nt": "ntriples",
    ".jsonld": "jsonld", ".stix": "stix2",
    ".sigma": "sigma", ".yar": "yara", ".yara": "yara", ".rules": "ids_rules",
    ".pcap": "pcap", ".pcapng": "pcapng", ".evtx": "evtx",
    ".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".webp": "webp", ".gif": "gif",
    ".tif": "tiff", ".tiff": "tiff", ".bmp": "bmp", ".heic": "heic", ".heif": "heif",
    ".svg": "svg", ".cr2": "raw", ".nef": "raw", ".arw": "raw",
    ".mp4": "mp4", ".mov": "mov", ".avi": "avi", ".mkv": "mkv", ".webm": "webm",
    ".mpeg": "mpeg", ".mpg": "mpeg", ".m4v": "mp4", ".3gp": "3gp",
    ".mp3": "mp3", ".wav": "wav", ".flac": "flac", ".aac": "aac", ".m4a": "m4a",
    ".ogg": "ogg", ".opus": "opus", ".amr": "amr",
    ".geojson": "geojson", ".kml": "kml", ".kmz": "kmz", ".gpx": "gpx",
    ".gpkg": "gpkg", ".shp": "shapefile", ".mbtiles": "mbtiles", ".osm": "osm",
    ".warc": "warc", ".wacz": "wacz", ".mhtml": "mhtml", ".mht": "mhtml",
    ".har": "har", ".patch": "diff", ".diff": "diff",
    ".sarif": "sarif", ".spdx": "spdx",
}

_SAFE = re.compile(r"^[A-Za-z0-9._\- ]*$")


@dataclass(frozen=True, slots=True)
class ExtensionEvidence:
    filename: str
    extension: Optional[str]
    format_candidate: Optional[str]
    mime_candidate: Optional[str]
    suspicious_name: bool = False       # control chars / traversal in name
    double_extension: bool = False      # e.g. invoice.pdf.exe


def detect_extension(filename: str | None) -> Optional[ExtensionEvidence]:
    if not filename:
        return None
    base = os.path.basename(filename.replace("\\", "/"))
    suspicious = (base != filename and ("/" in filename or "\\" in filename)) \
        or not _SAFE.match(base) or ".." in filename
    lowered = base.lower()
    ext: Optional[str] = None
    dbl = False
    for candidate in (".warc.gz", ".tar.gz", ".tar.bz2", ".tar.xz", ".cdx.json"):
        if lowered.endswith(candidate):
            ext = candidate
            break
    if ext is None:
        idx = lowered.rfind(".")
        ext = lowered[idx:] if 0 < idx < len(lowered) - 1 else None
    # double-extension deception check: .pdf.exe etc.
    stem = lowered[: lowered.rfind(".")] if ext else lowered
    double_extension = any(stem.endswith(e) for e in
                           (".pdf", ".doc", ".xls", ".jpg", ".png", ".zip", ".txt")) \
        and ext in (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".com", ".pif", ".jar")
    fmt = _EXT_TO_FORMAT.get(ext or "")
    mime = guess_mime_for_extension(ext) if ext else None
    return ExtensionEvidence(filename=base, extension=ext, format_candidate=fmt,
                             mime_candidate=mime, suspicious_name=suspicious,
                             double_extension=double_extension)


def format_from_extension(ext: str) -> Optional[str]:
    return _EXT_TO_FORMAT.get(ext.lower())
