"""traceatlas.ingestion.type_detector - Reconcile all format evidence.

Inputs: extension evidence, magic matches, MIME guesses (name-based and
content-based), supplied MIME from the client, structural probes. Output is a
single DetectionResult with ranked candidates, mismatch warnings, security
flags and quarantine decisions. Content always outranks filename.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .confidence import Confidence
from .container_detector import refine_ole_format, refine_sqlite_format, refine_zip_format
from .errors import ErrorCode
from .extension_detector import ExtensionEvidence, detect_extension
from .magic_detector import MagicMatch, detect_magic, looks_binary
from .mime_detector import detect_mime_from_name, normalize_mime

# Formats whose presence means "never execute; treat as potential malware"
EXECUTABLE_FORMATS = frozenset({"elf", "pe", "pe_exec", "elf_exec", "class_or_fatmacho",
                               "deb", "rpm", "macho"})

# formats that are containers we can safely recurse into
ARCHIVE_FORMATS = frozenset({"zip", "tar", "gzip", "bzip2", "xz", "7z", "rar",
                             "zstd", "lz4", "tar.gz"})


@dataclass(slots=True)
class FormatCandidate:
    format: str
    mime: Optional[str]
    confidence: Confidence
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"format": self.format, "mime": self.mime,
                "confidence": self.confidence.to_dict(), "evidence": list(self.evidence)}


@dataclass(slots=True)
class DetectionResult:
    detected_format: str
    detected_mime: Optional[str]
    extension: Optional[str]
    magic_signature: Optional[str]
    encoding: Optional[str]
    container: Optional[str]
    compression: Optional[str]
    candidates: list[FormatCandidate] = field(default_factory=list)
    schema_candidates: list[dict[str, Any]] = field(default_factory=list)
    parser_candidates: list[str] = field(default_factory=list)
    confidence: Confidence = field(default_factory=lambda: Confidence(0.0))
    security_risk: str = "low"                 # low | medium | high
    requires_quarantine: bool = False
    requires_manual_review: bool = False
    warnings: list[tuple[ErrorCode, str]] = field(default_factory=list)
    structure: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"detected_format": self.detected_format,
                "detected_mime": self.detected_mime, "extension": self.extension,
                "magic_signature": self.magic_signature, "encoding": self.encoding,
                "container": self.container, "compression": self.compression,
                "candidates": [c.to_dict() for c in self.candidates],
                "schema_candidates": self.schema_candidates,
                "parser_candidates": self.parser_candidates,
                "confidence": self.confidence.to_dict(),
                "security_risk": self.security_risk,
                "requires_quarantine": self.requires_quarantine,
                "requires_manual_review": self.requires_manual_review,
                "warnings": [[w[0].value, w[1]] for w in self.warnings],
                "structure": self.structure}


def _refine_content_format(fmt: str, head: bytes, sample_text: Optional[str]) -> tuple[str, Optional[str]]:
    """Return (format, container) after container-family refinement."""
    if fmt == "zip" and head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        refined = refine_zip_format(head)
        if refined:
            return refined, "zip"
    if fmt == "sqlite":
        refined = refine_sqlite_format(head)
        if refined:
            return refined, None
    if fmt == "ole":
        refined = refine_ole_format(head)
        if refined:
            return refined, "ole"
    if fmt == "json" and sample_text:
        try:
            obj = json.loads(sample_text)
        except Exception:
            obj = None
        if isinstance(obj, dict) and obj.get("type") == "FeatureCollection":
            return "geojson", None
        if isinstance(obj, dict) and str(obj.get("spec_version", "")).startswith("2."):
            return "stix2", None
        if isinstance(obj, dict) and "Version" in obj and "Runs" in obj:
            return "sarif", None
    if fmt == "xml" and sample_text:
        low = sample_text[:4096].lower()
        if "<graphml" in low:
            return "graphml", None
        if "<gexf" in low:
            return "gexf", None
        if "<kml" in low:
            return "kml", None
        if "<gpx" in low:
            return "gpx", None
        if "rdf:rdf" in low or "<rdf" in low:
            return "rdf", None
        if "<html" in low or "<!doctype html" in low:
            return "html", None
        if "<opensearchchangelog" in low or "<osm" in low:
            return "osm", None
    return fmt, None


def detect_type(head: bytes, *, filename: Optional[str] = None,
                supplied_mime: Optional[str] = None,
                encoding: Optional[str] = None,
                text_sample: Optional[str] = None) -> DetectionResult:
    ext_ev: Optional[ExtensionEvidence] = detect_extension(filename)
    magic_matches: list[MagicMatch] = detect_magic(head)
    warnings: list[tuple[ErrorCode, str]] = []

    # ---- build candidate map --------------------------------------------
    by_fmt: dict[str, FormatCandidate] = {}

    def add(fmt: str, mime: Optional[str], conf: Confidence, ev: str) -> None:
        cur = by_fmt.get(fmt)
        if cur is None:
            by_fmt[fmt] = FormatCandidate(fmt, mime, conf, (ev,))
        else:
            cur.confidence = cur.confidence.combine(conf)
            cur.evidence = tuple(sorted(set(cur.evidence) | {ev}))

    for m in magic_matches:
        add(m.format, m.mime, Confidence(m.confidence, "magic", ("magic",)), m.signature)

    if ext_ev and ext_ev.format_candidate:
        # extension alone caps at 0.5 — it can lie
        add(ext_ev.format_candidate, ext_ev.mime_candidate,
            Confidence(0.5, "extension", ("extension",)), f"extension {ext_ev.extension}")

    name_mime = detect_mime_from_name(filename)
    norm_supplied = normalize_mime(supplied_mime)

    # ---- pick best content candidate ------------------------------------
    top: Optional[FormatCandidate] = max(by_fmt.values(), key=lambda c: c.confidence.value) \
        if by_fmt else None

    # weak-JSON refinement using text sample even when only extension said json
    chosen_fmt = top.format if top else "unknown"
    chosen_container: Optional[str] = None
    if top and top.confidence.signals and "magic" in top.confidence.signals:
        chosen_fmt, chosen_container = _refine_content_format(top.format, head, text_sample)
        if chosen_fmt != top.format:
            rc = FormatCandidate(chosen_fmt, top.mime,
                                 Confidence(min(0.97, top.confidence.value + 0.02),
                                            "container-refinement", ("magic", "structure")),
                                 ("container member refinement",))
            by_fmt[chosen_fmt] = rc
            top = rc

    if top is None:
        if text_sample is not None and not looks_binary(head):
            add("text", "text/plain", Confidence(0.55, "no-magic+decodable", ("structure",)),
                "decodes as text, no known signature")
            top = by_fmt["text"]
        else:
            add("binary", "application/octet-stream",
                Confidence(0.5, "no-signature", ("structure",)), "unrecognized binary")
            top = by_fmt["binary"]

    # ---- mismatch handling ------------------------------------------------
    if ext_ev and ext_ev.format_candidate and chosen_fmt not in (
            ext_ev.format_candidate, ) and _formats_compatible(ext_ev.format_candidate, chosen_fmt) is False:
        warnings.append((ErrorCode.FORMAT_MISMATCH,
                         f"extension suggests '{ext_ev.format_candidate}' but content is '{chosen_fmt}'"))
    if norm_supplied:
        det_mime = normalize_mime(top.mime)
        if det_mime and norm_supplied != det_mime and not _mime_family_match(norm_supplied, det_mime):
            warnings.append((ErrorCode.FORMAT_MISMATCH,
                             f"supplied MIME '{norm_supplied}' disagrees with content '{det_mime}'"))

    # ---- security flags ----------------------------------------------------
    security_risk = "low"
    requires_quarantine = False
    if any(f in EXECUTABLE_FORMATS for f in by_fmt):
        security_risk = "high"
        requires_quarantine = True
        warnings.append((ErrorCode.EXECUTABLE_CONTENT, "executable container detected; will not parse"))
    if ext_ev and (ext_ev.suspicious_name or ext_ev.double_extension):
        security_risk = "high" if security_risk == "low" else security_risk
        warnings.append((ErrorCode.PATH_TRAVERSAL if ext_ev.suspicious_name
                         else ErrorCode.EXECUTABLE_CONTENT,
                         f"suspicious filename pattern: {ext_ev.filename}"))
        requires_quarantine = requires_quarantine or ext_ev.double_extension

    if top.confidence.value < 0.6:
        warnings.append((ErrorCode.LOW_CONFIDENCE_DETECTION,
                         f"detection confidence {top.confidence.value:.2f}"))
        requires_manual_review = True
    if chosen_fmt == "unknown":
        warnings.append((ErrorCode.UNKNOWN_FORMAT, "no format identified; generic extraction only"))

    compression = None
    if chosen_fmt in ("gzip", "bzip2", "xz", "zstd", "lz4"):
        compression = chosen_fmt
    elif chosen_container == "zip":
        compression = "deflate"

    return DetectionResult(
        detected_format=chosen_fmt,
        detected_mime=top.mime,
        extension=ext_ev.extension if ext_ev else None,
        magic_signature=top.evidence[0] if top.evidence else None,
        encoding=encoding,
        container=chosen_container or (chosen_fmt if chosen_fmt in ARCHIVE_FORMATS else None),
        compression=compression,
        candidates=sorted(by_fmt.values(), key=lambda c: -c.confidence.value),
        parser_candidates=[chosen_fmt],
        confidence=top.confidence,
        security_risk=security_risk,
        requires_quarantine=requires_quarantine,
        requires_manual_review=requires_manual_review,
        warnings=warnings,
    )


def _formats_compatible(ext_fmt: str, content_fmt: str) -> bool:
    """Tolerances: .md vs text, .jsonl vs json, OOXML variants vs zip etc."""
    ok = {
        "zip": {"docx", "xlsx", "xlsm", "pptx", "odt", "ods", "odp", "epub", "kmz", "wacz"},
        "json": {"jsonl", "stix2", "geojson", "sarif", "har", "jsonld"},
        "gzip": {"tar.gz"},
        "text": {"markdown", "log", "keyvalue", "rtf", "csv", "tsv", "psv", "yaml",
                 "toml", "syslog", "cef", "leef", "yara", "sigma", "ids_rules",
                 "sqldump", "diff", "gml", "dot", "turtle", "ntriples", "wkt"},
        "xml": {"graphml", "gexf", "kml", "gpx", "rdf", "osm", "html", "misp_xml",
                "openioc", "ooxml"},
        "sqlite": {"gpkg", "mbtiles"},
        "binary": set(),
    }
    if ext_fmt == content_fmt:
        return True
    groups = {
        "spreadsheet": {"csv", "tsv", "psv", "xlsx", "xls", "ods", "xlsm"},
        "document": {"pdf", "docx", "doc", "odt", "rtf", "epub"},
        "image": {"jpeg", "png", "gif", "webp", "tiff", "bmp", "heic", "svg", "raw"},
        "audio": {"mp3", "wav", "flac", "ogg", "m4a", "aac", "opus", "amr"},
        "video": {"mp4", "mov", "avi", "mkv", "webm", "mpeg", "3gp", "iso-bmff"},
    }
    for members in groups.values():
        if ext_fmt in members and content_fmt in members:
            return True
    return content_fmt in ok.get(ext_fmt, set())


def _mime_family_match(a: str, b: str) -> bool:
    fam_a, _, sub_a = a.partition("/")
    fam_b, _, sub_b = b.partition("/")
    if fam_a != fam_b:
        return False
    shared = {"xml", "json", "zip", "octet-stream", "plain"}
    return sub_a in shared or sub_b in shared
