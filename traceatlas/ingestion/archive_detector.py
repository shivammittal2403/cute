"""traceatlas.ingestion.archive_detector - Archive identification + safety audit.

Two responsibilities:
1. Identify archive containers (zip/tar/gz/bz2/xz) and list members WITHOUT
   extracting anything.
2. Run the pre-extraction security audit (path traversal, absolute paths,
   symlink/hardlink members, oversized members, member counts, compression
   ratio estimates, encryption flags) returning a risk assessment that the
   engine uses to quarantine. Extraction itself lives in the engine and always
   writes into an isolated workspace with sanitized names.
"""
from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterator, Optional

from .errors import ArchiveSecurityError, ErrorCode
from .limits import IngestionLimits


@dataclass(frozen=True, slots=True)
class MemberInfo:
    name: str
    size: int
    is_dir: bool = False
    is_symlink: bool = False
    is_hardlink: bool = False
    compressed_size: int = 0
    mode: int = 0


@dataclass(slots=True)
class ArchiveAudit:
    container: Optional[str]                  # zip|tar|tar.gz|gzip|bzip2|xz|7z|rar|zstd|lz4
    members: list[MemberInfo] = field(default_factory=list)
    total_uncompressed: int = 0
    encrypted: bool = False
    issues: list[tuple[ErrorCode, str]] = field(default_factory=list)
    safe_to_extract: bool = True

    @property
    def estimated_ratio(self) -> float:
        comp = sum(m.compressed_size for m in self.members) or 1
        return self.total_uncompressed / max(1, comp)


def _member_is_executable(mode: int) -> bool:
    return bool(mode & 0o111)


def audit_zip(data: bytes, limits: IngestionLimits) -> ArchiveAudit:
    audit = ArchiveAudit(container="zip")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        audit.issues.append((ErrorCode.MALFORMED_ARCHIVE, f"bad zip: {exc}"))
        audit.safe_to_extract = False
        return audit
    names_seen: set[str] = set()
    for info in zf.infolist():
        if len(audit.members) >= limits.max_archive_members:
            audit.issues.append((ErrorCode.ARCHIVE_BOMB,
                                 f"member count exceeds {limits.max_archive_members}"))
            audit.safe_to_extract = False
            break
        name = info.filename.replace("\\", "/")
        m = MemberInfo(name=name, size=info.file_size,
                       is_dir=name.endswith("/") or info.is_dir(),
                       compressed_size=info.compress_size,
                       mode=info.external_attr >> 16)
        audit.members.append(m)
        audit.total_uncompressed += max(0, info.file_size)
        # symlink detection via external attrs
        import stat as _stat
        if _stat.S_ISLNK(m.mode):
            m = MemberInfo(**{**m.__dict__, "is_symlink": True})
            audit.members[-1] = m
            audit.issues.append((ErrorCode.SYMLINK_MEMBER, name))
            audit.safe_to_extract = False
        if info.flag_bits & 0x1:      # ZipInfo has no is_encrypted() before 3.13
            audit.encrypted = True
            audit.issues.append((ErrorCode.ENCRYPTED_ARCHIVE, name))
            audit.safe_to_extract = False
        if name.startswith("/") or name.startswith("\\"):
            audit.issues.append((ErrorCode.ABSOLUTE_MEMBER_PATH, name))
            audit.safe_to_extract = False
        parts = PurePosixPath(name).parts
        if ".." in parts:
            audit.issues.append((ErrorCode.PATH_TRAVERSAL, name))
            audit.safe_to_extract = False
        if info.file_size > limits.max_member_bytes:
            audit.issues.append((ErrorCode.MEMBER_TOO_LARGE, f"{name}: {info.file_size} bytes"))
            audit.safe_to_extract = False
        if info.compress_size > 1024 and info.file_size / info.compress_size > limits.max_compression_ratio:
            audit.issues.append((ErrorCode.ARCHIVE_BOMB,
                                 f"{name}: ratio {info.file_size/info.compress_size:.0f}"))
            audit.safe_to_extract = False
        if name in names_seen:
            audit.issues.append((ErrorCode.MALFORMED_ARCHIVE, f"duplicate member {name}"))
        names_seen.add(name)
    if audit.total_uncompressed > limits.max_extracted_bytes:
        audit.issues.append((ErrorCode.ARCHIVE_BOMB, "declared total exceeds extraction cap"))
        audit.safe_to_extract = False
    return audit


def audit_tar(data: bytes, limits: IngestionLimits) -> ArchiveAudit:
    audit = ArchiveAudit(container="tar")
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data))
    except tarfile.TarError as exc:
        audit.issues.append((ErrorCode.MALFORMED_ARCHIVE, str(exc)))
        audit.safe_to_extract = False
        return audit
    for ti in tf.getmembers():
        if len(audit.members) >= limits.max_archive_members:
            audit.issues.append((ErrorCode.ARCHIVE_BOMB, "too many members"))
            audit.safe_to_extract = False
            break
        m = MemberInfo(name=ti.name, size=ti.size, is_dir=ti.isdir(),
                       is_symlink=ti.issym(), is_hardlink=ti.islnk(),
                       compressed_size=ti.size, mode=ti.mode)
        audit.members.append(m)
        audit.total_uncompressed += max(0, ti.size)
        if ti.issym():
            audit.issues.append((ErrorCode.SYMLINK_MEMBER, ti.name))
            audit.safe_to_extract = False
        if ti.islnk():
            audit.issues.append((ErrorCode.HARDLINK_MEMBER, ti.name))
            audit.safe_to_extract = False
        if ti.name.startswith("/") or ".." in PurePosixPath(ti.name).parts:
            audit.issues.append((ErrorCode.PATH_TRAVERSAL, ti.name))
            audit.safe_to_extract = False
        if ti.size > limits.max_member_bytes:
            audit.issues.append((ErrorCode.MEMBER_TOO_LARGE, ti.name))
            audit.safe_to_extract = False
    if audit.total_uncompressed > limits.max_extracted_bytes:
        audit.issues.append((ErrorCode.ARCHIVE_BOMB, "total exceeds cap"))
        audit.safe_to_extract = False
    return audit


def audit_stream_compressed(head: bytes, algo: str, limits: IngestionLimits) -> ArchiveAudit:
    """Single-member compressors: decompress a bounded prefix to estimate ratio."""
    container = {"gzip": "gzip", "bzip2": "bzip2", "xz": "xz"}.get(algo, algo)
    audit = ArchiveAudit(container=container)
    opener = {"gzip": gzip.open, "bzip2": __import__("bz2").open,
              "xz": __import__("lzma").open}.get(algo)
    if opener is None:
        audit.issues.append((ErrorCode.UNSUPPORTED_FORMAT, f"no stdlib reader for {algo}"))
        return audit
    try:
        with opener(io.BytesIO(head), "rb") as fh:
            sample = fh.read(min(limits.max_text_scan_bytes * 4, 4_000_000))
        compressed_len = max(1, len(head))
        ratio = len(sample) / compressed_len
        audit.members = [MemberInfo(name="(stream)", size=len(sample),
                                    compressed_size=compressed_len)]
        audit.total_uncompressed = len(sample)
        if ratio > limits.max_compression_ratio:
            audit.issues.append((ErrorCode.ARCHIVE_BOMB,
                                 f"stream ratio {ratio:.0f} in sampled prefix"))
            audit.safe_to_extract = False
    except Exception as exc:  # truncated/corrupt stream
        audit.issues.append((ErrorCode.MALFORMED_ARCHIVE, str(exc)[:200]))
    return audit


def detect_and_audit(head: bytes, whole: Optional[bytes], fmt: str,
                     limits: IngestionLimits) -> Optional[ArchiveAudit]:
    """Return audit for known archive containers, else None."""
    payload = whole if whole is not None else head
    if fmt == "zip":
        return audit_zip(payload, limits)
    if fmt == "tar":
        return audit_tar(payload, limits)
    if fmt in ("gzip", "bzip2", "xz"):
        return audit_stream_compressed(payload, fmt, limits)
    if fmt in ("7z", "rar", "zstd", "lz4"):
        a = ArchiveAudit(container=fmt)
        a.issues.append((ErrorCode.UNSUPPORTED_FORMAT,
                         f"{fmt} runtime decoder not available; artifact preserved only"))
        a.safe_to_extract = False
        return a
    return None


def iter_tar_safe(data: bytes, limits: IngestionLimits) -> Iterator[tuple[MemberInfo, bytes]]:
    """Extraction iterator enforcing every audit rule at read time.

    Members are yielded fully-decompressed with hard caps; nothing touches disk
    here — the caller stores derived artifacts through the evidence store.
    Raises ArchiveSecurityError on any violation (defense in depth vs audit).
    """
    tf = tarfile.open(fileobj=io.BytesIO(data))
    total = 0
    for ti in tf.getmembers():
        if ti.isdir():
            continue
        if ti.issym() or ti.islnk():
            raise ArchiveSecurityError(ErrorCode.SYMLINK_MEMBER.value, ti.name)
        name = ti.name
        if name.startswith("/") or ".." in PurePosixPath(name).parts:
            raise ArchiveSecurityError(ErrorCode.PATH_TRAVERSAL.value, name)
        if ti.size > limits.max_member_bytes:
            raise ArchiveSecurityError(ErrorCode.MEMBER_TOO_LARGE.value, name)
        f = tf.extractfile(ti)
        if f is None:
            continue
        buf = f.read(limits.max_member_bytes + 1)
        total += len(buf)
        if total > limits.max_extracted_bytes:
            raise ArchiveSecurityError(ErrorCode.ARCHIVE_BOMB.value, "cumulative extracted")
        yield MemberInfo(name=name, size=ti.size, mode=ti.mode), buf


def zip_member_is_directory(info: zipfile.ZipInfo) -> bool:
    return info.is_dir()
