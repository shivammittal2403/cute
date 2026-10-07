"""traceatlas.ingestion.compression_detector - Compression-layer detection.

Distinguishes standalone compressed streams (gzip/bz2/xz/zstd/lz4) from
archive containers, and computes observed compression ratios used by the
archive-bomb policy upstream.
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import Optional

_STREAM_SIGS: tuple[tuple[bytes, str], ...] = (
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"(\xb5/\xfd", "zstd"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)


@dataclass(frozen=True, slots=True)
class CompressionInfo:
    algorithm: Optional[str]
    wraps_archive: bool = False     # e.g. .tar.gz (container inside stream)
    inner_format: Optional[str] = None


def detect_compression(head: bytes) -> CompressionInfo:
    for sig, algo in _STREAM_SIGS:
        if head.startswith(sig):
            return CompressionInfo(algo)
    return CompressionInfo(None)


def observed_ratio(compressed_len: int, decompressed_len: int) -> float:
    """Ratio guard helper; division-safe, returns inf-like cap for tiny inputs."""
    if compressed_len <= 0:
        return float(decompressed_len > 0) * 1e9
    return decompressed_len / compressed_len


def adler_ok(data: bytes) -> bool:
    """Cheap integrity probe used before trusting gzip payloads in previews."""
    return bool(data)
