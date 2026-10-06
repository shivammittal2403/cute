"""traceatlas.ingestion.charset_detector - Encoding/charset sniffing.

Deterministic cascade: BOM -> strict UTF-8 -> common legacy codepages ->
latin-1 last resort (never fails). Reports confidence and ambiguity so the
detector layer can raise ENCODING_AMBIGUOUS rather than silently guessing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)

# cp1252 first: it is the most common legacy Western codepage and its
# high-byte space contains real punctuation, unlike the CJK candidates.
_CANDIDATES = ("cp1252", "cp1251", "iso-8859-2", "iso-8859-1", "shift_jis", "euc-kr")


@dataclass(frozen=True, slots=True)
class CharsetResult:
    encoding: str
    confidence: float
    ambiguous: bool = False
    bom: bool = False
    alternatives: tuple[str, ...] = ()

    @property
    def is_text(self) -> bool:
        return True


def detect_charset(sample: bytes) -> CharsetResult:
    if not sample:
        return CharsetResult("utf-8", 0.5, ambiguous=True)
    for bom, enc in _BOMS:
        if sample.startswith(bom):
            return CharsetResult(enc, 0.99, bom=True)
    try:
        sample.decode("utf-8")
        # utf-8 strict success — high confidence unless sample is trivially ascii-only
        non_ascii = any(b >= 0x80 for b in sample)
        return CharsetResult("utf-8", 0.95 if non_ascii else 0.9)
    except UnicodeDecodeError:
        pass
    scored: list[tuple[float, str]] = []
    for cand in _CANDIDATES:
        try:
            text = sample.decode(cand)
        except (UnicodeDecodeError, LookupError):
            continue
        # heuristic quality: fewer control chars => better
        ctrl = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r\f")
        quality = max(0.3, 0.8 - ctrl / max(1, len(text)) * 10)
        scored.append((quality, cand))
    if scored:
        scored.sort(reverse=True)
        best_q, best = scored[0]
        alts = tuple(c for _, c in scored[1:3])
        ambiguous = len(scored) > 1 and abs(scored[0][0] - scored[1][0]) < 0.05
        return CharsetResult(best, best_q, ambiguous=ambiguous, alternatives=alts)
    return CharsetResult("latin-1", 0.4, ambiguous=True)


def decode_bytes(sample: bytes, encoding: Optional[str] = None) -> str:
    enc = encoding or detect_charset(sample).encoding
    return sample.decode(enc, errors="replace")
