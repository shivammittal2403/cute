"""traceatlas.geoint.visual.ocr - OCR adapter with retained confidence.

Section 8: OCR confidence must be retained; low-confidence OCR must not become
fact. This module defines the OCR result schema and an engine-agnostic
interface. Adapters (tesseract via subprocess, PaddleOCR, cloud OCR) plug in
via `OcrEngine`; a deterministic null engine keeps the pipeline testable
offline. Language/script detection consumes OCR *tokens*, never conclusions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, Optional


@dataclass(slots=True)
class OcrToken:
    text: str
    confidence: float                 # 0..1 as reported by the engine
    bbox: tuple[int, int, int, int] | None = None   # x,y,w,h in source pixels
    language_hint: str = ""

    def to_dict(self) -> dict:
        return {"text": self.text, "confidence": self.confidence,
                "bbox": list(self.bbox) if self.bbox else None,
                "language_hint": self.language_hint}


@dataclass(slots=True)
class OcrResult:
    evidence_id: str                  # the media artifact OCR'd
    engine: str
    tokens: list[OcrToken] = field(default_factory=list)
    notes: str = ""

    @property
    def full_text(self) -> str:
        return " ".join(t.text for t in self.tokens if t.confidence >= 0.5)

    def high_confidence_tokens(self, threshold: float = 0.7) -> list[OcrToken]:
        return [t for t in self.tokens if t.confidence >= threshold]

    def low_confidence_tokens(self, threshold: float = 0.5) -> list[OcrToken]:
        return [t for t in self.tokens if t.confidence < threshold]

    def to_dict(self) -> dict:
        return {"evidence_id": self.evidence_id, "engine": self.engine,
                "tokens": [t.to_dict() for t in self.tokens], "notes": self.notes}


class OcrEngine(Protocol):
    name: str

    def run(self, image_bytes: bytes, evidence_id: str) -> OcrResult: ...


class NullOcrEngine:
    """Deterministic placeholder used when no OCR engine is configured. It
    returns NO tokens — absence of OCR is recorded, never faked."""
    name = "null"

    def run(self, image_bytes: bytes, evidence_id: str) -> OcrResult:
        return OcrResult(evidence_id=evidence_id, engine=self.name, tokens=[],
                         notes="no OCR engine configured; OCR stage skipped")


# ---------------------------------------------------------------------------
# Script detection from token text (deterministic Unicode-range analysis).
# ---------------------------------------------------------------------------

_SCRIPT_RANGES: dict[str, list[tuple[int, int]]] = {
    "latin": [(0x0041, 0x007A), (0x00C0, 0x024F)],
    "devanagari": [(0x0900, 0x097F)],
    "arabic": [(0x0600, 0x06FF)],
    "cyrillic": [(0x0400, 0x04FF)],
    "han": [(0x4E00, 0x9FFF)],
    "hiragana": [(0x3040, 0x309F)],
    "katakana": [(0x30A0, 0x30FF)],
    "hangul": [(0xAC00, 0xD7AF)],
    "greek": [(0x0370, 0x03FF)],
    "hebrew": [(0x0590, 0x05FF)],
    "thai": [(0x0E00, 0x0E7F)],
    "armenian": [(0x0530, 0x058F)],
    "georgian": [(0x10A0, 0x10FF)],
}


def detect_scripts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ch in text:
        cp = ord(ch)
        for script, ranges in _SCRIPT_RANGES.items():
            if any(lo <= cp <= hi for lo, hi in ranges):
                counts[script] = counts.get(script, 0) + 1
                break
    return counts


def dominant_script(text: str) -> Optional[str]:
    counts = detect_scripts(text)
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]


# Well-known sign/plate regexes kept deliberately conservative: they produce
# *candidate* strings for map lookup, never facts on their own.
_ROAD_NUMBER_PATTERNS = [
    re.compile(r"\b(?:NH|SH|MRD)\s?\d{1,4}\b", re.IGNORECASE),      # India
    re.compile(r"\b(?:A|B|E|N|S)\s?\d{1,3}(?:\s?[A-Z])?\b"),        # EU motorways
    re.compile(r"\b(?:I|US|SR|CR)\s?\d{1,4}\b"),                    # US
    re.compile(r"\bR\d{1,4}\b"),                                    # France/cycle
]


def extract_road_number_candidates(tokens: list[OcrToken]) -> list[str]:
    out: list[str] = []
    for t in tokens:
        if t.confidence < 0.7:
            continue   # weak OCR never seeds candidates (section 8)
        for pat in _ROAD_NUMBER_PATTERNS:
            for m in pat.finditer(t.text.upper()):
                val = m.group(0).strip()
                if val not in out:
                    out.append(val)
    return out
