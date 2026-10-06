"""traceatlas.verification.independence - Source independence engine.

Counts of URLs are NOT corroboration. This engine classifies evidence pairs as
INDEPENDENT / PARTIALLY_DEPENDENT / DEPENDENT / UNKNOWN using:
1 exact content hash equality -> DEPENDENT (same bytes)
2 normalized shingle fingerprint + MinHash Jaccard -> near-duplicate detection
3 explicit upstream/citation metadata (provenance.upstream_source_id) -> syndication
4 shared publisher-domain heuristics -> PARTIALLY_DEPENDENT
Deterministic, no LLM required.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional


class Independence(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    PARTIALLY_DEPENDENT = "PARTIALLY_DEPENDENT"
    DEPENDENT = "DEPENDENT"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class EvidenceDoc:
    evidence_id: str
    source_slug: str
    publisher_domain: str
    text: str
    upstream_source_id: Optional[str] = None  # syndication marker if known
    sha256: str = ""


_WS = re.compile(r"\s+")
_TRACK = re.compile(r"(utm_[a-z]+=[^&\s]+|ref(errer)?=[^&\s]+)", re.I)


def normalize_text(text: str) -> str:
    t = _TRACK.sub("", text.lower())
    t = re.sub(r"[^a-z0-9 ]+", " ", t)
    return _WS.sub(" ", t).strip()


def shingles(text: str, k: int = 8) -> set[str]:
    words = text.split()
    if len(words) < k:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def minhash_signature(shingle_set: set[str], num_perm: int = 64) -> tuple[int, ...]:
    if not shingle_set:
        return (0,) * num_perm
    sig = []
    for seed in range(num_perm):
        best = None
        for sh in shingle_set:
            h = struct.unpack("<Q", hashlib.sha256(
                f"{seed}:{sh}".encode()).digest()[:8])[0]
            if best is None or h < best:
                best = h
        sig.append(best)
    return tuple(sig)


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def estimate_jaccard(sig_a: tuple[int, ...], sig_b: tuple[int, ...]) -> float:
    if not sig_a or not sig_b:
        return 0.0
    agree = sum(1 for x, y in zip(sig_a, sig_b) if x == y)
    return agree / max(len(sig_a), len(sig_b))


class IndependenceEngine:
    NEAR_DUP_THRESHOLD = 0.85          # shingle Jaccard => same underlying copy
    PARTIAL_THRESHOLD = 0.55           # heavy overlap => partial dependence

    def __init__(self):
        self._cache: dict[str, tuple[set[str], tuple[int, ...]]] = {}

    def _features(self, doc: EvidenceDoc) -> tuple[set[str], tuple[int, ...]]:
        if doc.evidence_id in self._cache:
            return self._cache[doc.evidence_id]
        norm = normalize_text(doc.text)
        sh = shingles(norm)
        sig = minhash_signature(sh)
        self._cache[doc.evidence_id] = (sh, sig)
        return sh, sig

    # ------------------------------------------------------------------ classify
    def classify_pair(self, a: EvidenceDoc, b: EvidenceDoc) -> tuple[Independence, str]:
        if a.evidence_id == b.evidence_id:
            return Independence.DEPENDENT, "same evidence artifact"
        if a.sha256 and a.sha256 == b.sha256:
            return Independence.DEPENDENT, "identical content hash"
        # syndication via declared upstream metadata
        if (a.upstream_source_id and a.upstream_source_id == b.source_slug) or \
           (b.upstream_source_id and b.upstream_source_id == a.source_slug):
            return Independence.DEPENDENT, "declared syndication/upstream relationship"
        if a.upstream_source_id and a.upstream_source_id == b.upstream_source_id:
            return Independence.DEPENDENT, "common declared upstream dataset"
        sh_a, sig_a = self._features(a)
        sh_b, sig_b = self._features(b)
        jac = jaccard(sh_a, sh_b)
        est = estimate_jaccard(sig_a, sig_b)
        if jac >= self.NEAR_DUP_THRESHOLD or est >= self.NEAR_DUP_THRESHOLD:
            return Independence.DEPENDENT, f"near-duplicate content (jaccard={jac:.2f})"
        if jac >= self.PARTIAL_THRESHOLD:
            return Independence.PARTIALLY_DEPENDENT, f"heavy overlap (jaccard={jac:.2f})"
        if a.publisher_domain and a.publisher_domain == b.publisher_domain:
            return Independence.PARTIALLY_DEPENDENT, "same publisher domain"
        if not a.text.strip() or not b.text.strip():
            return Independence.UNKNOWN, "insufficient content to compare"
        return Independence.INDEPENDENT, f"distinct content (jaccard={jac:.2f})"

    # ------------------------------------------------------- corroboration count
    def independent_sources_for_observation(
            self, docs: Iterable[EvidenceDoc]) -> tuple[list[EvidenceDoc], list[tuple[str, str]]]:
        """Cluster docs; return one representative per independence cluster + notes."""
        docs = list(docs)
        clusters: list[list[EvidenceDoc]] = []
        notes: list[tuple[str, str]] = []
        for d in docs:
            placed = False
            for cl in clusters:
                kind, why = self.classify_pair(cl[0], d)
                if kind in (Independence.DEPENDENT, Independence.PARTIALLY_DEPENDENT):
                    cl.append(d)
                    notes.append((d.evidence_id, f"{kind.value} to {cl[0].evidence_id}: {why}"))
                    placed = True
                    break
            if not placed:
                clusters.append([d])
        reps = [cl[0] for cl in clusters]
        return reps, notes
