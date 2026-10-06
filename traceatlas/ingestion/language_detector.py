"""traceatlas.ingestion.language_detector - Stopword-frequency language ID.

Small deterministic n-gram/stopword scorer over extracted text. Good enough to
route translation/analyzer choices; explicitly NOT a certainty claim.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_WORD = re.compile(r"[a-zA-Zà-ÿÀ-ſ]+")

_STOPLISTS: dict[str, frozenset[str]] = {
    "en": frozenset("the of and to in is you that it he was for on are as with do this".split()),
    "es": frozenset("de la que el y a en los un para con no una ser esta las del se por lo".split()),
    "fr": frozenset("le des et en les un une de la est dans qui ne pas pour par avec ou ce".split()),
    "de": frozenset("der die und in den von zu das mit sich des auf für ist im dem nicht ein".split()),
    "pt": frozenset("de a o que e do da em um para com não uma os se na por mais as como".split()),
    "ru": frozenset("и в не на что я с со как то все она его да при это её но к у них за".split()),
    "it": frozenset("di che e la il a per un in non si delle gli del le quale nella vi".split()),
    "nl": frozenset("van en ik te dat in een het niet op mijn ook de voor tot aan uit".split()),
    "zh": frozenset("的 了 和 是 我 不 人 都 一 一个 上 也 很 到 说 们".split()),
    "ar": frozenset("في من على هذا أن لا ما هو التي له مع ذلك قد كان".split()),
}
_ASCII_LANGS = ("en", "es", "fr", "de", "pt", "it", "nl")


@dataclass(frozen=True, slots=True)
class LanguageGuess:
    language: str          # ISO 639-1
    confidence: float
    script: str


def detect_language(text: str, max_words: int = 5000) -> LanguageGuess:
    if not text.strip():
        return LanguageGuess("und", 0.0, "unknown")
    # script detection first (CJK / Cyrillic / Arabic blocks)
    cyr = sum(1 for ch in text if "\u0400" <= ch <= "\u04FF")
    cjk = sum(1 for ch in text if "\u4E00" <= ch <= "\u9FFF")
    arab = sum(1 for ch in text if "\u0600" <= ch <= "\u06FF")
    total_alpha = max(1, cyr + cjk + arab + len(_WORD.findall(text[:20000])))
    if cjk / total_alpha > 0.3:
        return LanguageGuess("zh", min(0.95, cjk / total_alpha + 0.4), "Han")
    if cyr / total_alpha > 0.3:
        return LanguageGuess("ru", min(0.9, cyr / total_alpha + 0.35), "Cyrillic")
    if arab / total_alpha > 0.3:
        return LanguageGuess("ar", min(0.9, arab / total_alpha + 0.35), "Arabic")

    words = [w.lower() for w in _WORD.findall(text)][:max_words]
    if len(words) < 8:
        return LanguageGuess("en", 0.3, "Latin")   # too short to be sure
    scores: dict[str, float] = {}
    for lang in _ASCII_LANGS:
        sl = _STOPLISTS[lang]
        hits = sum(1 for w in words if w in sl)
        scores[lang] = hits / len(words)
    # Russian stoplist also checked against latin-translit? No — skip.
    best_lang = max(scores, key=lambda k: scores[k])
    best = scores[best_lang]
    runner = sorted(scores.values(), reverse=True)[1] if len(scores) > 1 else 0.0
    margin = best - runner
    conf = min(0.95, best * 3 + margin)
    if best < 0.03:
        return LanguageGuess("en", 0.25, "Latin")  # default guess, low confidence
    return LanguageGuess(best_lang, conf, "Latin")
