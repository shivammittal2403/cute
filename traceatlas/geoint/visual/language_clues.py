"""traceatlas.geoint.visual.language_clues - Script/language -> country sets.

Deterministic mapping from observed scripts (and, where available, detected
languages) to *plausible* country sets. These are probabilistic constraints —
"Devanagari suggests South Asia among many possibilities", never "therefore
India". The produced clue records carry that framing explicitly.
"""
from __future__ import annotations

from traceatlas.geoint.visual.visual_clues import VisualClue, make_clue

# Script -> plausible countries (ISO 3166-1 alpha-2). Deliberately generous:
# under-constraining is safe; over-constraining manufactures false precision.
SCRIPT_COUNTRIES: dict[str, list[str]] = {
    "devanagari": ["IN", "NP"],
    "arabic": ["EG", "SA", "AE", "IQ", "JO", "MA", "DZ", "TN", "LY", "SD", "SY", "YE", "QA", "KW", "BH", "OM"],
    "cyrillic": ["RU", "UA", "BY", "BG", "RS", "MK", "MD", "KZ", "UZ"],
    "han": ["CN", "TW", "SG"],
    "hiragana": ["JP"],
    "katakana": ["JP"],
    "hangul": ["KR", "KP"],
    "greek": ["GR", "CY"],
    "hebrew": ["IL"],
    "thai": ["TH"],
    "armenian": ["AM"],
    "georgian": ["GE"],
    # latin alone constrains almost nothing
    "latin": [],
}

# Language-name hints (from OCR engine language detection or analyst notes).
LANGUAGE_COUNTRIES: dict[str, list[str]] = {
    "hindi": ["IN"], "marathi": ["IN"], "telugu": ["IN"], "tamil": ["IN", "LK"],
    "bengali": ["BD", "IN"], "urdu": ["PK", "IN"], "punjabi": ["IN", "PK"],
    "arabic": ["EG", "SA", "AE", "MA", "DZ", "IQ", "JO"],
    "russian": ["RU", "BY", "KZ"], "ukrainian": ["UA"],
    "spanish": ["ES", "MX", "AR", "CO", "CL", "PE", "VE"],
    "portuguese": ["PT", "BR"], "french": ["FR", "BE", "CH", "CA"],
    "german": ["DE", "AT", "CH"], "italian": ["IT", "CH"],
    "japanese": ["JP"], "korean": ["KR"], "chinese": ["CN", "TW"],
    "turkish": ["TR"], "persian": ["IR"], "dutch": ["NL", "BE"],
    "polish": ["PL"], "romanian": ["RO"], "hungarian": ["HU"],
    "vietnamese": ["VN"], "indonesian": ["ID"], "malay": ["MY"],
    "swahili": ["KE", "TZ"], "yoruba": ["NG"], "hausa": ["NG", "NE"],
}


def script_clue_to_countries(script: str) -> list[str]:
    return SCRIPT_COUNTRIES.get(str(script).lower(), [])


def language_clue_to_countries(language: str) -> list[str]:
    return LANGUAGE_COUNTRIES.get(str(language).lower(), [])


def build_language_clue(evidence_id: str, text_sample: str, script: str,
                        confidence: str, *, language: str | None = None,
                        method: str = "deterministic") -> VisualClue:
    """Emit a signage.language_script clue with honest geographic scope."""
    countries = script_clue_to_countries(script)
    if language:
        lang_c = language_clue_to_countries(language)
        if countries and lang_c:
            countries = sorted(set(countries) & set(lang_c)) or countries
        elif lang_c:
            countries = lang_c
    generic = not countries   # latin-only / unknown => no real constraint
    limitations = []
    if generic:
        limitations.append("generic_scene")
    sample = (text_sample[:40] + "…") if len(text_sample) > 40 else text_sample
    return make_clue(
        "signage.language_script",
        observation=f"visible text uses script '{script}'"
                    + (f", language hint '{language}'" if language else "")
                    + f"; sample: {sample!r}",
        evidence_id=evidence_id, confidence=confidence,
        geographic_scope="COUNTRY" if countries else "GLOBAL",
        candidate_regions=countries, method=method,
        uniqueness=0.8 if not generic else 0.1,
        limitations=limitations,
        notes="script/language narrows plausible countries; it never proves one")
