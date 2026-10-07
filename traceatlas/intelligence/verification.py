"""traceatlas.intelligence.verification — Dual-AI review pipeline (§9, §19).

One reusable pipeline for every module: analyze_primary() -> independent
analyze_secondary() (skeptic sees ORIGINAL EVIDENCE ONLY, never pass-1 output)
-> deterministic compare_results() -> adjudicate()/human review only when needed.

Honesty rules enforced here:
* model agreement is REVIEW, never independent corroboration; two AIs cannot
  bypass the Fact Gate (`fact_gate.py` owns promotion);
* same model used twice => MODEL_DIVERSITY=LOW recorded on the verdict;
* LOCAL_ONLY mode makes ZERO transport calls; restricted/local-only evidence is
  never silently sent to a cloud endpoint (blocked, not downgraded);
* unavailable models produce BLOCKED_CONFIGURATION-style outcomes with reasons,
  never fabricated analysis;
* invalid/non-JSON model output is a failure state, never coerced into success.

Transport is injected (`transport(prompt, model)->str`) so tests run offline and
production can wire Ollama (/api/generate or /api/chat) via config.AISettings.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from traceatlas.intelligence.constants import (
    AIExecutionMode,
    CrossCheckVerdict,
    PrivacyClass,
)


# ------------------------------------------------------------------ model policy
@dataclass(slots=True)
class ModelPolicy:
    execution_mode: AIExecutionMode = AIExecutionMode.LOCAL_ONLY
    primary_model: str = ""
    secondary_model: str = ""
    adjudicator_model: str = ""
    # endpoints considered "cloud" for privacy enforcement
    cloud_endpoint_hosts: tuple[str, ...] = ()

    @property
    def model_diversity(self) -> str:
        if not self.primary_model or not self.secondary_model:
            return "UNKNOWN"
        return "LOW" if self.primary_model == self.secondary_model else "OK"

    def allows_cloud(self, privacy_class: str) -> bool:
        if self.execution_mode is AIExecutionMode.LOCAL_ONLY:
            return False
        pc = (privacy_class or "").lower()
        if pc in (PrivacyClass.RESTRICTED.value, PrivacyClass.LOCAL_ONLY.value):
            # HYBRID may still use cloud for PUBLIC/AUTHORIZED only
            return self.execution_mode is AIExecutionMode.CLOUD and pc not in (
                PrivacyClass.RESTRICTED.value, PrivacyClass.LOCAL_ONLY.value)
        return True


class CloudLeakBlocked(RuntimeError):
    """Restricted/local-only evidence was routed at a cloud call — refused."""


# ------------------------------------------------------------------- pass results
@dataclass(slots=True)
class AnalysisPass:
    role: str                    # primary_analyst | independent_skeptic
    model: str
    claims: tuple[str, ...] = ()          # normalized claim keys the pass endorses
    findings: dict[str, Any] = field(default_factory=dict)
    caveats: tuple[str, ...] = ()
    raw_ok: bool = True                  # parse succeeded
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "model": self.model,
                "claims": list(self.claims), "findings": self.findings,
                "caveats": list(self.caveats), "raw_ok": self.raw_ok,
                "error": self.error}


def normalize_claim(text: str) -> str:
    """Deterministic claim key: lowercased, punctuation-stripped, collapsed ws."""
    t = re.sub(r"[^a-z0-9 ]+", " ", (text or "").lower())
    return " ".join(t.split())


def parse_pass_output(role: str, model: str, raw: str) -> AnalysisPass:
    """Strict structured-output parsing. Invalid JSON => failed pass, never guess."""
    if raw is None or not str(raw).strip():
        return AnalysisPass(role=role, model=model, raw_ok=False,
                            error="empty model response")
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        # tolerate fenced blocks only when the payload itself is valid JSON
        m = re.search(r"\{.*\}", str(raw), re.S)
        if not m:
            return AnalysisPass(role=role, model=model, raw_ok=False,
                                error="invalid model JSON: no object found")
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return AnalysisPass(role=role, model=model, raw_ok=False,
                                error="invalid model JSON: unparseable object")
    if not isinstance(obj, dict):
        return AnalysisPass(role=role, model=model, raw_ok=False,
                            error="invalid model JSON: top level not an object")
    claims = obj.get("claims") or obj.get("agreed_claims") or []
    if not isinstance(claims, list):
        return AnalysisPass(role=role, model=model, raw_ok=False,
                            error="invalid model JSON: claims must be a list")
    caveats = obj.get("caveats") or obj.get("concerns") or []
    caveats = tuple(str(c) for c in caveats) if isinstance(caveats, list) else ()
    return AnalysisPass(role=role, model=model,
                        claims=tuple(normalize_claim(str(c)) for c in claims if str(c).strip()),
                        findings={k: v for k, v in obj.items()
                                  if k not in ("claims", "agreed_claims", "caveats")},
                        caveats=caveats)


# --------------------------------------------------------------------- cross-check
@dataclass(slots=True)
class CrossCheck:
    verdict: str
    shared_claims: tuple[str, ...] = ()
    pass1_only: tuple[str, ...] = ()
    pass2_only: tuple[str, ...] = ()
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "shared_claims": list(self.shared_claims),
                "pass1_only": list(self.pass1_only), "pass2_only": list(self.pass2_only),
                "note": self.note}


def compare_results(p1: AnalysisPass, p2: AnalysisPass) -> CrossCheck:
    """Deterministic cross-check of two structured passes (§9 vocabulary)."""
    if not p1.raw_ok and not p2.raw_ok:
        return CrossCheck(CrossCheckVerdict.INSUFFICIENT_EVIDENCE.value,
                          note="both passes failed to produce valid structured output")
    if not p1.raw_ok:
        return CrossCheck(CrossCheckVerdict.PASS2_ONLY.value, note="primary pass invalid")
    if not p2.raw_ok:
        return CrossCheck(CrossCheckVerdict.PASS1_ONLY.value, note="skeptic pass invalid")
    s1, s2 = set(p1.claims), set(p2.claims)
    shared = tuple(sorted(s1 & s2))
    only1 = tuple(sorted(s1 - s2))
    only2 = tuple(sorted(s2 - s1))
    if not s1 and not s2:
        return CrossCheck(CrossCheckVerdict.INSUFFICIENT_EVIDENCE.value,
                          note="neither pass endorsed any claim")
    if s1 == s2:
        v = CrossCheckVerdict.AGREE.value
    elif shared and not only1 and not only2:
        v = CrossCheckVerdict.AGREE.value
    elif shared and (only1 or only2):
        # exact-key overlap but differing scope: partial unless one side is a
        # subset restatement of the other (semantic agreement heuristic)
        bigger, smaller = (s1, s2) if len(s1) >= len(s2) else (s2, s1)
        contained = all(any(sc in bc or bc in sc for bc in bigger) for sc in smaller) \
            if smaller else False
        v = (CrossCheckVerdict.SEMANTIC_AGREEMENT.value if contained and smaller
             else CrossCheckVerdict.PARTIAL_AGREEMENT.value)
    else:
        v = CrossCheckVerdict.DISAGREE.value
    return CrossCheck(v, shared_claims=shared, pass1_only=only1, pass2_only=only2,
                      note="agreement between two models is review, not a second source")


# ------------------------------------------------------------------------ pipeline
PromptBuilder = Callable[[str, str], str]   # (role, evidence_blob) -> prompt


class DualAIReviewer:
    """Reusable dual-analysis pipeline. `transport(prompt, model)->str` performs
    the actual LLM call; this class never opens sockets itself."""

    def __init__(self, *, policy: ModelPolicy, transport: Optional[Callable],
                 prompt_builder: Optional[PromptBuilder] = None):
        self.policy = policy
        self._transport = transport
        self._prompt_builder = prompt_builder or self._default_prompt

    @staticmethod
    def _default_prompt(role: str, evidence: str) -> str:
        stance = ("You are the primary analyst. List the claims the evidence supports."
                  if role == "primary_analyst" else
                  "You are an independent skeptic. Do NOT assume anything; list only "
                  "claims the evidence itself supports, and raise concerns.")
        return (f"{stance}\nReturn strict JSON: "
                '{"claims":[...],"caveats":[...]}\n\nEVIDENCE:\n' + evidence)

    def _call(self, role: str, model: str, evidence: str, privacy_class: str) -> AnalysisPass:
        pc = (privacy_class or "").lower()
        if pc in (PrivacyClass.RESTRICTED.value, PrivacyClass.LOCAL_ONLY.value) \
                and self.policy.execution_mode is not AIExecutionMode.LOCAL_ONLY \
                and not self.policy.allows_cloud(pc):
            # hybrid/cloud policy but restricted evidence -> refuse rather than leak
            raise CloudLeakBlocked(
                f"evidence privacy_class={pc} cannot be sent to non-local AI")
        if self._transport is None:
            return AnalysisPass(role=role, model=model, raw_ok=False,
                                error="BLOCKED_CONFIGURATION: no AI transport configured")
        if pc == PrivacyClass.LOCAL_ONLY.value \
                and self.policy.execution_mode is not AIExecutionMode.LOCAL_ONLY:
            # belt-and-braces: local-only evidence never leaves the local path
            raise CloudLeakBlocked("local_only evidence blocked from non-local execution")
        prompt = self._prompt_builder(role, evidence)
        try:
            raw = self._transport(prompt, model)
        except Exception as exc:  # provider outage / timeout -> honest failure state
            return AnalysisPass(role=role, model=model, raw_ok=False,
                                error=f"provider_error: {type(exc).__name__}: {exc}"[:400])
        return parse_pass_output(role, model, raw)

    def review(self, evidence_blob: str, *, privacy_class: str = PrivacyClass.PUBLIC.value
               ) -> dict[str, Any]:
        """Run pass1 then pass2 (pass2 receives ORIGINAL evidence only — the
        pipeline structurally cannot see pass1 output before comparison)."""
        p1 = self._call("primary_analyst", self.policy.primary_model,
                        evidence_blob, privacy_class)
        p2 = self._call("independent_skeptic", self.policy.secondary_model,
                        evidence_blob, privacy_class)
        check = compare_results(p1, p2)
        return {"pass1": p1.to_dict(), "pass2": p2.to_dict(),
                "cross_check": check.to_dict(),
                "model_diversity": self.policy.model_diversity,
                "execution_mode": self.policy.execution_mode.value,
                "corroborates_independently": False,  # §9: AI agreement != 2 sources
                "promotion_allowed_by_this_component": False}
