"""AttackMapper - the full mapping pipeline (sections 10-12).

raw report -> behavior extraction -> normalized behavior -> procedure ->
deterministic candidates -> AI pass 1 -> AI pass 2 (blind to pass 1) ->
ATT&CK object validation -> contradiction review -> final mapping.

AI passes are pluggable callables ``fn(prompt: str, context: dict) -> dict``
so the platform LLM runtime can be injected; deterministic fallbacks refuse
to invent mappings when no AI is available.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable

from traceatlas.malware.enums import (
    DualAiOutcome, MappingMethod, MappingVerification, MatrixCellState,
)
from traceatlas.malware.models.report import AttackMapping
from .matcher import BehaviorMatcher
from .validator import AttackValidator

AiFn = Callable[..., dict]

PASS1_PROMPT = """You are ATT&CK mapping analyst 1. From the EVIDENCE ONLY,
decide whether the observed behaviour corresponds to a MITRE ATT&CK
technique/sub-technique in the pinned knowledge base. Return JSON:
{"technique_id": "Txxxx|''", "subtechnique_id": "Txxxx.yyy|''",
 "tactic_id": "TAxxxx|''", "procedure": "...", "reasoning": "...",
 "confidence": 0..1, "insufficient_evidence": bool}
Do not map from keywords alone; require behavioural context."""

PASS2_PROMPT = """You are ATT&CK mapping analyst 2 performing an INDEPENDENT
review. You have NOT seen another analyst's conclusion. From the EVIDENCE
ONLY, return the same JSON schema. If evidence does not support any mapping,
say so via insufficient_evidence=true."""


@dataclass
class MappingRequest:
    malware_id: str
    normalized_behavior: str
    raw_text: str
    evidence_ids: list[str]
    source_ids: list[str]
    matrix: str = "enterprise"
    attack_version: str | None = None
    platforms: list[str] = field(default_factory=list)


class AttackMapper:
    def __init__(self, validator: AttackValidator, matcher: BehaviorMatcher | None = None,
                 *, ai_primary: AiFn | None = None, ai_secondary: AiFn | None = None):
        self.validator = validator
        self.matcher = matcher or BehaviorMatcher()
        self.ai_primary = ai_primary
        self.ai_secondary = ai_secondary

    # ------------------------------------------------------------------ passes
    def _ai_pass(self, fn: AiFn | None, prompt: str, req: MappingRequest,
                 candidates: list[dict], *, show_conclusion_of: dict | None = None) -> dict:
        if fn is None:
            return {"unavailable": True}
        ctx = {"behavior": req.normalized_behavior, "evidence_text": req.raw_text,
               "candidates": candidates, "matrix": req.matrix,
               "platforms": req.platforms}
        if show_conclusion_of is not None:
            ctx["other_analyst_conclusion"] = show_conclusion_of
            prompt = ("You are reviewing another analyst's proposed mapping. " + prompt)
        try:
            out = fn(prompt, ctx)
        except Exception as exc:   # noqa: BLE001 - AI failure must not fake a mapping
            return {"error": str(exc)}
        if isinstance(out, str):
            try:
                out = json.loads(out)
            except json.JSONDecodeError:
                out = {"parse_error": out[:400]}
        return dict(out or {})

    # ------------------------------------------------------------------ main
    def map_behavior(self, req: MappingRequest) -> AttackMapping:
        m = AttackMapping(malware_id=req.malware_id, attack_version="",
                          evidence_ids=list(req.evidence_ids),
                          source_ids=list(req.source_ids))
        m.attack_version = self.validator.client.version(req.matrix) or ""
        if req.attack_version:
            m.attack_version = req.attack_version
        if not req.evidence_ids:
            m.limitations.append("no evidence supplied; mapping refused at intake")
            m.verification = MappingVerification.INCONCLUSIVE.value
            m.dual_ai_outcome = DualAiOutcome.INSUFFICIENT_EVIDENCE.value
            return m

        candidates = self.matcher.candidates_for(req.normalized_behavior, req.raw_text)

        p1 = self._ai_pass(self.ai_primary, PASS1_PROMPT, req, candidates)
        # Pass 2 initially sees evidence but NOT pass-1 conclusion:
        p2 = self._ai_pass(self.ai_secondary, PASS2_PROMPT, req, candidates)
        m.primary_ai_assessment = p1
        m.secondary_ai_assessment = p2

        if p1.get("unavailable") or p2.get("unavailable"):
            m.mapping_method = MappingMethod.DETERMINISTIC_PATTERN.value
            m.dual_ai_outcome = DualAiOutcome.INSUFFICIENT_EVIDENCE.value
            m.verification = MappingVerification.PENDING.value
            m.limitations.append("AI runtime unavailable; only candidate hints recorded "
                                 f"{[c['technique_hint'] for c in candidates if c['technique_hint']]}")
            if candidates and candidates[0]["technique_hint"]:
                m.technique_id, m.subtechnique_id = self._split(
                    candidates[0]["technique_hint"])
                m.cell_state = MatrixCellState.INCONCLUSIVE.value
            return m

        outcome = self._compare(p1, p2)
        m.dual_ai_outcome = outcome.value
        chosen = self._choose(p1, p2, outcome)
        if chosen is None:
            m.verification = MappingVerification.INCONCLUSIVE.value
            m.cell_state = MatrixCellState.INCONCLUSIVE.value
            m.confidence = 0.3
            m.limitations.append("analysts disagree and evidence cannot resolve; "
                                 "mapping marked INCONCLUSIVE")
            return m

        tid, sid = self._split(chosen.get("subtechnique_id") or
                               chosen.get("technique_id") or "")
        res = self.validator.validate_mapping(
            technique_id=tid, subtechnique_id=sid,
            tactic_id=chosen.get("tactic_id", ""), matrix=req.matrix,
            attack_version=m.attack_version, malware_platforms=req.platforms)
        if not res.ok:
            m.verification = MappingVerification.INCONCLUSIVE.value
            m.cell_state = MatrixCellState.INCONCLUSIVE.value
            m.limitations.extend(res.errors)
            return m
        m.technique_id = res.resolved_technique_id.split(".")[0]
        m.subtechnique_id = res.resolved_technique_id if "." in \
            res.resolved_technique_id else ""
        m.tactic_id = chosen.get("tactic_id", "") or (res.resolved_tactic_ids[0]
                                                       if res.resolved_tactic_ids else "")
        m.procedure = chosen.get("procedure", "")
        m.mapping_method = MappingMethod.AI_DUAL_CONSENSUS.value \
            if outcome == DualAiOutcome.AGREE else MappingMethod.AI_PRIMARY.value
        base = float(chosen.get("confidence", 0.5) or 0.5)
        # Two agreeing models raise confidence but never to certainty:
        cap = {DualAiOutcome.AGREE: 0.85, DualAiOutcome.PARTIAL: 0.6,
               DualAiOutcome.DISAGREE: 0.4,
               DualAiOutcome.INSUFFICIENT_EVIDENCE: 0.3}[outcome]
        m.confidence = round(min(base, cap), 3)
        m.verification = MappingVerification.VALIDATED.value \
            if outcome in (DualAiOutcome.AGREE, DualAiOutcome.PARTIAL) \
            else MappingVerification.CONTESTED.value
        m.cell_state = MatrixCellState.TRACEATLAS_MAPPED.value
        m.platform_scope_ok = not res.warnings
        m.limitations.extend(res.warnings)
        m.limitations.append("two AI models agreeing does not make the mapping fact")
        return m

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _split(eff: str) -> tuple[str, str]:
        if "." in (eff or ""):
            return eff.split(".")[0], eff
        return eff or "", ""

    @staticmethod
    def _compare(p1: dict, p2: dict) -> DualAiOutcome:
        if p1.get("insufficient_evidence") or p2.get("insufficient_evidence") or \
                not (p1.get("technique_id") or p1.get("subtechnique_id")) or \
                not (p2.get("technique_id") or p2.get("subtechnique_id")):
            return DualAiOutcome.INSUFFICIENT_EVIDENCE
        e1 = p1.get("subtechnique_id") or p1.get("technique_id")
        e2 = p2.get("subtechnique_id") or p2.get("technique_id")
        if e1 == e2:
            return DualAiOutcome.AGREE
        if e1.split(".")[0] == e2.split(".")[0]:
            return DualAiOutcome.PARTIAL          # same technique, different sub
        return DualAiOutcome.DISAGREE

    @staticmethod
    def _choose(p1: dict, p2: dict, outcome: DualAiOutcome) -> dict | None:
        if outcome == DualAiOutcome.AGREE:
            return p1
        if outcome == DualAiOutcome.PARTIAL:
            # prefer the more conservative (parent-level) claim
            parent_first = [p for p in (p1, p2) if not p.get("subtechnique_id")]
            return parent_first[0] if parent_first else p1
        if outcome == DualAiOutcome.DISAGREE:
            return None      # evidence decides elsewhere; here: inconclusive
        return None


def dual_ai_with_evidence_resolution(mapper: AttackMapper, req: MappingRequest,
                                     arbiter: AiFn | None) -> AttackMapping:
    """If pass1/pass2 disagree, run an evidence-only arbitration pass before
    falling back to INCONCLUSIVE (spec section 12)."""
    m = mapper.map_behavior(req)
    if m.dual_ai_outcome != DualAiOutcome.DISAGREE.value or arbiter is None:
        return m
    verdict = arbiter("Given ONLY the evidence below, decide which of the two "
                      "competing ATT&CK mappings (if either) is supported. JSON: "
                      '{"choice": "A|B|neither", "technique_id": "...", '
                      '"subtechnique_id": "...", "reasoning": "..."}',
                      {"evidence_text": req.raw_text, "A": m.primary_ai_assessment,
                       "B": m.secondary_ai_assessment})
    if not verdict or verdict.get("choice") == "neither":
        m.verification = MappingVerification.INCONCLUSIVE.value
        m.limitations.append("arbitration could not resolve disagreement on evidence")
        return m
    chosen = {"A": m.primary_ai_assessment, "B": m.secondary_ai_assessment}.get(
        verdict.get("choice", ""), {})
    tid, sid = AttackMapper._split(verdict.get("subtechnique_id") or
                                   chosen.get("technique_id") or "")
    res = mapper.validator.validate_mapping(technique_id=tid, subtechnique_id=sid,
                                            matrix=req.matrix,
                                            attack_version=m.attack_version,
                                            malware_platforms=req.platforms)
    if res.ok:
        m.technique_id, m.subtechnique_id = AttackMapper._split(res.resolved_technique_id)
        m.verification = MappingVerification.VALIDATED.value
        m.confidence = 0.7
        m.mapping_method = MappingMethod.MANUAL.value
        m.limitations.append(f"resolved by evidence arbitration: {verdict.get('reasoning','')}")
    else:
        m.limitations.extend(res.errors)
    return m
