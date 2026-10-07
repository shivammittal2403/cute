"""traceatlas.intelligence.fact_gate — Fact-first law enforcement (§7).

SOURCE RESULT -> RAW EVIDENCE -> OBSERVATION -> CANDIDATE FACT -> FACT GATE ->
reliability/bias/independence -> SUPPORTED / PARTIAL / DISPUTED / INCONCLUSIVE.

No module may turn a source/API/model result directly into a fact. This gate
is the only sanctioned promotion path:

* a candidate fact WITHOUT evidence linkage is REJECTED (rejected_no_evidence);
* observations lacking evidence are never promotable at all;
* conflicting observations on the same (subject, predicate) make the fact
  DISPUTED — both sides stay preserved, nothing is silently overwritten;
* a single-source direct observation may be SUPPORTED with an explicit caveat;
  consequential predicates (identity/attribution/accusation) require >=2
  INDEPENDENT clusters, otherwise the best outcome is PARTIAL;
* model agreement is never counted as corroboration (see verification.py).

The output `FactSummary` is mandatory before any hypothesis work (§7).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from traceatlas.core.confidence import Confidence
from traceatlas.core.observation import Observation
from traceatlas.intelligence.constants import FactGateOutcome


# ------------------------------------------------------------------- constants
DEFAULT_FRESHNESS_WINDOW_H = {
    "dns": 24, "ip": 720, "asn": 2160, "registry": 8760, "certificates": 720,
}
STALE_DEFAULT_H = 24 * 90  # unknown namespace: 90 days

# predicates where a conclusion about PEOPLE/CONTROL needs corroboration
CONSEQUENTIAL_TOKENS = ("owner", "registrant", "operator", "attributed",
                        "same_person", "belongs_to", "culpab", "fraud",
                        "sanction", "wallet_owner")


def is_consequential(predicate: str) -> bool:
    p = (predicate or "").lower()
    return any(tok in p for tok in CONSEQUENTIAL_TOKENS)


def _canon(value: Any) -> str:
    """Canonical value form for conflict detection (order-insensitive)."""
    if isinstance(value, (list, tuple, set)):
        return "|".join(sorted(_canon(v) for v in value))
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    s = str(value).strip().lower()
    return s.rstrip(".") if s else ""


# ------------------------------------------------------------- independence hook
@dataclass(slots=True)
class IndependenceCluster:
    representative_evidence_id: str
    member_evidence_ids: tuple[str, ...] = ()
    state: str = "unknown"   # SourceIndependenceState value


class EvidenceOnlyClusterer:
    """Default clusterer: every distinct evidence artifact is its own cluster
    until an IndependenceEngine-backed clusterer is injected. Conservative:
    identical bytes (same evidence_id via content-addressed store) count once."""

    def clusters(self, evidence_ids: list[str]) -> list[IndependenceCluster]:
        seen: dict[str, list[str]] = {}
        for eid in evidence_ids:
            seen.setdefault(eid, []).append(eid)
        return [IndependenceCluster(representative_evidence_id=k,
                                    member_evidence_ids=tuple(v), state="independent")
                for k, v in seen.items()]


class TextCorpusClusterer:
    """Clusters by CONTENT using traceatlas.verification.independence's
    IndependenceEngine (hash/shingle/minhash/publisher). Five copied URLs
    remain ONE cluster. Requires a callable text_of(evidence_id)->str and
    a callable meta_of(evidence_id)->dict with keys source_slug, publisher_domain."""

    def __init__(self, engine, text_of, meta_of):
        self._engine = engine          # IndependenceEngine instance
        self._text_of = text_of
        self._meta_of = meta_of

    def _doc(self, eid: str):
        from traceatlas.verification.independence import EvidenceDoc
        m = self._meta_of(eid) or {}
        return EvidenceDoc(evidence_id=eid,
                           source_slug=m.get("source_slug", ""),
                           publisher_domain=m.get("publisher_domain", ""),
                           text=self._text_of(eid) or "",
                           upstream_source_id=m.get("upstream_source_id"),
                           sha256=m.get("sha256", ""))

    def clusters(self, evidence_ids: list[str]) -> list[IndependenceCluster]:
        reps, notes = self._engine.independent_sources_for_observation(
            [self._doc(e) for e in evidence_ids])
        rep_ids = {r.evidence_id for r in reps}
        note_by_eid = dict(notes)
        out: list[IndependenceCluster] = []
        members: dict[str, list[str]] = {e: [e] for e in evidence_ids}
        for eid, note in notes:
            # attach to the representative named inside the note when parseable
            for rid in rep_ids:
                if rid in note:
                    members[rid].append(eid)
                    members[eid] = members[rid]
                    break
        placed = set()
        for eid in evidence_ids:
            grp = members[eid]
            key = grp[0]
            if id(grp) in placed:
                continue
            placed.add(id(grp))
            state = "dependent" if len(grp) > 1 else "independent"
            out.append(IndependenceCluster(representative_evidence_id=key,
                                           member_evidence_ids=tuple(dict.fromkeys(grp)),
                                           state=state))
        return out


# --------------------------------------------------------------------- records
@dataclass(slots=True)
class GateRecord:
    subject_id: str
    predicate: str
    value: Any
    outcome: str
    confidence: Confidence
    observation_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    independent_cluster_count: int = 0
    reasons: tuple[str, ...] = ()
    bias_notes: tuple[str, ...] = ()
    stale: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"subject_id": self.subject_id, "predicate": self.predicate,
                "value": self.value, "outcome": self.outcome,
                "confidence": self.confidence.to_dict(),
                "observation_ids": list(self.observation_ids),
                "evidence_ids": list(self.evidence_ids),
                "independent_cluster_count": self.independent_cluster_count,
                "reasons": list(self.reasons), "bias_notes": list(self.bias_notes),
                "stale": self.stale}


@dataclass(slots=True)
class FactSummary:
    """§7 pre-hypothesis summary. Hypotheses may not be produced without one."""
    case_id: str
    supported: list[GateRecord] = field(default_factory=list)
    partial: list[GateRecord] = field(default_factory=list)
    disputed: list[GateRecord] = field(default_factory=list)
    inconclusive: list[GateRecord] = field(default_factory=list)
    rejected: list[GateRecord] = field(default_factory=list)
    observations_total: int = 0
    reliability_notes: tuple[str, ...] = ()
    bias_limitations: tuple[str, ...] = ()
    independence_notes: tuple[str, ...] = ()
    temporal_limitations: tuple[str, ...] = ()
    identity_limitations: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()

    def counts(self) -> dict[str, int]:
        return {"supported": len(self.supported), "partial": len(self.partial),
                "disputed": len(self.disputed), "inconclusive": len(self.inconclusive),
                "rejected": len(self.rejected), "observations": self.observations_total}

    def has_promotable_facts(self) -> bool:
        return bool(self.supported or self.partial or self.disputed)

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "counts": self.counts(),
                "supported": [g.to_dict() for g in self.supported],
                "partial": [g.to_dict() for g in self.partial],
                "disputed": [g.to_dict() for g in self.disputed],
                "inconclusive": [g.to_dict() for g in self.inconclusive],
                "rejected": [g.to_dict() for g in self.rejected],
                "reliability_notes": list(self.reliability_notes),
                "bias_limitations": list(self.bias_limitations),
                "independence_notes": list(self.independence_notes),
                "temporal_limitations": list(self.temporal_limitations),
                "identity_limitations": list(self.identity_limitations),
                "contradictions": list(self.contradictions)}


# ------------------------------------------------------------------------ gate
class FactGate:
    """Deterministic promotion gate. Inject `clusterer` (IndependenceCluster
    provider) and optionally `reliability_fn(subject_meta)->score 0..1` per
    deployment; defaults are conservative."""

    def __init__(self, *, clusterer=None, freshness_window_h: dict | None = None,
                 max_age_h_default: int = STALE_DEFAULT_H):
        self.clusterer = clusterer or EvidenceOnlyClusterer()
        self.freshness = freshness_window_h or DEFAULT_FRESHNESS_WINDOW_H
        self.max_age_default = max_age_h_default

    # ------------------------------------------------------------------ helpers
    def _age_hours(self, obs: Observation, now: datetime) -> Optional[float]:
        t = obs.observed_at or obs.recorded_at
        if t is None:
            return None
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (now - t).total_seconds() / 3600.0

    def _is_stale(self, obs: Observation, now: datetime) -> bool:
        age = self._age_hours(obs, now)
        if age is None:
            return True  # unverifiable freshness is treated as stale
        ns = (obs.predicate or "").split(".", 1)[0]
        window = self.freshness.get(ns, self.max_age_default)
        return age > window

    # -------------------------------------------------------------------- gate
    def evaluate_group(self, observations: list[Observation], *,
                       now: Optional[datetime] = None) -> list[GateRecord]:
        """Evaluate all candidate facts within one (subject, predicate) group.
        Returns one record per DISTINCT value; conflicting values => DISPUTED."""
        now = now or datetime.now(timezone.utc)
        if not observations:
            return []
        subject = observations[0].subject_id or ""
        predicate = observations[0].predicate or ""

        by_value: dict[str, list[Observation]] = {}
        no_evidence: list[Observation] = []
        for o in observations:
            if not o.evidence_id:
                no_evidence.append(o)
                continue
            by_value.setdefault(_canon(o.value), []).append(o)

        records: list[GateRecord] = []
        consequential = is_consequential(predicate)
        n_values = len(by_value)

        for _, group in by_value.items():
            eids = list(dict.fromkeys(o.evidence_id for o in group if o.evidence_id))
            clusters = self.clusterer.clusters(eids) if eids else []
            n_clusters = len(clusters)
            stale_flags = [self._is_stale(o, now) for o in group]
            fresh = [o for o, s in zip(group, stale_flags) if not s]
            reasons: list[str] = []
            bias_notes: list[str] = []
            for cl in clusters:
                if cl.state != "independent":
                    reasons.append(f"evidence cluster {cl.representative_evidence_id} is {cl.state}")
            if consequential:
                reasons.append("consequential predicate: corroboration required")
            if any(stale_flags) and not fresh:
                reasons.append("all supporting observations exceed freshness window")
            elif stale_flags and not all(stale_flags):
                reasons.append("some supporting observations are stale (historical only)")

            value = group[0].value
            obs_ids = tuple(o.observation_id for o in group)

            if n_values > 1:
                outcome, conf = FactGateOutcome.DISPUTED, Confidence.of(
                    0.35, "conflicting values on same subject/predicate; both preserved")
            elif not fresh:
                outcome, conf = FactGateOutcome.INCONCLUSIVE, Confidence.of(
                    0.2, "; ".join(reasons) or "no fresh evidence")
            elif consequential and n_clusters < 2:
                outcome, conf = FactGateOutcome.PARTIAL, Confidence.of(
                    0.5, f"single independence cluster ({n_clusters}) for consequential claim")
            elif consequential:
                outcome, conf = FactGateOutcome.SUPPORTED, Confidence.of(
                    0.8, f"{n_clusters} independent clusters corroborate")
            elif n_clusters >= 2:
                outcome, conf = FactGateOutcome.SUPPORTED, Confidence.of(
                    0.85, f"{n_clusters} independent clusters; direct observation")
            else:
                outcome, conf = FactGateOutcome.SUPPORTED, Confidence.of(
                    0.7, "one source direct observation; single-source caveat recorded")
                reasons.append("single-source direct observation")

            records.append(GateRecord(
                subject_id=subject, predicate=predicate, value=value,
                outcome=outcome.value, confidence=conf, observation_ids=obs_ids,
                evidence_ids=tuple(eids), independent_cluster_count=n_clusters,
                reasons=tuple(reasons), bias_notes=tuple(bias_notes),
                stale=all(stale_flags)))

        for o in no_evidence:
            records.append(GateRecord(
                subject_id=o.subject_id or subject, predicate=o.predicate or predicate,
                value=o.value, outcome=FactGateOutcome.REJECTED_NO_EVIDENCE.value,
                confidence=Confidence.unknown(), observation_ids=(o.observation_id,),
                reasons=("candidate fact without evidence linkage rejected "
                         "(fact-first law)",)))
        return records

    # ------------------------------------------------------------------ summary
    def run(self, observations: list[Observation], *, case_id: str = "",
            now: Optional[datetime] = None) -> FactSummary:
        groups: dict[tuple[str, str], list[Observation]] = {}
        for o in observations:
            groups.setdefault((o.subject_id or "", o.predicate or ""), []).append(o)
        summary = FactSummary(case_id=case_id, observations_total=len(observations))
        buckets = {
            FactGateOutcome.SUPPORTED.value: summary.supported,
            FactGateOutcome.PARTIAL.value: summary.partial,
            FactGateOutcome.DISPUTED.value: summary.disputed,
            FactGateOutcome.INCONCLUSIVE.value: summary.inconclusive,
            FactGateOutcome.REJECTED_NO_EVIDENCE.value: summary.rejected,
        }
        rel_notes, bias_notes, indep_notes, temporal, identities, contras = \
            [], [], [], [], [], []
        for (_s, _p), group in groups.items():
            for rec in self.evaluate_group(group, now=now):
                buckets[rec.outcome].append(rec)
                if rec.stale:
                    temporal.append(f"{_s} {_p}: stale evidence kept historical, not current")
                for r in rec.reasons:
                    if "independence" in r or "cluster" in r:
                        indep_notes.append(f"{_s} {_p}: {r}")
                    if "corroboration" in r:
                        identities.append(f"{_s} {_p}: {r}")
                for b in rec.bias_notes:
                    bias_notes.append(f"{_s} {_p}: {b}")
                if rec.outcome == FactGateOutcome.SUPPORTED.value:
                    rel_notes.append(f"{_s} {_p}: supported with "
                                     f"{rec.independent_cluster_count} cluster(s)")
                if rec.outcome == FactGateOutcome.DISPUTED.value:
                    contras.append(f"{_s} {_p}: conflicting values preserved "
                                   f"({len(buckets[rec.outcome])} side(s) under review)")
        summary.reliability_notes = tuple(dict.fromkeys(rel_notes))
        summary.bias_limitations = tuple(dict.fromkeys(bias_notes))
        summary.independence_notes = tuple(dict.fromkeys(indep_notes))
        summary.temporal_limitations = tuple(dict.fromkeys(temporal))
        summary.identity_limitations = tuple(dict.fromkeys(identities))
        summary.contradictions = tuple(dict.fromkeys(contras))
        return summary
