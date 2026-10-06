"""traceatlas.hypotheses.generator - Produce MULTIPLE plausible explanations.

Spec §6: never select the most interesting story; enumerate alternatives
deterministically from observation structure. Each generator rule emits a
competing set so ACH-style reasoning always has rivals to test against.
"""
from __future__ import annotations

from typing import Any

from traceatlas.core.enums import EntityKind, RelationshipKind
from traceatlas.core.observation import Observation

from .model import Hypothesis, HypothesisLifecycle


def _new(case_id: str | None, statement: str, htype: str,
         assumptions: list[str], required: list[str],
         falsifiers: list[str], discriminators: list[str],
         entities: list[str]) -> Hypothesis:
    return Hypothesis(
        case_id=case_id, statement=statement, htype=htype,
        status=HypothesisLifecycle.PROPOSED,
        assumptions=assumptions, required_evidence=required,
        falsification_conditions=falsifiers,
        discriminating_questions=discriminators,
        related_entity_ids=list(entities),
        created_by="hypothesis_generator",
    )


class HypothesisGenerator:
    """Deterministic alternative-explanation generator (no LLM)."""

    def generate_for_shared_ip(self, case_id: str | None,
                               domains: list[str], ip: str) -> list[Hypothesis]:
        """Two+ domains resolving to one IP must get >=5 competing explanations."""
        dom_list = ", ".join(sorted(set(domains)))
        ents = [ip] + list(domains)
        return [
            _new(case_id, f"the organization controlling {dom_list} also controls {ip}",
                 "causal", ["DNS observations are current"],
                 ["ownership/registrant evidence linking all domains"],
                 ["registrants differ across domains",
                  "IP belongs to a shared hosting provider used by unrelated tenants"],
                 ["Does registration data name the same registrant for each domain?"],
                 ents),
            _new(case_id, f"{dom_list} merely share hosting infrastructure at {ip}",
                 "alternative", [],
                 ["ASN/hosting context showing multi-tenant hosting"],
                 [f"{ip} is a dedicated single-tenant server owned by one registrant"],
                 ["Is the ASN a known CDN/shared-hosting range?"],
                 ents),
            _new(case_id, f"one of {dom_list} moved to {ip} recently; linkage is transitional",
                 "temporal", ["current DNS reflects a recent change"],
                 ["historical DNS records for each domain"],
                 ["all domains have long stable histories pointing at {0}".format(ip)],
                 ["Do historical DNS series show different IPs before this week?"],
                 ents),
            _new(case_id, f"the shared resolution to {ip} is stale or erroneous data",
                 "data_quality", ["sources may be outdated or incorrect"],
                 ["second independent resolver confirming current mapping"],
                 ["two independent live resolvers agree on every mapping"],
                 ["Does an independent resolver reproduce the same answers?"],
                 ents),
            _new(case_id, f"{ip} is CDN/proxy fronting unrelated origins behind {dom_list}",
                 "alternative", ["shared IP may be a front, not an origin"],
                 ["origin discovery / certificate SAN diversity"],
                 ["certificates and headers indicate distinct origin servers"],
                 ["Do TLS certificates reveal distinct backends per domain?"],
                 ents),
        ]

    def generate_for_identity_link(self, case_id: str | None,
                                   person: str, account: str) -> list[Hypothesis]:
        """Username/person correlation gets rival explanations (spec §8 example)."""
        return [
            _new(case_id, f"person '{person}' controls account '{account}'",
                 "identity", ["username string refers to one human"],
                 ["profile content naming the person",
                  "cross-platform handle consistency with corroborating attributes"],
                 ["public evidence links the account to a different person",
                  "activity times/locations are mutually impossible"],
                 ["Is there an independent identifier (email domain, location, employer) "
                  "matching both?"],
                 [person, account]),
            _new(case_id, f"'{account}' is a namesake — a different person chose the same handle",
                 "alternative", [], ["distinct biographic signals on the account"],
                 ["every profile attribute matches the target person"],
                 ["Do profile bio, locale, or history contradict the match?"],
                 [person, account]),
            _new(case_id, f"'{account}' is automated/impersonation rather than the person",
                 "alternative", [], ["account age, posting cadence, verification state"],
                 ["verified platform badge ties account to the person"],
                 ["Does the platform itself verify the identity?"],
                 [person, account]),
        ]

    def generate_for_observations(self, case_id: str | None,
                                  observations: list[Observation]) -> list[Hypothesis]:
        """Route structural observation patterns to the right rival generator."""
        out: list[Hypothesis] = []
        by_predicate: dict[str, list[Observation]] = {}
        for o in observations:
            by_predicate.setdefault(o.predicate, []).append(o)

        # shared-IP pattern: multiple subjects RESOLVES_TO same value
        resolves = by_predicate.get(RelationshipKind.RESOLVES_TO.value, [])
        by_target: dict[Any, list[Observation]] = {}
        for o in resolves:
            by_target.setdefault(str(o.value), []).append(o)
        for ip, obs in by_target.items():
            if len(obs) >= 2:
                domains = [str(o.subject_id) for o in obs]
                out.extend(self.generate_for_shared_ip(case_id, domains, ip))

        # identity-link pattern
        same_person = by_predicate.get(RelationshipKind.SAME_PERSON_AS.value, [])
        for o in same_person:
            out.extend(self.generate_for_identity_link(
                case_id, str(o.subject_id), str(o.value)))
        return out
