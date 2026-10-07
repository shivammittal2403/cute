"""traceatlas.intelligence.contracts — runtime contract dataclasses (§5, §10).

Every module manifest must validate against ModuleManifest. Every worker result
must be an EmployeeResult (structured, never prose concatenation). These types
are the authoritative shapes; modules must not fork them locally.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from traceatlas.core.enums import EntityKind
from traceatlas.intelligence.constants import (
    ModuleLifecycle, PrivacyClass, lifecycle_at_least)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class SourceRequirement:
    """What a module needs from a source to do its job honestly."""
    capability: str                      # e.g. "dns.A", "rdap.domain"
    min_qualification: str = "integration_tested"
    required: bool = True
    notes: str = ""


@dataclass(slots=True)
class Permissions:
    network: bool = False                # outbound collection permitted
    credential_sources: tuple[str, ...] = ()  # env/config keys allowed
    write_graph: bool = True
    write_evidence: bool = True
    cloud_ai: bool = False               # sending evidence to hosted models
    tenant_scope_required: bool = True


@dataclass(slots=True)
class CostEstimate:
    cost_class: str = "free"             # free | metered | paid | licensed
    latency_class: str = "fast"          # fast | moderate | slow | variable
    estimated_units: float = 0.0         # abstract budget units per run


@dataclass(slots=True)
class EvidenceRequirements:
    require_raw_capture: bool = True     # raw bytes MUST be preserved
    require_timestamps: bool = True
    require_source_uri: bool = True
    retention: str = "case_lifetime"


@dataclass(slots=True)
class VerificationRequirements:
    fact_gate: str = "required"          # required | waived_with_reason
    dual_ai_when_material: bool = True
    material_threshold: float = 0.6      # confidence above which review fires
    human_review_for: tuple[str, ...] = ("accusation", "attribution", "takedown")


@dataclass(slots=True)
class ModuleManifest:
    """The §5 runtime contract. `validate()` is enforced at registration time;
    an invalid manifest cannot enter the registry or the planner."""
    module_id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""
    version: str = "0.1.0"
    accepted_inputs: tuple[str, ...] = ()
    output_types: tuple[str, ...] = ()
    required_skills: tuple[str, ...] = ()
    source_requirements: tuple[SourceRequirement, ...] = ()
    configured_sources: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    prohibited_actions: tuple[str, ...] = ()
    permissions: Permissions = field(default_factory=Permissions)
    privacy_class: str = PrivacyClass.PUBLIC.value
    cost: CostEstimate = field(default_factory=CostEstimate)
    evidence_requirements: EvidenceRequirements = field(default_factory=EvidenceRequirements)
    verification_requirements: VerificationRequirements = field(default_factory=VerificationRequirements)
    source_boundaries: tuple[str, ...] = ()
    known_limitations: tuple[str, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    status: str = ModuleLifecycle.CREATED.value
    last_validated_sha: str = ""

    def validate(self, *, enforce_honesty: bool = True) -> list[str]:
        """Return a list of contract violations (empty == valid)."""
        from traceatlas.intelligence.constants import PROHIBITED_BASELINE
        errors: list[str] = []
        if not self.module_id or not self.module_id.replace("_", "").isalnum():
            errors.append("module_id missing or non-alphanumeric")
        if not self.name:
            errors.append("name missing")
        if not self.category:
            errors.append("category missing")
        if not self.description or len(self.description) < 20:
            errors.append("description missing or too thin to be meaningful")
        if not self.accepted_inputs:
            errors.append("accepted_inputs empty: module could never be invoked")
        if not self.output_types:
            errors.append("output_types empty: results would be untyped prose")
        if not self.required_skills:
            errors.append("required_skills empty: worker capability unconstrained")
        if not self.source_requirements and self.permissions.network:
            errors.append("network permission without declared source_requirements")
        overlap = set(self.allowed_actions) & set(self.prohibited_actions)
        if overlap:
            errors.append(f"actions both allowed and prohibited: {sorted(overlap)}")
        if enforce_honesty:
            missing_baseline = set(PROHIBITED_BASELINE) - set(self.prohibited_actions)
            if missing_baseline:
                errors.append(
                    f"prohibited_actions must cover the §34 baseline; missing {sorted(missing_baseline)}")
            if self.privacy_class in (PrivacyClass.RESTRICTED.value, PrivacyClass.LOCAL_ONLY.value) \
                    and self.permissions.cloud_ai:
                errors.append("restricted/local-only privacy class forbids cloud_ai permission")
            if self.status != ModuleLifecycle.CREATED.value \
                    and not lifecycle_at_least(self.status, ModuleLifecycle.IMPLEMENTED.value):
                errors.append("status before IMPLEMENTED must be created/partial/missing")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id, "name": self.name, "category": self.category,
            "description": self.description, "version": self.version,
            "accepted_inputs": list(self.accepted_inputs),
            "output_types": list(self.output_types),
            "required_skills": list(self.required_skills),
            "source_requirements": [vars(s) for s in self.source_requirements],
            "configured_sources": list(self.configured_sources),
            "allowed_actions": list(self.allowed_actions),
            "prohibited_actions": list(self.prohibited_actions),
            "permissions": vars(self.permissions),
            "privacy_class": self.privacy_class,
            "estimated_cost": vars(self.cost), "estimated_latency": self.cost.latency_class,
            "evidence_requirements": vars(self.evidence_requirements),
            "verification_requirements": vars(self.verification_requirements),
            "source_boundaries": list(self.source_boundaries),
            "known_limitations": list(self.known_limitations),
            "stop_conditions": list(self.stop_conditions),
            "status": self.status, "last_validated_sha": self.last_validated_sha,
        }


# ---------------------------------------------------------------- workforce (§10)

@dataclass(slots=True)
class AIEmployeeSpec:
    employee_id: str
    role: str
    department: str
    job_description: str
    skills: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    accepted_inputs: tuple[str, ...]
    output_schema: str = "EmployeeResult"
    required_evidence: bool = True
    quality_checks: tuple[str, ...] = ("fact_gate", "citation_coverage")
    escalation_rules: tuple[str, ...] = ("material_finding_to_dual_ai",
                                         "blocked_state_to_manager")
    model_policy: str = "hybrid"
    memory_policy: str = "write_observation_only"
    cost_policy: str = "reserve_before_run"


@dataclass(slots=True)
class TaskSpec:
    task_id: str
    case_id: str
    objective: str
    question: str
    inputs: dict[str, Any] = field(default_factory=dict)
    scope: str = ""
    authorization_granted: bool = False
    parent_task: Optional[str] = None
    manager_id: str = ""
    employee_id: str = ""
    required_skills: tuple[str, ...] = ()
    required_outputs: tuple[str, ...] = ()
    evidence_requirements: str = "raw_capture_required"
    priority: int = 3
    budget_units: float = 1.0
    deadline: Optional[datetime] = None


@dataclass(slots=True)
class CandidateFact:
    predicate: str
    value: Any
    subject_ref: str = ""
    evidence_ids: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EmployeeResult:
    """Structured worker output. Managers synthesize these, never raw prose."""
    task_id: str = ""
    module_id: str = ""
    employee_id: str = ""
    status: str = "succeeded"
    observations: list[dict[str, Any]] = field(default_factory=list)
    candidate_facts: list[CandidateFact] = field(default_factory=list)
    entities: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    bias_notes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    suggested_next_actions: tuple[str, ...] = ()
    error: str = ""
    finished_at: datetime = field(default_factory=_utcnow)

    def counts_as_intelligence(self) -> bool:
        """Blocked/skipped/cancelled/failed runs NEVER count as intelligence,
        even if they carry partial payloads."""
        from traceatlas.intelligence.constants import TERMINAL_FAILURE_OR_BLOCKED
        return self.status not in TERMINAL_FAILURE_OR_BLOCKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "module_id": self.module_id,
            "employee_id": self.employee_id, "status": self.status,
            "observations": self.observations,
            "candidate_facts": [vars(c) for c in self.candidate_facts],
            "entities": self.entities, "relationships": self.relationships,
            "events": self.events, "evidence_ids": list(self.evidence_ids),
            "source_ids": list(self.source_ids), "bias_notes": list(self.bias_notes),
            "limitations": list(self.limitations),
            "contradictions": list(self.contradictions),
            "unknowns": list(self.unknowns),
            "suggested_next_actions": list(self.suggested_next_actions),
            "error": self.error, "finished_at": self.finished_at.isoformat(),
        }


# canonical entity kinds understood by normalization/graph bridges
CANONICAL_ENTITY_KINDS = tuple(k.value for k in EntityKind)
