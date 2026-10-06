"""traceatlas.investigation.manager - End-to-end investigation orchestrator.

Objective text -> ObjectiveParser -> authorization/scope gate -> Planner ->
InvestigationEngine with real connectors -> persisted case artifacts
(evidence store, graph JSONL, observations JSONL, audit log, checkpoint).
This is the single entry point used by CLI/API/tests for a vertical slice.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from traceatlas.core.case import Case
from traceatlas.core.enums import TaskStatus
from traceatlas.core.observation import Observation
from traceatlas.evidence.store import EvidenceStore
from traceatlas.graph.model import KnowledgeGraph
from traceatlas.objectives.parser import ObjectiveParser
from traceatlas.planning.planner import Planner
from traceatlas.sources.registry import SourceRegistry

from .engine import EngineConfig, InvestigationEngine


class CaseWorkspace:
    """Filesystem workspace per case (production target: Postgres + S3)."""

    def __init__(self, root: str | Path, case_id: str):
        self.root = Path(root) / case_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.evidence = EvidenceStore(self.root / "evidence")
        self.graph = KnowledgeGraph(self.root / "graph.jsonl")
        self.observations_path = self.root / "observations.jsonl"
        self.audit_path = self.root / "audit.jsonl"
        self.checkpoint_path = self.root / "checkpoint.json"
        self.state_path = self.root / "case_state.json"


class InvestigationManager:
    def __init__(self, workspace_root: str | Path = ".traceatlas/cases",
                 source_registry: SourceRegistry | None = None,
                 connectors: dict | None = None):
        self.workspace_root = Path(workspace_root)
        self.sources = source_registry or SourceRegistry.load_default()
        if connectors is None:
            from traceatlas.sources.connectors.dns import DNSConnector
            from traceatlas.sources.connectors.rdap import RDAPConnector
            from traceatlas.sources.connectors.http import HTTPConnector
            from traceatlas.sources.connectors.certificates import CertStreamConnector
            connectors = {
                "dns-system": DNSConnector(),
                "rdap-iana-bootstrap": RDAPConnector(),
                "web-direct": HTTPConnector(),
                "crtsh": CertStreamConnector(),
            }
        self.connectors = connectors

    # --------------------------------------------------------------------- run
    def investigate(self, objective_text: str, case_id: str | None = None,
                    authorized: bool = False, scope_note: str = "") -> dict:
        parser = ObjectiveParser()
        spec = parser.parse(objective_text)
        if not spec.authorization.is_valid() and not authorized:
            return {"ok": False, "stage": "authorization",
                    "reason": ("objective lacks valid authorization and caller did "
                               "not assert an authorized scope; refusing to collect"),
                    "ambiguities": list(spec.ambiguities)}
        ws = CaseWorkspace(self.workspace_root, case_id or spec.case_id or _auto_case_id())
        plan = Planner(self.sources).plan(spec)
        prior_obs = _load_observations(ws.observations_path)
        engine = InvestigationEngine(
            case_id=ws.root.name, evidence_store=ws.evidence, graph=ws.graph,
            connectors=self.connectors, config=EngineConfig(max_workers=4),
            checkpoint_path=ws.checkpoint_path, observations_out=prior_obs)
        summary = engine.run(plan)
        _append_observations(ws.observations_path, engine.observations[len(prior_obs):])
        _write_jsonl(ws.audit_path, engine.audit)
        state = {"case_id": ws.root.name, "objective": spec.raw_text,
                 "question": spec.question, "targets": [t.value for t in spec.targets],
                 "finished_at": datetime.now(timezone.utc).isoformat(),
                 "summary": summary,
                 "task_statuses": {t.name: t.status.value for t in plan.tasks}}
        ws.state_path.write_text(json.dumps(state, indent=2))
        return {"ok": True, "case_dir": str(ws.root), "spec": {
            "question": spec.question,
            "targets": [(t.kind.value, t.value) for t in spec.targets],
            "constraints": list(spec.constraints)},
            "plan_warnings": plan.warnings, **summary}


def _auto_case_id() -> str:
    return "case_" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _load_observations(path: Path) -> list[Observation]:
    out: list[Observation] = []
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(Observation.from_dict(json.loads(line)))
                    except Exception:
                        continue
    return out


def _append_observations(path: Path, obs: list[Observation]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for o in obs:
            fh.write(json.dumps(o.to_dict()) + "\n")


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
