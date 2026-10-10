"""traceatlas.api.app - real routes over the investigation plane.

Endpoints (all evidence-first; authorization enforced before any collection):
  GET  /health                 liveness + persistence backend info
  POST /cases                  create durable case (PostgreSQL/SQLite via SQLAlchemy)
  GET  /cases                  list cases for tenant
  GET  /cases/{id}             case detail
  POST /cases/{id}/investigate run bounded authorized investigation (offline-safe plan,
                                live connectors only when scope asserts authorization);
                                successful runs are mirrored durably into SQL
                                (investigations/tasks/evidence/graph/observations/
                                contradictions)
  GET  /cases/{id}/investigations   durable investigation history
  GET  /investigations/{id}/tasks   task records for an investigation
  GET  /cases/{id}/graph       temporal knowledge graph snapshot (DB first, file fallback)
  GET  /cases/{id}/evidence    evidence registry for the case (DB first)
  GET  /cases/{id}/observations typed observations for the case
  GET  /cases/{id}/contradictions detected contradictions (durable)
  GET  /cases/{id}/report      markdown intelligence report + replay manifest path

This replaces the previous stub-only api tree on these paths; remaining route
files stay listed as stubs in .ai/FILE_IMPLEMENTATION_LEDGER.json until wired.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from traceatlas.config import load_settings
from traceatlas.core.case import Case
from traceatlas.core.enums import CaseStatus, InvestigationStatus
from traceatlas.db.repositories.cases import CaseRepository
from traceatlas.db.repositories.investigation import (
    InvestigationRepository, TaskRepository)
from traceatlas.db.repositories.truth import (
    ContradictionRepository, EvidenceRepository, GraphRepository, ObservationRepository)
from traceatlas.db.session import build_engine, build_session_factory
from traceatlas.investigation.manager import InvestigationManager


def create_app(db_url: str | None = None, workspace_root: str | Path | None = None) -> FastAPI:
    settings = load_settings()
    engine = build_engine(db_url or settings.database.url)
    session_factory = build_session_factory(engine)
    ws_root = Path(workspace_root or ".traceatlas/cases")
    manager = InvestigationManager(workspace_root=ws_root)

    app = FastAPI(title="TraceAtlas Intelligence OS", version="0.2.0")

    def get_session():
        with Session(engine) as s:
            yield s

    class CaseCreate(BaseModel):
        title: str = Field(min_length=1, max_length=500)
        tenant_id: str = "default"

    class InvestigateRequest(BaseModel):
        objective: str = Field(min_length=3)
        authorized_scope: bool = False
        scope_note: str = ""

    @app.get("/health")
    def health():
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "database": engine.url.render_as_string(hide_password=True)}

    @app.post("/cases", status_code=201)
    def create_case(body: CaseCreate, session: Session = Depends(get_session)):
        repo = CaseRepository(session)
        case = Case(tenant_id=body.tenant_id, title=body.title, status=CaseStatus.DRAFT)
        repo.save(case)
        repo.audit(case.case_id, body.tenant_id, "case.created")
        session.commit()
        return {"case_id": case.case_id, "title": case.title, "status": case.status.value}

    @app.get("/cases")
    def list_cases(tenant_id: str = "default", session: Session = Depends(get_session)):
        cases = CaseRepository(session).list(tenant_id)
        return [{"case_id": c.case_id, "title": c.title, "status": c.status.value}
                for c in cases]

    @app.get("/cases/{case_id}")
    def get_case(case_id: str, session: Session = Depends(get_session)):
        case = CaseRepository(session).get(case_id)
        if case is None:
            raise HTTPException(404, "case not found")
        return case.to_dict()

    @app.post("/cases/{case_id}/investigate")
    def investigate(case_id: str, body: InvestigateRequest,
                    session: Session = Depends(get_session)):
        repo = CaseRepository(session)
        case = repo.get(case_id)
        if case is None:
            raise HTTPException(404, "case not found")
        inv_repo = InvestigationRepository(session)
        task_repo = TaskRepository(session)
        investigation_id = f"inv_{case_id}_{int(datetime.now(timezone.utc).timestamp())}"
        inv_repo.start(investigation_id, case_id, plan=None,
                       payload={"objective": body.objective,
                                "authorized_scope": body.authorized_scope})
        result = manager.investigate(body.objective, case_id=case_id,
                                     authorized=body.authorized_scope,
                                     scope_note=body.scope_note)
        if result.get("ok"):
            # durable mirror of the run: investigations/tasks/evidence/graph/
            # observations/contradictions — SQL becomes the production query path
            ws = manager.workspace(case_id)
            EvidenceRepository(session).ingest_workspace(case_id, ws.evidence.root)
            GraphRepository(session).ingest_workspace(case_id, ws.root / "graph.jsonl")
            ObservationRepository(session).ingest_workspace(case_id, ws.observations_path)
            _persist_contradictions(session, case_id, ws)
            _persist_tasks(session, task_repo, investigation_id, case_id, ws)
            inv_repo.finish(investigation_id, InvestigationStatus.COMPLETED,
                            stop_reason="OBJECTIVE_SATISFIED_OR_STOPPED",
                            summary=result.get("summary"))
            repo.save(Case(case_id=case.case_id, tenant_id=case.tenant_id,
                           title=case.title, status=CaseStatus.ACTIVE,
                           objective=case.objective,
                           created_at=case.created_at))
            repo.audit(case_id, "ai_employee", "investigation.completed",
                       {"investigation_id": investigation_id,
                        "tasks": result.get("summary", {}).get("tasks_total")})
        else:
            inv_repo.finish(investigation_id, InvestigationStatus.STOPPED,
                            stop_reason=f"AUTHORIZATION_BOUNDARY:{result.get('reason', '')[:200]}")
            repo.audit(case_id, "ai_employee", "investigation.refused",
                       {"investigation_id": investigation_id,
                        "reason": result.get("reason", "")})
        session.commit()
        if not result.get("ok"):
            raise HTTPException(403, result)
        return {**result, "investigation_id": investigation_id}

    @app.get("/cases/{case_id}/investigations")
    def list_investigations(case_id: str, session: Session = Depends(get_session)):
        rows = InvestigationRepository(session).list_for_case(case_id)
        return [{"investigation_id": r.investigation_id, "status": r.status,
                 "stop_reason": r.stop_reason,
                 "created_at": r.created_at.isoformat()} for r in rows]

    @app.get("/investigations/{investigation_id}/tasks")
    def list_tasks(investigation_id: str, session: Session = Depends(get_session)):
        tasks = TaskRepository(session).list_for_investigation(investigation_id)
        return [{"task_id": t.task_id, "name": t.name, "kind": t.kind.value,
                 "status": t.status.value, "wave": t.wave, "attempts": t.attempts,
                 "error": t.error} for t in tasks]

    @app.get("/cases/{case_id}/contradictions")
    def contradictions(case_id: str, session: Session = Depends(get_session)):
        items = ContradictionRepository(session).list_for_case(case_id)
        return {"case_id": case_id, "count": len(items), "items": items}

    @app.get("/cases/{case_id}/observations")
    def observations(case_id: str, session: Session = Depends(get_session)):
        obs = ObservationRepository(session).list_for_case(case_id)
        return {"case_id": case_id, "count": len(obs),
                "items": [o.to_dict() for o in obs]}

    @app.get("/cases/{case_id}/graph")
    def graph(case_id: str, session: Session = Depends(get_session)):
        snap = GraphRepository(session).snapshot(case_id)
        if not snap["entities"]:
            # fall back to the workspace file so pre-DB cases remain visible
            ws = manager.workspace(case_id)
            snap = ws.graph.to_dict()
        if not snap.get("entities"):
            raise HTTPException(404, "no graph yet for case")
        return {"case_id": case_id, **snap}

    @app.get("/cases/{case_id}/evidence")
    def evidence(case_id: str, session: Session = Depends(get_session)):
        items = EvidenceRepository(session).list_for_case(case_id)
        if not items:
            ws = manager.workspace(case_id)
            reg = ws.evidence.registry_path
            if reg.exists():
                raw = [json.loads(l) for l in reg.read_text().splitlines() if l.strip()]
                return {"case_id": case_id, "count": len(raw), "items": raw,
                        "source": "workspace"}
            return {"case_id": case_id, "items": []}
        return {"case_id": case_id, "count": len(items), "source": "database",
                "items": [e.to_dict() for e in items]}

    @app.get("/cases/{case_id}/report")
    def report(case_id: str):
        from traceatlas.reporting.report_manager import ReportManager
        ws = manager.workspace(case_id)
        if not ws.state_path.exists():
            raise HTTPException(404, "no investigation output yet for this case")
        md = ReportManager().build(ws.root)
        return {"case_id": case_id, "report_md": md}

    return app


def _persist_contradictions(session: Session, case_id: str, ws) -> int:
    """Run the contradiction detector over durable observations and store results."""
    from traceatlas.verification.contradictions import ContradictionDetector
    obs = ObservationRepository(session).list_for_case(case_id)
    cons = ContradictionDetector().detect(obs)
    crepo = ContradictionRepository(session)
    for c in cons:
        crepo.save(case_id, c.contradiction_id, c.kind, "medium",
                   {"contradiction_id": c.contradiction_id, "subject": c.subject,
                    "predicate": c.predicate, "kind": c.kind, "sides": c.sides,
                    "status": c.status, "detected_at": c.detected_at},
                   resolution_status=c.status.lower())
    return len(cons)


def _persist_tasks(session: Session, task_repo: TaskRepository,
                   investigation_id: str, case_id: str, ws) -> int:
    """Mirror engine task records (checkpoint list) into the tasks table."""
    cp = ws.checkpoint_path
    if not cp.exists():
        return 0
    try:
        data = json.loads(cp.read_text())
    except Exception:
        return 0
    n = 0
    recs = data.get("tasks", [])
    if isinstance(recs, dict):
        recs = list(recs.values())
    for payload in recs:
        try:
            from traceatlas.core.task import Task
            task = Task.from_dict(payload)
            task_repo.save(task, investigation_id, wave=task.wave)
            n += 1
        except Exception:
            continue
    return n


app = create_app()
