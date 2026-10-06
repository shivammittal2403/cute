"""TraceAtlas FastAPI application - real routes over the investigation plane.

Endpoints (all evidence-first; authorization enforced before any collection):
  GET  /health                 liveness + persistence backend info
  POST /cases                  create durable case (PostgreSQL/SQLite via SQLAlchemy)
  GET  /cases                  list cases for tenant
  GET  /cases/{id}             case detail
  POST /cases/{id}/investigate run bounded authorized investigation (offline-safe plan,
                                live connectors only when scope asserts authorization)
  GET  /cases/{id}/graph       temporal knowledge graph snapshot (entities+edges)
  GET  /cases/{id}/evidence    evidence registry for the case
  GET  /cases/{id}/report      markdown intelligence report + replay manifest path

This replaces the previous stub-only api tree on these paths; remaining route
files stay listed as stubs in .ai/FILE_IMPLEMENTATION_LEDGER.json until wired.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from traceatlas.config import load_settings
from traceatlas.core.case import Case
from traceatlas.core.enums import CaseStatus
from traceatlas.db.repositories.cases import CaseRepository
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
        result = manager.investigate(body.objective, case_id=case_id,
                                     authorized=body.authorized_scope,
                                     scope_note=body.scope_note)
        if result.get("ok"):
            repo.save(Case(case_id=case.case_id, tenant_id=case.tenant_id,
                           title=case.title, status=CaseStatus.ACTIVE,
                           objective=case.objective,
                           created_at=case.created_at))
            repo.audit(case_id, "ai_employee", "investigation.completed",
                       {"tasks": result.get("summary", {}).get("tasks_total")})
        else:
            repo.audit(case_id, "ai_employee", "investigation.refused",
                       {"reason": result.get("reason", "")})
        session.commit()
        if not result.get("ok"):
            raise HTTPException(403, result)
        return result

    @app.get("/cases/{case_id}/graph")
    def graph(case_id: str):
        ws = manager.workspace(case_id)
        snap = ws.graph.to_dict()
        if not snap.get("entities"):
            raise HTTPException(404, "no graph yet for case")
        return {"case_id": case_id, **snap}

    @app.get("/cases/{case_id}/evidence")
    def evidence(case_id: str):
        ws = manager.workspace(case_id)
        reg = ws.evidence.registry_path
        if not reg.exists():
            return {"case_id": case_id, "items": []}
        items = [json.loads(l) for l in reg.read_text().splitlines() if l.strip()]
        return {"case_id": case_id, "count": len(items), "items": items}

    @app.get("/cases/{case_id}/report")
    def report(case_id: str):
        from traceatlas.reporting.report_manager import ReportManager
        ws = manager.workspace(case_id)
        if not ws.state_path.exists():
            raise HTTPException(404, "no investigation output yet for this case")
        md = ReportManager().build(ws.root)
        return {"case_id": case_id, "report_md": md}

    return app


app = create_app()
