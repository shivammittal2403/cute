"""Durable case repository over SQLAlchemy (removes process-local storage from the prod path)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from traceatlas.core.case import Case
from traceatlas.db.models.case import AuditEventRecord, CaseRecord


class CaseRepository:
    def __init__(self, session: Session):
        self.session = session

    def save(self, case: Case) -> CaseRecord:
        rec = self._by_id(case.case_id)
        payload = case.to_dict()
        if rec is None:
            rec = CaseRecord(case_id=case.case_id, tenant_id=case.tenant_id or "default",
                             title=case.title, status=case.status.value,
                             payload_json=payload)
            self.session.add(rec)
        else:
            rec.title = case.title
            rec.status = case.status.value
            rec.payload_json = payload
            rec.tenant_id = case.tenant_id or rec.tenant_id
        self.session.flush()
        return rec

    def _by_id(self, case_id: str) -> CaseRecord | None:
        return self.session.scalar(select(CaseRecord).where(CaseRecord.case_id == case_id))

    def get(self, case_id: str) -> Case | None:
        rec = self._by_id(case_id)
        return rec.to_domain() if rec else None

    def list(self, tenant_id: str = "default", limit: int = 100) -> list[Case]:
        rows = self.session.scalars(
            select(CaseRecord)
            .where(CaseRecord.tenant_id == tenant_id)
            .order_by(CaseRecord.pk.desc())
            .limit(limit)
        ).all()
        return [r.to_domain() for r in rows]

    def audit(self, case_id: str, actor: str, action: str, detail: dict | None = None):
        self.session.add(AuditEventRecord(case_id=case_id, actor=actor,
                                          action=action, detail_json=detail))
        self.session.flush()
