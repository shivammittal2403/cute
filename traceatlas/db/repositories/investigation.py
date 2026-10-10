"""Durable repositories for the investigation plane.

Investigations and tasks are persisted as canonical domain payloads
(core.to_dict() / from_dict()) so the DB stays a durable mirror of the typed
model — never a second, loosely-typed source of truth.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from traceatlas.core.enums import InvestigationStatus, TaskStatus
from traceatlas.core.task import Task
from traceatlas.db.models.case import InvestigationRecord, TaskRecord


class InvestigationRepository:
    def __init__(self, session: Session):
        self.session = session

    def _by_id(self, investigation_id: str) -> InvestigationRecord | None:
        return self.session.scalar(
            select(InvestigationRecord).where(
                InvestigationRecord.investigation_id == investigation_id
            )
        )

    def start(self, investigation_id: str, case_id: str, plan: dict | None = None,
              payload: dict | None = None) -> InvestigationRecord:
        """Upsert an investigation in RUNNING state (called when collection begins)."""
        rec = self._by_id(investigation_id)
        if rec is None:
            rec = InvestigationRecord(
                investigation_id=investigation_id, case_id=case_id,
                status=InvestigationStatus.RUNNING.value, plan_json=plan,
                payload_json=payload,
            )
            self.session.add(rec)
        else:
            rec.status = InvestigationStatus.RUNNING.value
            rec.plan_json = plan if plan is not None else rec.plan_json
            rec.payload_json = payload if payload is not None else rec.payload_json
        self.session.flush()
        return rec

    def finish(self, investigation_id: str, status: InvestigationStatus,
               stop_reason: str = "", summary: dict | None = None) -> InvestigationRecord:
        rec = self._by_id(investigation_id)
        if rec is None:
            raise KeyError(f"unknown investigation {investigation_id}")
        rec.status = status.value
        rec.stop_reason = stop_reason
        if summary is not None:
            rec.payload_json = summary
        self.session.flush()
        return rec

    def get(self, investigation_id: str) -> InvestigationRecord | None:
        return self._by_id(investigation_id)

    def list_for_case(self, case_id: str) -> list[InvestigationRecord]:
        return list(self.session.scalars(
            select(InvestigationRecord)
            .where(InvestigationRecord.case_id == case_id)
            .order_by(InvestigationRecord.pk.desc())
        ).all())


class TaskRepository:
    def __init__(self, session: Session):
        self.session = session

    def _by_id(self, task_id: str) -> TaskRecord | None:
        return self.session.scalar(select(TaskRecord).where(TaskRecord.task_id == task_id))

    def save(self, task: Task, investigation_id: str, wave: int = 0) -> TaskRecord:
        rec = self._by_id(task.task_id)
        payload = task.to_dict()
        if rec is None:
            rec = TaskRecord(task_id=task.task_id, investigation_id=investigation_id,
                             wave=wave, status=task.status.value,
                             attempts=getattr(task, "attempts", 0),
                             error=getattr(task, "error", "") or "",
                             task_json=payload)
            self.session.add(rec)
        else:
            rec.status = task.status.value
            rec.attempts = getattr(task, "attempts", rec.attempts)
            rec.error = getattr(task, "error", "") or ""
            rec.result_json = payload.get("result")
            rec.task_json = payload
        self.session.flush()
        return rec

    def get(self, task_id: str) -> Task | None:
        rec = self._by_id(task_id)
        return Task.from_dict(rec.task_json) if rec else None

    def list_for_investigation(self, investigation_id: str,
                               status: TaskStatus | None = None) -> list[Task]:
        q = select(TaskRecord).where(TaskRecord.investigation_id == investigation_id)
        if status is not None:
            q = q.where(TaskRecord.status == status.value)
        return [r and Task.from_dict(r.task_json)
                for r in self.session.scalars(q.order_by(TaskRecord.pk)).all()]
