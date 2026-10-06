"""Durable persistence tests for the case plane (SQLAlchemy, SQLite in-memory;
same models run on PostgreSQL in production)."""
from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from traceatlas.core.case import Case
from traceatlas.core.enums import CaseStatus
from traceatlas.db.base import Base
from traceatlas.db.models import AuditEventRecord  # noqa: F401  (ensures metadata)
from traceatlas.db.repositories.cases import CaseRepository
from traceatlas.db.session import build_engine


@pytest.fixture()
def session():
    eng = build_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


def _case(cid="CASE-1", tenant="acme", title="demo", status=CaseStatus.ACTIVE):
    return Case(case_id=cid, tenant_id=tenant, title=title, status=status)


def test_save_get_roundtrip(session):
    repo = CaseRepository(session)
    repo.save(_case())
    session.commit()
    got = repo.get("CASE-1")
    assert got is not None
    assert got.title == "demo" and got.status is CaseStatus.ACTIVE


def test_update_is_upsert_not_duplicate(session):
    repo = CaseRepository(session)
    repo.save(_case())
    session.commit()
    repo.save(_case(title="renamed", status=CaseStatus.CLOSED))
    session.commit()
    cases = repo.list("acme")
    assert len(cases) == 1
    assert cases[0].title == "renamed"
    assert cases[0].status is CaseStatus.CLOSED


def test_tenant_isolation_in_list(session):
    repo = CaseRepository(session)
    repo.save(_case(cid="CASE-A", tenant="alpha"))
    repo.save(_case(cid="CASE-B", tenant="beta"))
    session.commit()
    assert [c.case_id for c in repo.list("alpha")] == ["CASE-A"]
    assert [c.case_id for c in repo.list("beta")] == ["CASE-B"]
    assert repo.get("CASE-B") is not None  # direct get still works (authz enforced at API layer)


def test_missing_case_returns_none(session):
    assert CaseRepository(session).get("nope") is None


def test_audit_events_persist(session):
    repo = CaseRepository(session)
    repo.save(_case())
    repo.audit("CASE-1", "analyst", "investigation.started", {"wave": 1})
    session.commit()
    rows = session.query(AuditEventRecord).filter_by(case_id="CASE-1").all()
    assert len(rows) == 1
    assert rows[0].detail_json == {"wave": 1}
