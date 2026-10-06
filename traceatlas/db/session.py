"""Engine/session factory. PostgreSQL in production; SQLite URL supported for dev/tests."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from traceatlas.config import load_settings


def build_engine(url: str | None = None) -> Engine:
    url = url or load_settings().database.url
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
        if ":memory:" not in url and "/" in url.replace("sqlite:///", "/"):
            import os
            path = url.replace("sqlite:///", "")
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return create_engine(url, **kwargs)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def make_test_engine():  # convenience used by tests
    return build_engine("sqlite+pysqlite:///:memory:")
