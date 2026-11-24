from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_Session: sessionmaker | None = None


def init_engine(url: str | None = None):
    global _engine, _Session
    url = url or get_settings().database_url
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _fk(dbapi_conn, _):  # enforce FK constraints in SQLite
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
    _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def bind_tenant(session, tenant_id: str) -> None:
    """Bind the tenant for PostgreSQL RLS (transaction-local). No-op on SQLite (dev/test)."""
    from sqlalchemy import text
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant_id})


def engine():
    return _engine or init_engine()


def create_all():
    from . import models  # noqa: F401
    Base.metadata.create_all(engine())


@contextmanager
def session_scope():
    if _Session is None:
        init_engine()
    s: Session = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_session():
    if _Session is None:
        init_engine()
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
