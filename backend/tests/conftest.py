import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIX = Path(__file__).parent / "fixtures"

from aegisrmf import db as dbmod  # noqa: E402
from aegisrmf.config import Settings, set_settings  # noqa: E402

BOOT = "test-bootstrap-token"


PG_ADMIN = os.getenv("AEGIS_TEST_PG_ADMIN_URL")  # e.g. postgresql+psycopg://postgres@/postgres?host=/tmp/pg&port=5433


def _fresh_postgres() -> str:
    """Recreate the test DB with Alembic (as admin) and return a URL for a NON-superuser app role,
    so PostgreSQL row-level security is actually enforced during the tests."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, make_url, text
    admin = create_engine(PG_ADMIN, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text("DROP DATABASE IF EXISTS aegis_test WITH (FORCE)"))
        c.execute(text("CREATE DATABASE aegis_test"))
        if not c.execute(text("SELECT 1 FROM pg_roles WHERE rolname='aegis_app'")).scalar():
            c.execute(text("CREATE ROLE aegis_app LOGIN PASSWORD 'aegis-app-test' NOSUPERUSER NOBYPASSRLS"))
    admin.dispose()
    test_admin_url = make_url(PG_ADMIN).set(database="aegis_test").render_as_string(hide_password=False)
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    os.environ["AEGIS_DATABASE_URL"] = test_admin_url
    command.upgrade(cfg, "head")
    del os.environ["AEGIS_DATABASE_URL"]
    e = create_engine(test_admin_url, isolation_level="AUTOCOMMIT")
    with e.connect() as c:
        c.execute(text("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app"))
        c.execute(text("REVOKE UPDATE, DELETE ON audit_events FROM aegis_app"))
    e.dispose()
    return make_url(test_admin_url).set(username="aegis_app", password="aegis-app-test").render_as_string(hide_password=False)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    url = _fresh_postgres() if PG_ADMIN else f"sqlite:///{tmp_path/'t.db'}"
    s = Settings(database_url=url, data_dir=tmp_path / "data", bootstrap_token=BOOT)
    set_settings(s)
    dbmod.init_engine(s.database_url)
    if not PG_ADMIN:
        dbmod.create_all()
    yield s
    dbmod.engine().dispose()


@pytest.fixture()
def client(env):
    from fastapi.testclient import TestClient
    from aegisrmf.api.main import app
    with TestClient(app) as c:
        yield c


def H(key):
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture()
def tenant(client):
    """Factory: register a tenant, return (owner_key, tenant_id)."""
    def make(slug):
        r = client.post("/v1/tenants", json={"name": f"{slug} (synthetic)", "slug": slug,
                                             "owner_email": f"owner@{slug}.example", "owner_name": "Owner"},
                        headers={"X-Bootstrap-Token": BOOT})
        assert r.status_code == 201, r.text
        return r.json()["api_key"], r.json()["tenant_id"]
    return make


def user_key(client, owner_key, role, scopes=None, email=None):
    r = client.post("/v1/users", json={"email": email or f"{role}@x.example", "name": role, "role": role,
                                       "scopes": scopes}, headers=H(owner_key))
    assert r.status_code == 201, r.text
    return r.json()["api_key"]
