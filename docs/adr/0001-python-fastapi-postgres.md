# ADR-0001: Python 3.12+/FastAPI, SQLAlchemy 2, PostgreSQL
**Decision.** Backend in Python with FastAPI + Pydantic, SQLAlchemy 2 + Alembic, PostgreSQL 16.
**Why.** The compliance ecosystem (compliance-trestle, Prowler, pypdf, python-docx) is Python; FastAPI gives
OpenAPI for free; PostgreSQL gives row-level security for tenant isolation. SQLite is used only for fast
local tests; CI also runs the suite on PostgreSQL with RLS enforced through a non-superuser role.
