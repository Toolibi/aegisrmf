"""PostgreSQL row-level security on every customer-data table (defense in depth).

The application role must NOT be a superuser and must NOT have BYPASSRLS. Each
request binds its tenant with set_config('app.tenant_id', <id>, true) (transaction
local). With no tenant bound, policies return zero rows (fail closed).
Auth tables (tenants, users, api_keys) are looked up by key prefix before a tenant
is known and are excluded; they hold no assessment data.

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLES = ["systems", "assets", "assessments", "objective_results", "requirement_conditions",
          "evidence_artifacts", "evidence_chunks", "evidence_links", "findings", "poams", "milestones",
          "poam_history", "score_snapshots", "approvals", "audit_events"]


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    for t in TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON {t}
            USING (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true))""")
    # audit log is append-only for the application role
    op.execute("REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC")


def downgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    for t in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
