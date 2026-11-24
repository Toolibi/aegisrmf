"""REST API (OpenAPI at /docs). Thin layer over services.core."""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import catalog
from ..config import get_settings
from ..db import create_all, get_session
from ..security import audit
from ..security.auth import AuthError, Forbidden, Principal, verify_bearer
from ..services import core, reports

@asynccontextmanager
async def lifespan(_app):
    if get_settings().database_url.startswith("sqlite"):
        create_all()  # dev convenience; PostgreSQL schema is managed only by `alembic upgrade head`
    yield


app = FastAPI(title="AegisRMF API", version="0.1.0", lifespan=lifespan,
              description="AI-assisted CMMC / NIST RMF readiness platform. AI output is advisory; humans decide.")


@app.exception_handler(AuthError)
async def _auth(_: Request, e: AuthError):
    return JSONResponse({"detail": str(e)}, status_code=401, headers={"WWW-Authenticate": "Bearer"})


for exc, code in ((Forbidden, 403), (core.NotFound, 404), (core.Conflict, 409), (core.Invalid, 422)):
    def _make(c):
        async def handler(_: Request, e: Exception):
            return JSONResponse({"detail": str(e)}, status_code=c)
        return handler
    app.add_exception_handler(exc, _make(code))


_cors = [o.strip() for o in __import__("os").getenv("AEGIS_CORS_ORIGINS", "").split(",") if o.strip()]
if _cors:
    from fastapi.middleware.cors import CORSMiddleware
    # Explicit origin allowlist only (no wildcard): the dashboard sends a bearer key, never cookies.
    app.add_middleware(CORSMiddleware, allow_origins=_cors, allow_methods=["GET", "POST", "PUT", "PATCH"],
                       allow_headers=["Authorization", "Content-Type"], allow_credentials=False)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                         "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
    return resp


def principal(authorization: str | None = Header(default=None), db: Session = Depends(get_session)) -> Principal:
    token = authorization[7:] if authorization and authorization.lower().startswith("bearer ") else None
    return verify_bearer(db, token)


# ------------------------------------------------------------------ models
class TenantIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str
    owner_email: str
    owner_name: str


class UserIn(BaseModel):
    email: str
    name: str
    role: str
    scopes: list[str] | None = None


class SystemIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    boundary: str = ""
    data_types: list[str] = []
    cui_data_flows: list[dict] = []


class AssetIn(BaseModel):
    name: str
    category: str
    asset_type: str = ""
    esp: bool = False
    shared_responsibility: str = ""


class AssessmentIn(BaseModel):
    system_id: str
    framework_id: str = "cmmc-l2"
    kind: str = "READINESS"
    title: str = ""


class ObjectiveIn(BaseModel):
    status: str
    rationale: str = ""
    methods: list[str] = []
    evidence_link_ids: list[str] = []


class ConditionIn(BaseModel):
    partial_condition: str | None = None
    na_justification: str | None = None
    implementation_statement: str | None = None


class ReviewIn(BaseModel):
    decision: str
    comment: str = ""


class PoamPatch(BaseModel):
    risk_owner: str | None = None
    remediation_owner: str | None = None
    corrective_action: str | None = None
    resources: str | None = None
    dependencies: list[str] | None = None
    scheduled_completion: str | None = None
    affected_assets: list[str] | None = None
    severity: str | None = None


class TransitionIn(BaseModel):
    to_status: str
    comment: str = ""
    closure_evidence: list[str] | None = None


class MilestoneIn(BaseModel):
    description: str
    due_date: str


class ReasonIn(BaseModel):
    reason: str = ""


def _row(o) -> dict[str, Any]:
    return {c.name: getattr(o, c.name) for c in o.__table__.columns if c.name not in ("secret_hash", "storage_key")}


# ------------------------------------------------------------------ routes
@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/v1/tenants", status_code=201)
def register(body: TenantIn, x_bootstrap_token: str | None = Header(default=None), db: Session = Depends(get_session)):
    expected = get_settings().bootstrap_token
    if not expected or not x_bootstrap_token or not hmac.compare_digest(expected, x_bootstrap_token):
        raise HTTPException(401, "tenant registration requires the platform bootstrap token")
    return core.register_tenant(db, body.name, body.slug, body.owner_email, body.owner_name)


@app.post("/v1/users", status_code=201)
def create_user(body: UserIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return core.create_user_and_key(db, p, body.email, body.name, body.role, body.scopes)


@app.get("/v1/me")
def me(p: Principal = Depends(principal), db: Session = Depends(get_session)):
    from ..models import Tenant, User
    t, u = db.get(Tenant, p.tenant_id), db.get(User, p.user_id)
    return {"tenant": t.name, "tenant_id": t.id, "user": u.display_name, "email": u.email, "role": p.role,
            "scopes": sorted(p.scopes)}


@app.get("/v1/assessments")
def list_assessments(p: Principal = Depends(principal), db: Session = Depends(get_session)):
    p.require("read")
    from sqlalchemy import select as _sel
    from ..models import Assessment, System
    rows = db.scalars(_sel(Assessment).where(Assessment.tenant_id == p.tenant_id).order_by(Assessment.created_at.desc()))
    names = {s.id: s.name for s in core.list_systems(db, p)}
    return [{**_row(a), "system_name": names.get(a.system_id, "")} for a in rows]


@app.get("/v1/assessments/{aid}/requirements")
def requirement_view(aid: str, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    """Per-requirement status with titles, point values and link/finding counts (dashboard matrix)."""
    p.require("read")
    from collections import Counter
    from sqlalchemy import select as _sel
    from ..models import Assessment, EvidenceLink, Finding
    from ..scoring import cmmc as _c
    a = core.get_scoped(db, Assessment, aid, p)
    pkg = catalog.load(a.framework_id, a.framework_version)
    reqs = core.requirement_statuses(db, a)
    links = Counter((l.requirement_id, l.status) for l in db.scalars(_sel(EvidenceLink).where(EvidenceLink.assessment_id == a.id)))
    ai = {}
    for f in db.scalars(_sel(Finding).where(Finding.assessment_id == a.id, Finding.origin == "AI")):
        ai.setdefault(f.requirement_id, Counter())[f.proposed_status] += 1
    rules = _c.load_rules() if a.framework_id == "cmmc-l2" else None
    out = []
    for c in pkg["controls"]:
        k = catalog.requirement_key(c)
        info = reqs[k]
        pts = None
        if rules:
            v = rules["point_values"][k]
            pts = v if isinstance(v, int) or v is None else v["max"]
        out.append({"id": c["id"], "key": k, "family": c["family"], "family_title": c.get("family_title", c["family"]),
                    "title": c["title"], "statement": c["statement"], "status": info["status"].value,
                    "points": pts, "partial_condition": info["partial"],
                    "implementation_statement": info["implementation_statement"],
                    "objectives": [{"id": o["id"], "text": o["text"], "status": info["objectives"][o["id"]]}
                                   for o in c["assessment_objectives"]],
                    "links_proposed": links[(k, "PROPOSED")], "links_accepted": links[(k, "ACCEPTED")],
                    "ai_suggestions": dict(ai.get(k, {}))})
    return out


@app.get("/v1/assessments/{aid}/findings")
def findings(aid: str, requirement_id: str | None = None, p: Principal = Depends(principal),
             db: Session = Depends(get_session)):
    p.require("read")
    from sqlalchemy import select as _sel
    from ..models import Assessment, Finding
    core.get_scoped(db, Assessment, aid, p)
    q = _sel(Finding).where(Finding.tenant_id == p.tenant_id, Finding.assessment_id == aid)
    if requirement_id:
        q = q.where(Finding.requirement_id == requirement_id)
    return [_row(f) for f in db.scalars(q.order_by(Finding.objective_id))]


@app.get("/v1/frameworks")
def frameworks(p: Principal = Depends(principal)):
    p.require("read")
    return catalog.list_frameworks()


@app.get("/v1/frameworks/{framework_id}/controls")
def controls(framework_id: str, family: str | None = None, p: Principal = Depends(principal)):
    p.require("read")
    try:
        pkg = catalog.load(framework_id)
    except catalog.UnknownFramework:
        raise HTTPException(404, "unknown framework")
    return [c for c in pkg["controls"] if not family or c["family"] == family.upper()]


@app.post("/v1/systems", status_code=201)
def create_system(body: SystemIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.create_system(db, p, body.name, body.description, body.boundary, body.data_types, body.cui_data_flows))


@app.get("/v1/systems")
def systems(p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return [_row(s) for s in core.list_systems(db, p)]


@app.post("/v1/systems/{system_id}/assets", status_code=201)
def asset(system_id: str, body: AssetIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.add_asset(db, p, system_id, body.name, body.category, body.asset_type, body.esp,
                               body.shared_responsibility))


@app.post("/v1/systems/{system_id}/evidence", status_code=201)
async def upload(system_id: str, file: UploadFile = File(...), classification: str = Form("INTERNAL"),
                 p: Principal = Depends(principal), db: Session = Depends(get_session)):
    data = await file.read(get_settings().max_upload_bytes + 1)
    return _row(core.upload_evidence(db, p, system_id, file.filename or "upload", data, classification))


@app.get("/v1/systems/{system_id}/evidence")
def evidence(system_id: str, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return [_row(e) for e in core.list_evidence(db, p, system_id)]


@app.post("/v1/assessments", status_code=201)
def create_assessment(body: AssessmentIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.create_assessment(db, p, body.system_id, body.framework_id, body.kind, body.title))


@app.get("/v1/assessments/{aid}")
def get_assessment(aid: str, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    p.require("read")
    from ..models import Assessment
    a = core.get_scoped(db, Assessment, aid, p)
    reqs = core.requirement_statuses(db, a)
    counts: dict[str, int] = {}
    for v in reqs.values():
        counts[v["status"].value] = counts.get(v["status"].value, 0) + 1
    return {**_row(a), "requirement_status_counts": counts}


@app.post("/v1/assessments/{aid}/analyze")
def analyze(aid: str, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return core.analyze_assessment_evidence(db, p, aid)


@app.get("/v1/assessments/{aid}/evidence-links")
def links(aid: str, objective_id: str | None = None, status: str | None = None,
          p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return [_row(l) for l in core.list_links(db, p, aid, objective_id, status)]


@app.post("/v1/evidence-links/{lid}/review")
def review(lid: str, body: ReviewIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.review_link(db, p, lid, body.decision, body.comment))


@app.post("/v1/assessments/{aid}/findings/propose")
def propose(aid: str, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    fs = core.propose_findings(db, p, aid)
    return {"count": len(fs), "by_status": {s: sum(1 for f in fs if f.proposed_status == s)
                                           for s in {f.proposed_status for f in fs}}}


@app.put("/v1/assessments/{aid}/objectives/{oid}")
def objective(aid: str, oid: str, body: ObjectiveIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.set_objective_result(db, p, aid, oid, body.status, body.rationale, body.methods, body.evidence_link_ids))


@app.put("/v1/assessments/{aid}/requirements/{rid}")
def condition(aid: str, rid: str, body: ConditionIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.set_requirement_condition(db, p, aid, rid, body.partial_condition, body.na_justification,
                                               body.implementation_statement))


@app.get("/v1/assessments/{aid}/score")
def score(aid: str, mode: str = "READINESS", p: Principal = Depends(principal), db: Session = Depends(get_session)):
    if mode not in ("READINESS", "OFFICIAL"):
        raise HTTPException(422, "mode must be READINESS or OFFICIAL")
    return core.calculate_score(db, p, aid, mode)


@app.post("/v1/assessments/{aid}/finalize")
def finalize(aid: str, body: ReasonIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return core.finalize_assessment(db, p, aid, body.reason)


@app.post("/v1/assessments/{aid}/reopen")
def reopen(aid: str, body: ReasonIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.reopen_assessment(db, p, aid, body.reason))


@app.post("/v1/assessments/{aid}/poams/generate")
def gen_poams(aid: str, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return [_row(x) for x in core.generate_poams(db, p, aid)]


@app.get("/v1/assessments/{aid}/poams")
def poams(aid: str, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return [_row(x) for x in core.list_poams(db, p, aid)]


@app.patch("/v1/poams/{pid}")
def patch_poam(pid: str, body: PoamPatch, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.update_poam(db, p, pid, **body.model_dump(exclude_none=True)))


@app.post("/v1/poams/{pid}/milestones", status_code=201)
def milestone(pid: str, body: MilestoneIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.add_milestone(db, p, pid, body.description, body.due_date))


@app.post("/v1/poams/{pid}/transition")
def transition(pid: str, body: TransitionIn, p: Principal = Depends(principal), db: Session = Depends(get_session)):
    return _row(core.transition_poam(db, p, pid, body.to_status, body.comment, body.closure_evidence))


@app.get("/v1/assessments/{aid}/report")
def report(aid: str, format: str = "json", p: Principal = Depends(principal), db: Session = Depends(get_session)):
    r = reports.build_report(db, p, aid)
    if format == "json":
        return r
    md = reports.report_markdown(r)
    if format == "md":
        return PlainTextResponse(md, media_type="text/markdown")
    if format == "docx":
        return Response(reports.to_docx(md), media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": f'attachment; filename="aegis-report-{aid[:8]}.docx"'})
    raise HTTPException(422, "format must be json, md or docx")


@app.get("/v1/assessments/{aid}/ssp")
def ssp(aid: str, format: str = "md", p: Principal = Depends(principal), db: Session = Depends(get_session)):
    md = reports.ssp_draft(db, p, aid)
    if format == "docx":
        return Response(reports.to_docx(md), media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    return PlainTextResponse(md, media_type="text/markdown")


@app.get("/v1/audit/verify")
def verify_audit(p: Principal = Depends(principal), db: Session = Depends(get_session)):
    p.require("read")
    return audit.verify_chain(db, p.tenant_id)
