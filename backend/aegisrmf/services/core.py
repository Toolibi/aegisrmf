"""Application services. Both the REST API and the MCP server call only these
functions, so authorization, tenant scoping and audit logging happen in one place."""
from __future__ import annotations

import re
from datetime import date, datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import catalog
from ..evidence import analyzer as an
from ..evidence import extract, ingest, injection
from ..models import (ASSET_CATEGORIES, POAM, POAM_STATES, Approval, Assessment, Asset, EvidenceArtifact,
                      EvidenceChunk, EvidenceLink, Finding, Milestone, ObjectiveResult, POAMHistory,
                      RequirementCondition, ScoreSnapshot, System, Tenant, User)
from ..scoring import cmmc
from ..security import audit
from ..security.auth import Forbidden, Principal, issue_key


class NotFound(LookupError):
    status = 404


class Conflict(ValueError):
    status = 409


class Invalid(ValueError):
    status = 422


def get_scoped(db: Session, model, obj_id: str, p: Principal):
    """Fetch a tenant-owned row. A row from another tenant is indistinguishable from a missing one."""
    obj = db.get(model, obj_id)
    if obj is None or getattr(obj, "tenant_id", None) != p.tenant_id:
        raise NotFound(f"{model.__name__} not found")
    return obj


# ---------------------------------------------------------------- tenants & users
def register_tenant(db: Session, name: str, slug: str, owner_email: str, owner_name: str) -> dict:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,60}", slug):
        raise Invalid("slug must be lowercase letters, digits, hyphens")
    if db.scalar(select(Tenant).where(Tenant.slug == slug)):
        raise Conflict("slug already registered")
    t = Tenant(name=name, slug=slug)
    db.add(t)
    db.flush()
    from ..db import bind_tenant
    bind_tenant(db, t.id)
    u = User(tenant_id=t.id, email=owner_email.lower(), display_name=owner_name, role="owner")
    db.add(u)
    db.flush()
    key = issue_key(db, u, label="owner bootstrap")
    p = Principal(t.id, u.id, "owner", frozenset(), channel="system")
    audit.record(db, p, "tenant.register", "tenant", t.id, {"slug": slug})
    return {"tenant_id": t.id, "owner_user_id": u.id, "api_key": key,
            "note": "Store this key now; it is shown once."}


def create_user_and_key(db: Session, p: Principal, email: str, name: str, role: str,
                        scopes: list[str] | None = None) -> dict:
    p.require("admin")
    if role not in ("owner", "assessor", "contributor", "viewer", "agent"):
        raise Invalid("unknown role")
    u = User(tenant_id=p.tenant_id, email=email.lower(), display_name=name, role=role)
    db.add(u)
    db.flush()
    key = issue_key(db, u, set(scopes) if scopes is not None else None, label=f"{role} key")
    audit.record(db, p, "user.create", "user", u.id, {"role": role, "scopes": scopes})
    return {"user_id": u.id, "role": role, "api_key": key}


# ---------------------------------------------------------------- systems & scoping
def create_system(db: Session, p: Principal, name: str, description: str = "", boundary: str = "",
                  data_types: list[str] | None = None, cui_data_flows: list[dict] | None = None) -> System:
    p.require("assessment:write")
    bad = set(data_types or []) - {"FCI", "CUI"}
    if bad:
        raise Invalid(f"unknown data types {bad}")
    s = System(tenant_id=p.tenant_id, name=name, description=description, boundary_description=boundary,
               data_types=data_types or [], cui_data_flows=cui_data_flows or [])
    db.add(s)
    db.flush()
    audit.record(db, p, "system.create", "system", s.id, {"name": name})
    return s


def add_asset(db: Session, p: Principal, system_id: str, name: str, category: str, asset_type: str = "",
              esp: bool = False, shared_responsibility: str = "") -> Asset:
    p.require("assessment:write")
    get_scoped(db, System, system_id, p)
    if category not in ASSET_CATEGORIES:
        raise Invalid(f"category must be one of {sorted(ASSET_CATEGORIES)}")
    a = Asset(tenant_id=p.tenant_id, system_id=system_id, name=name, category=category, asset_type=asset_type,
              is_external_service_provider=esp, shared_responsibility=shared_responsibility)
    db.add(a)
    db.flush()
    audit.record(db, p, "asset.create", "asset", a.id, {"category": category})
    return a


def list_systems(db: Session, p: Principal) -> list[System]:
    p.require("read")
    return list(db.scalars(select(System).where(System.tenant_id == p.tenant_id).order_by(System.created_at)))


# ---------------------------------------------------------------- assessments
def create_assessment(db: Session, p: Principal, system_id: str, framework_id: str = "cmmc-l2",
                      kind: str = "READINESS", title: str = "") -> Assessment:
    p.require("assessment:write")
    get_scoped(db, System, system_id, p)
    try:
        pkg = catalog.load(framework_id)
    except catalog.UnknownFramework as e:
        raise Invalid(str(e)) from e
    if kind not in ("READINESS", "SELF_ASSESSMENT_PREP", "C3PAO_PREP"):
        raise Invalid("kind must be READINESS, SELF_ASSESSMENT_PREP or C3PAO_PREP")
    a = Assessment(tenant_id=p.tenant_id, system_id=system_id, framework_id=framework_id,
                   framework_version=pkg["package_version"], kind=kind, title=title or f"{pkg['title']} {kind.lower()}",
                   created_by=p.user_id)
    db.add(a)
    db.flush()
    audit.record(db, p, "assessment.create", "assessment", a.id, {"framework": framework_id, "kind": kind})
    return a


def _editable(a: Assessment) -> None:
    if a.status == "FINALIZED":
        raise Conflict("assessment is finalized; reopen it to make changes (history is preserved)")


def set_objective_result(db: Session, p: Principal, assessment_id: str, objective_id: str, status: str,
                         rationale: str, methods: list[str] | None = None,
                         evidence_link_ids: list[str] | None = None) -> ObjectiveResult:
    """Human determination. Agents may never call this (agent role lacks findings:review)."""
    p.require("assessment:write")
    p.require("findings:review")
    a = get_scoped(db, Assessment, assessment_id, p)
    _editable(a)
    pkg = catalog.load(a.framework_id, a.framework_version)
    if objective_id not in pkg["_objectives"]:
        raise Invalid(f"unknown objective {objective_id}")
    st = cmmc.Status(status)
    if st == cmmc.Status.NOT_APPLICABLE and not rationale.strip():
        raise Invalid("NOT_APPLICABLE requires a justification")
    if st == cmmc.Status.MET and not (evidence_link_ids or rationale.strip()):
        raise Invalid("MET requires a rationale or accepted evidence")
    for lid in evidence_link_ids or []:
        link = get_scoped(db, EvidenceLink, lid, p)
        if link.status != "ACCEPTED" or link.assessment_id != a.id:
            raise Invalid("only accepted evidence links from this assessment may be cited")
    req_id = pkg["_objectives"][objective_id][0]
    r = db.scalar(select(ObjectiveResult).where(ObjectiveResult.assessment_id == a.id,
                                                ObjectiveResult.objective_id == objective_id))
    before = r.status if r else None
    if r is None:
        r = ObjectiveResult(tenant_id=p.tenant_id, assessment_id=a.id, objective_id=objective_id,
                            requirement_id=req_id, status=st.value, determined_by=p.user_id)
        db.add(r)
    r.status, r.rationale, r.methods = st.value, rationale, methods or []
    r.evidence_link_ids, r.determined_by, r.determined_at = evidence_link_ids or [], p.user_id, datetime.now(timezone.utc)
    db.flush()
    audit.record(db, p, "objective.determine", "objective_result", r.id,
                 {"assessment": a.id, "objective": objective_id, "from": before, "to": st.value})
    return r


def set_requirement_condition(db: Session, p: Principal, assessment_id: str, requirement_id: str,
                              partial_condition: str | None = None, na_justification: str | None = None,
                              implementation_statement: str | None = None) -> RequirementCondition:
    p.require("assessment:write")
    a = get_scoped(db, Assessment, assessment_id, p)
    _editable(a)
    if requirement_id not in catalog.load(a.framework_id, a.framework_version)["_index"]:
        raise Invalid("unknown requirement")
    if partial_condition is not None:
        p.require("findings:review")
        v = cmmc.load_rules()["point_values"].get(requirement_id)
        if not (isinstance(v, dict) and v["partial_condition"] == partial_condition):
            raise Invalid("partial condition not permitted for this requirement")
    rc = db.scalar(select(RequirementCondition).where(RequirementCondition.assessment_id == a.id,
                                                      RequirementCondition.requirement_id == requirement_id))
    if rc is None:
        rc = RequirementCondition(tenant_id=p.tenant_id, assessment_id=a.id, requirement_id=requirement_id)
        db.add(rc)
    if partial_condition is not None:
        rc.partial_condition = partial_condition or None
    if na_justification is not None:
        rc.na_justification = na_justification
    if implementation_statement is not None:
        rc.implementation_statement = implementation_statement
    db.flush()
    audit.record(db, p, "requirement.condition", "requirement_condition", rc.id,
                 {"requirement": requirement_id, "partial": rc.partial_condition})
    return rc


def requirement_statuses(db: Session, a: Assessment) -> dict[str, dict]:
    pkg = catalog.load(a.framework_id, a.framework_version)
    res = {r.objective_id: r for r in db.scalars(select(ObjectiveResult).where(ObjectiveResult.assessment_id == a.id))}
    conds = {c.requirement_id: c for c in db.scalars(
        select(RequirementCondition).where(RequirementCondition.assessment_id == a.id))}
    out = {}
    for c in pkg["controls"]:
        key = catalog.requirement_key(c)
        objs = [cmmc.Status(res[o["id"]].status) if o["id"] in res else cmmc.Status.NOT_ASSESSED
                for o in c["assessment_objectives"]]
        st = cmmc.derive_requirement_status(objs)
        cond = conds.get(key)
        na_just = None
        if st == cmmc.Status.NOT_APPLICABLE:
            na_just = (cond.na_justification if cond and cond.na_justification else None) or "; ".join(
                res[o["id"]].rationale for o in c["assessment_objectives"] if o["id"] in res)
        out[key] = {"status": st, "partial": cond.partial_condition if cond else None, "na": na_just,
                    "objectives": {o["id"]: s.value for o, s in zip(c["assessment_objectives"], objs)},
                    "implementation_statement": cond.implementation_statement if cond else None}
    return out


def calculate_score(db: Session, p: Principal, assessment_id: str, mode: str = "READINESS",
                    snapshot: bool = False) -> dict:
    p.require("read")
    a = get_scoped(db, Assessment, assessment_id, p)
    reqs = requirement_statuses(db, a)
    if a.framework_id == "cmmc-l1":
        return {"framework": "cmmc-l1", **cmmc.score_level1({k: v["status"] for k, v in reqs.items()}, list(reqs))}
    inputs = [cmmc.RequirementInput(k, v["status"], v["partial"] if v["status"] == cmmc.Status.NOT_MET else None,
                                    v["na"]) for k, v in reqs.items()]
    result = cmmc.score_level2(inputs, cmmc.Mode(mode)).to_dict()
    result.update({"assessment_id": a.id, "assessment_revision": a.revision, "assessment_status": a.status,
                   "framework": f"{a.framework_id}@{a.framework_version}"})
    if snapshot:
        db.add(ScoreSnapshot(tenant_id=p.tenant_id, assessment_id=a.id, assessment_revision=a.revision,
                             mode=mode, score=result["score"], input_hash=result["input_hash"], result=result,
                             created_by=p.user_id))
        audit.record(db, p, "score.snapshot", "assessment", a.id,
                     {"mode": mode, "score": result["score"], "input_hash": result["input_hash"]})
    return result


def finalize_assessment(db: Session, p: Principal, assessment_id: str, comment: str = "") -> dict:
    p.require("assessment:finalize")
    if p.role == "agent":
        raise Forbidden("AI agents cannot finalize assessments")
    a = get_scoped(db, Assessment, assessment_id, p)
    _editable(a)
    score = calculate_score(db, p, a.id, "OFFICIAL", snapshot=True)
    if score.get("errors"):
        raise Conflict("cannot finalize: " + "; ".join(score["errors"]))
    a.status, a.finalized_at = "FINALIZED", datetime.now(timezone.utc)
    db.add(Approval(tenant_id=p.tenant_id, entity="assessment", entity_id=a.id, decision="FINALIZE",
                    actor_id=p.user_id, comment=comment))
    audit.record(db, p, "assessment.finalize", "assessment", a.id,
                 {"revision": a.revision, "score": score["score"], "input_hash": score["input_hash"]})
    return score


def reopen_assessment(db: Session, p: Principal, assessment_id: str, reason: str) -> Assessment:
    p.require("assessment:finalize")
    a = get_scoped(db, Assessment, assessment_id, p)
    if a.status != "FINALIZED":
        raise Conflict("only finalized assessments can be reopened")
    if not reason.strip():
        raise Invalid("a reason is required")
    a.status, a.revision = "DRAFT", a.revision + 1
    db.add(Approval(tenant_id=p.tenant_id, entity="assessment", entity_id=a.id, decision="REOPEN",
                    actor_id=p.user_id, comment=reason))
    audit.record(db, p, "assessment.reopen", "assessment", a.id, {"new_revision": a.revision, "reason": reason})
    return a


# ---------------------------------------------------------------- evidence
def upload_evidence(db: Session, p: Principal, system_id: str, filename: str, data: bytes,
                    classification: str = "INTERNAL", store: ingest.BlobStore | None = None) -> EvidenceArtifact:
    p.require("evidence:write")
    get_scoped(db, System, system_id, p)
    if classification not in ingest.CLASSIFICATIONS:
        raise Invalid("classification must be PUBLIC, INTERNAL, FCI or CUI")
    try:
        v = ingest.detect_and_validate(filename, data)
    except ingest.RejectedFile as e:
        audit.record(db, p, "evidence.rejected", "system", system_id, {"filename": filename[:200], "reason": str(e)})
        raise Invalid(f"rejected: {e}") from e
    store = store or ingest.BlobStore()
    prior = db.scalars(select(EvidenceArtifact).where(EvidenceArtifact.tenant_id == p.tenant_id,
                                                      EvidenceArtifact.system_id == system_id,
                                                      EvidenceArtifact.filename == filename)).all()
    if any(x.sha256 == v.sha256 for x in prior):
        raise Conflict("identical file already uploaded")
    lines, note = extract.extract_lines(v.detected_type, data)
    art = EvidenceArtifact(tenant_id=p.tenant_id, system_id=system_id, filename=filename,
                           detected_type=v.detected_type, evidence_kind=extract.classify_kind(filename, lines),
                           classification=classification, sha256=v.sha256, size_bytes=v.size,
                           version=len(prior) + 1, storage_key=store.put(p.tenant_id, v.sha256, data),
                           text_extracted=bool(lines), extraction_note=note, uploaded_by=p.user_id)
    db.add(art)
    db.flush()
    flags = set()
    for i, c in enumerate(extract.chunk(lines)):
        hits = injection.screen(c["text"])
        flags.update(hits)
        db.add(EvidenceChunk(tenant_id=p.tenant_id, artifact_id=art.id, ordinal=i, page=c["page"],
                             section=c["section"][:300], line_start=c["line_start"], line_end=c["line_end"],
                             text=c["text"], injection_suspected=bool(hits)))
    art.injection_flags = sorted(flags)
    db.flush()
    audit.record(db, p, "evidence.upload", "evidence", art.id,
                 {"sha256": v.sha256, "type": v.detected_type, "classification": classification,
                  "version": art.version, "injection_flags": len(flags)})
    return art


def list_evidence(db: Session, p: Principal, system_id: str) -> list[EvidenceArtifact]:
    p.require("read")
    get_scoped(db, System, system_id, p)
    return list(db.scalars(select(EvidenceArtifact).where(EvidenceArtifact.tenant_id == p.tenant_id,
                                                          EvidenceArtifact.system_id == system_id)
                           .order_by(EvidenceArtifact.collected_at)))


def analyze_assessment_evidence(db: Session, p: Principal, assessment_id: str, analyzer=None) -> dict:
    """Run the Evidence Analysis Agent over the system's evidence; creates PROPOSED links only."""
    p.require("assessment:write")
    a = get_scoped(db, Assessment, assessment_id, p)
    _editable(a)
    if analyzer is None:
        from ..config import get_settings
        if get_settings().ai_provider == "azure-foundry":
            from ..evidence.foundry_client import from_settings
            client, deployment = from_settings()
            analyzer = an.FoundryAnalyzer(client, deployment)
        else:
            analyzer = an.RulesAnalyzer()
    arts = db.scalars(select(EvidenceArtifact).where(EvidenceArtifact.tenant_id == p.tenant_id,
                                                     EvidenceArtifact.system_id == a.system_id)).all()
    existing = {(l.artifact_id, l.objective_id) for l in db.scalars(
        select(EvidenceLink).where(EvidenceLink.assessment_id == a.id))}
    created, skipped = 0, []
    for art in arts:
        chunks = [{"id": c.id, "artifact_id": art.id, "page": c.page, "text": c.text,
                   "injection_suspected": c.injection_suspected}
                  for c in db.scalars(select(EvidenceChunk).where(EvidenceChunk.artifact_id == art.id)
                                      .order_by(EvidenceChunk.ordinal))]
        try:
            if isinstance(analyzer, an.FoundryAnalyzer):
                props = analyzer.propose(a.framework_id, a.framework_version, chunks, art.classification)
            else:
                props = analyzer.propose(a.framework_id, a.framework_version, chunks)
        except an.CUINotApproved as e:
            skipped.append({"artifact": art.id, "reason": str(e)})
            continue
        for pr in props:
            if (art.id, pr.objective_id) in existing:
                continue
            db.add(EvidenceLink(
                tenant_id=p.tenant_id, assessment_id=a.id, artifact_id=art.id, chunk_id=pr.chunk_id,
                objective_id=pr.objective_id, requirement_id=pr.requirement_id, origin="AI", status="PROPOSED",
                confidence=pr.confidence, analyzer=analyzer.name, analyzer_version=analyzer.version,
                prompt_version=analyzer.prompt_version,
                citation={"artifact_id": art.id, "filename": art.filename, "version": art.version,
                          "sha256": art.sha256, "page": pr.page, "line": pr.line_no, "quote": pr.quote,
                          "collected_at": art.collected_at.isoformat(), "system_id": art.system_id,
                          "evidence_kind": art.evidence_kind, "rationale": pr.rationale}))
            existing.add((art.id, pr.objective_id))
            created += 1
    db.flush()
    audit.record(db, p, "evidence.analyze", "assessment", a.id,
                 {"analyzer": analyzer.name, "proposed": created, "skipped": len(skipped)})
    flagged = [x.id for x in arts if x.injection_flags]
    return {"proposed_links": created, "skipped": skipped, "artifacts_with_injection_flags": flagged}


def review_link(db: Session, p: Principal, link_id: str, decision: str, comment: str = "") -> EvidenceLink:
    p.require("findings:review")
    if p.role == "agent":
        raise Forbidden("AI agents cannot review evidence links")
    link = get_scoped(db, EvidenceLink, link_id, p)
    _editable(get_scoped(db, Assessment, link.assessment_id, p))
    if decision not in ("ACCEPTED", "REJECTED"):
        raise Invalid("decision must be ACCEPTED or REJECTED")
    link.status, link.reviewer_id, link.reviewed_at, link.review_comment = (
        decision, p.user_id, datetime.now(timezone.utc), comment)
    db.flush()
    audit.record(db, p, "evidence_link.review", "evidence_link", link.id, {"decision": decision})
    return link


def list_links(db: Session, p: Principal, assessment_id: str, objective_id: str | None = None,
               status: str | None = None) -> list[EvidenceLink]:
    p.require("read")
    get_scoped(db, Assessment, assessment_id, p)
    q = select(EvidenceLink).where(EvidenceLink.tenant_id == p.tenant_id, EvidenceLink.assessment_id == assessment_id)
    if objective_id:
        q = q.where(EvidenceLink.objective_id == objective_id)
    if status:
        q = q.where(EvidenceLink.status == status)
    return list(db.scalars(q.order_by(EvidenceLink.objective_id, EvidenceLink.confidence.desc())))


def propose_findings(db: Session, p: Principal, assessment_id: str) -> list[Finding]:
    """CMMC Assessment Agent + QA: one UNREVIEWED AI finding per objective, from accepted evidence only."""
    p.require("assessment:write")
    a = get_scoped(db, Assessment, assessment_id, p)
    _editable(a)
    pkg = catalog.load(a.framework_id, a.framework_version)
    accepted: dict[str, list[EvidenceLink]] = {}
    for l in list_links(db, p, a.id, status="ACCEPTED"):
        accepted.setdefault(l.objective_id, []).append(l)
    for f in db.scalars(select(Finding).where(Finding.assessment_id == a.id, Finding.origin == "AI",
                                              Finding.review_status == "UNREVIEWED")):
        db.delete(f)
    out = []
    for oid, (rid, obj) in pkg["_objectives"].items():
        links = accepted.get(oid, [])
        kinds = [l.citation.get("evidence_kind", "other") for l in links]
        status, warnings, statement = an.propose_finding(obj["text"], kinds)
        f = Finding(tenant_id=p.tenant_id, assessment_id=a.id, requirement_id=rid, objective_id=oid, origin="AI",
                    proposed_status=status, statement=statement, evidence_link_ids=[l.id for l in links],
                    qa_warnings=warnings, analyzer=f"assessment-agent/{an.ANALYZER_VERSION}")
        db.add(f)
        out.append(f)
    db.flush()
    audit.record(db, p, "findings.propose", "assessment", a.id, {"count": len(out)})
    return out


# ---------------------------------------------------------------- POA&M
TRANSITIONS = {
    "DRAFT": {"OPEN"}, "OPEN": {"IN_PROGRESS", "BLOCKED", "ACCEPTED_RISK"},
    "IN_PROGRESS": {"BLOCKED", "PENDING_VERIFICATION", "ACCEPTED_RISK"}, "BLOCKED": {"IN_PROGRESS", "ACCEPTED_RISK"},
    "PENDING_VERIFICATION": {"CLOSED", "IN_PROGRESS"}, "CLOSED": set(), "ACCEPTED_RISK": {"OPEN"},
}


def generate_poams(db: Session, p: Principal, assessment_id: str) -> list[POAM]:
    p.require("poam:write")
    a = get_scoped(db, Assessment, assessment_id, p)
    if a.framework_id == "cmmc-l1":
        raise Conflict("POA&Ms are not permitted for CMMC Level 1 (32 CFR 170.21(a)(1))")
    reqs = requirement_statuses(db, a)
    have = {x.requirement_id for x in db.scalars(select(POAM).where(POAM.assessment_id == a.id))}
    pkg = catalog.load(a.framework_id, a.framework_version)
    rules = cmmc.load_rules()
    out = []
    for rid, info in reqs.items():
        if info["status"] != cmmc.Status.NOT_MET or rid in have:
            continue
        ok, basis = cmmc.poam_permitted(rid, info["partial"], rules)
        pts, _ = cmmc._value(rules, rid, info["partial"])
        failed = [o for o, s in info["objectives"].items() if s == "NOT_MET"]
        n = len(have) + len(out) + 1
        x = POAM(tenant_id=p.tenant_id, display_id=f"POAM-{a.revision:02d}-{n:03d}", assessment_id=a.id,
                 requirement_id=rid, weakness=f"{pkg['_index'][rid]['id']} {pkg['_index'][rid]['title']}: "
                 f"objectives NOT MET: {', '.join(failed)}",
                 severity="HIGH" if pts >= 5 else "MODERATE" if pts == 3 else "LOW", point_value=pts,
                 cmmc_poam_permitted=ok, cmmc_poam_basis=basis)
        db.add(x)
        db.flush()
        db.add(POAMHistory(tenant_id=p.tenant_id, poam_id=x.id, from_status="", to_status="DRAFT",
                           actor_id=p.user_id, comment="generated from NOT MET requirement"))
        out.append(x)
    db.flush()
    audit.record(db, p, "poam.generate", "assessment", a.id, {"created": len(out)})
    return out


def update_poam(db: Session, p: Principal, poam_id: str, **fields) -> POAM:
    p.require("poam:write")
    x = get_scoped(db, POAM, poam_id, p)
    allowed = {"risk_owner", "remediation_owner", "corrective_action", "resources", "dependencies",
               "scheduled_completion", "affected_assets", "severity", "source_evidence"}
    bad = set(fields) - allowed
    if bad:
        raise Invalid(f"fields not updatable here: {sorted(bad)}")
    if "scheduled_completion" in fields and fields["scheduled_completion"]:
        date.fromisoformat(fields["scheduled_completion"])
    for k, v in fields.items():
        setattr(x, k, v)
    db.flush()
    audit.record(db, p, "poam.update", "poam", x.id, {"fields": sorted(fields)})
    return x


def add_milestone(db: Session, p: Principal, poam_id: str, description: str, due_date: str) -> Milestone:
    p.require("poam:write")
    x = get_scoped(db, POAM, poam_id, p)
    date.fromisoformat(due_date)
    m = Milestone(tenant_id=p.tenant_id, poam_id=x.id, description=description, due_date=due_date)
    db.add(m)
    db.flush()
    audit.record(db, p, "poam.milestone", "poam", x.id, {"due": due_date})
    return m


def transition_poam(db: Session, p: Principal, poam_id: str, to_status: str, comment: str = "",
                    closure_evidence: list[str] | None = None) -> POAM:
    p.require("poam:write")
    x = get_scoped(db, POAM, poam_id, p)
    if to_status not in POAM_STATES:
        raise Invalid("unknown status")
    if to_status not in TRANSITIONS[x.status]:
        raise Conflict(f"cannot move POA&M from {x.status} to {to_status}")
    if to_status == "OPEN" and not (x.risk_owner and x.remediation_owner and x.corrective_action and x.scheduled_completion):
        raise Invalid("risk owner, remediation owner, corrective action and scheduled completion are required to open")
    if to_status == "PENDING_VERIFICATION":
        if not closure_evidence:
            raise Invalid("closure evidence is required")
        for eid in closure_evidence:
            get_scoped(db, EvidenceArtifact, eid, p)
        x.closure_evidence = closure_evidence
    if to_status in ("CLOSED", "ACCEPTED_RISK"):
        p.require("findings:review")
        if p.role == "agent":
            raise Forbidden("AI agents cannot verify, close or accept risk")
    if to_status == "CLOSED":
        if not x.closure_evidence:
            raise Invalid("closure evidence is required")
        x.verified_by = x.approved_by = p.user_id
        x.actual_completion = date.today().isoformat()
    if to_status == "ACCEPTED_RISK" and not comment.strip():
        raise Invalid("risk acceptance requires a written justification")
    db.add(POAMHistory(tenant_id=p.tenant_id, poam_id=x.id, from_status=x.status, to_status=to_status,
                       actor_id=p.user_id, comment=comment))
    before, x.status = x.status, to_status
    db.flush()
    audit.record(db, p, "poam.transition", "poam", x.id, {"from": before, "to": to_status})
    # NOTE: ACCEPTED_RISK never changes the requirement result; it stays NOT MET for scoring.
    return x


def list_poams(db: Session, p: Principal, assessment_id: str) -> list[POAM]:
    p.require("read")
    get_scoped(db, Assessment, assessment_id, p)
    return list(db.scalars(select(POAM).where(POAM.tenant_id == p.tenant_id, POAM.assessment_id == assessment_id)
                           .order_by(POAM.display_id)))


def overdue_poams(db: Session, p: Principal, today: str | None = None) -> list[POAM]:
    p.require("read")
    t = today or date.today().isoformat()
    return [x for x in db.scalars(select(POAM).where(POAM.tenant_id == p.tenant_id))
            if x.status not in ("CLOSED", "ACCEPTED_RISK") and x.scheduled_completion and x.scheduled_completion < t]
