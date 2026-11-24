"""Reporting Agent (deterministic): assessment report, SSP draft, signed evidence manifest.
Reports only restate stored, attributed data. Nothing is generated to fill gaps."""
from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import catalog
from ..models import POAM, Assessment, Asset, EvidenceArtifact, EvidenceLink, Finding, ObjectiveResult, System, Tenant
from ..security import audit
from ..security.auth import Principal
from . import core

NOT_PROVIDED = "[NOT PROVIDED - no implementation statement has been entered]"


def build_report(db: Session, p: Principal, assessment_id: str) -> dict:
    p.require("report:export")
    a = core.get_scoped(db, Assessment, assessment_id, p)
    system = core.get_scoped(db, System, a.system_id, p)
    tenant = db.get(Tenant, p.tenant_id)
    pkg = catalog.load(a.framework_id, a.framework_version)
    mode = "OFFICIAL" if a.status == "FINALIZED" else "READINESS"
    score = core.calculate_score(db, p, a.id, mode)
    reqs = core.requirement_statuses(db, a)
    results = {r.objective_id: r for r in db.scalars(select(ObjectiveResult).where(ObjectiveResult.assessment_id == a.id))}
    links = {l.id: l for l in db.scalars(select(EvidenceLink).where(EvidenceLink.assessment_id == a.id,
                                                                     EvidenceLink.status == "ACCEPTED"))}
    findings = db.scalars(select(Finding).where(Finding.assessment_id == a.id)).all()
    evidence = db.scalars(select(EvidenceArtifact).where(EvidenceArtifact.system_id == system.id,
                                                         EvidenceArtifact.tenant_id == p.tenant_id)).all()
    requirements = []
    for c in pkg["controls"]:
        key = catalog.requirement_key(c)
        info = reqs[key]
        objs = []
        for o in c["assessment_objectives"]:
            r = results.get(o["id"])
            objs.append({
                "objective": o["id"], "text": o["text"], "status": info["objectives"][o["id"]],
                "determined_by": r.determined_by if r else None, "rationale": r.rationale if r else "",
                "methods": r.methods if r else [],
                "citations": [links[i].citation for i in (r.evidence_link_ids if r else []) if i in links],
                "ai_suggestions": [{"proposed_status": f.proposed_status, "review_status": f.review_status,
                                    "qa_warnings": f.qa_warnings}
                                   for f in findings if f.objective_id == o["id"] and f.origin == "AI"],
            })
        requirements.append({"id": c["id"], "key": key, "title": c["title"], "status": info["status"].value,
                             "partial_condition": info["partial"], "objectives": objs})
    poams = [{"id": x.display_id, "requirement": x.requirement_id, "status": x.status, "points": x.point_value,
              "cmmc_poam_permitted": x.cmmc_poam_permitted, "basis": x.cmmc_poam_basis,
              "scheduled_completion": x.scheduled_completion, "weakness": x.weakness}
             for x in db.scalars(select(POAM).where(POAM.assessment_id == a.id).order_by(POAM.display_id))]
    report = {
        "report_type": "AegisRMF Assessment Report",
        "label": ("FINALIZED INTERNAL ASSESSMENT RECORD" if mode == "OFFICIAL"
                  else "READINESS REVIEW - INCOMPLETE / NOT A FORMAL ASSESSMENT"),
        "disclaimer": score.get("disclaimer"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "organization": tenant.name, "system": {"id": system.id, "name": system.name,
                                                 "boundary": system.boundary_description,
                                                 "data_types": system.data_types},
        "assets": [{"name": x.name, "category": x.category, "esp": x.is_external_service_provider}
                   for x in db.scalars(select(Asset).where(Asset.system_id == system.id))],
        "assessment": {"id": a.id, "kind": a.kind, "status": a.status, "revision": a.revision,
                       "framework": a.framework_id, "framework_package": a.framework_version,
                       "framework_revision": pkg["revision"], "catalog_source_sha256": pkg.get("source_sha256")},
        "score": score, "requirements": requirements, "poams": poams,
    }
    manifest = {"assessment_id": a.id, "revision": a.revision, "score_input_hash": score.get("input_hash"),
                "evidence": sorted([{"artifact_id": e.id, "filename": e.filename, "version": e.version,
                                     "sha256": e.sha256} for e in evidence], key=lambda d: d["artifact_id"]),
                "report_body_sha256": hashlib.sha256(json.dumps(report, sort_keys=True, default=str).encode()).hexdigest()}
    report["manifest"] = manifest
    report["manifest_signature"] = audit.sign_manifest(manifest)
    audit.record(db, p, "report.export", "assessment", a.id, {"report_sha256": manifest["report_body_sha256"]})
    return report


def report_markdown(r: dict) -> str:
    s = r["score"]
    out = [f"# {r['report_type']}", f"**{r['label']}**", "", f"> {r['disclaimer']}", "",
           f"- Organization: {r['organization']}", f"- System: {r['system']['name']}",
           f"- Framework: {r['assessment']['framework']} ({r['assessment']['framework_revision']})",
           f"- Assessment: {r['assessment']['id']} rev {r['assessment']['revision']} - {r['assessment']['status']}",
           f"- Score ({s.get('mode', 'L1')}): **{s.get('score')} / {s.get('max_score', '')}** indicator {s.get('indicator', '')}",
           f"- Rules: {s.get('rules_version')} (review status: {s.get('rules_review_status')}) input hash `{s.get('input_hash')}`",
           ""]
    if s.get("blockers"):
        out += ["## Blockers"] + [f"- {b}" for b in s["blockers"]] + [""]
    out += ["## Score trace", "```"] + s.get("trace", []) + ["```", "", "## Requirements", "",
                                                            "| Requirement | Title | Status |", "|---|---|---|"]
    out += [f"| {q['id']} | {q['title']} | {q['status']} |" for q in r["requirements"]]
    out += ["", "## Evidence citations (accepted, human-reviewed)"]
    for q in r["requirements"]:
        for o in q["objectives"]:
            for c in o["citations"]:
                loc = f"p.{c['page']} " if c.get("page") else ""
                out.append(f"- {o['objective']}: {c['filename']} v{c['version']} {loc}line {c['line']} "
                           f"(sha256 {c['sha256'][:12]}...) - \"{c['quote'][:160]}\"")
    out += ["", "## POA&M", "", "| ID | Req | Points | Permitted on CMMC POA&M | Status | Due |", "|---|---|---|---|---|---|"]
    out += [f"| {x['id']} | {x['requirement']} | {x['points']} | {'yes' if x['cmmc_poam_permitted'] else 'NO - ' + x['basis']} "
            f"| {x['status']} | {x['scheduled_completion'] or ''} |" for x in r["poams"]]
    out += ["", "## Evidence manifest", f"Signature (HMAC-SHA256): `{r['manifest_signature']}`", ""]
    out += [f"- {e['filename']} v{e['version']} `{e['sha256']}`" for e in r["manifest"]["evidence"]]
    return "\n".join(out) + "\n"


def to_docx(markdown: str) -> bytes:
    import docx
    d = docx.Document()
    for line in markdown.splitlines():
        if line.startswith("# "):
            d.add_heading(line[2:], 0)
        elif line.startswith("## "):
            d.add_heading(line[3:], 1)
        elif line.startswith("- "):
            d.add_paragraph(line[2:], style="List Bullet")
        elif line.strip() and not line.startswith("```") and not line.startswith("|---"):
            d.add_paragraph(line.replace("**", ""))
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def ssp_draft(db: Session, p: Principal, assessment_id: str) -> str:
    """SSP Agent (deterministic): assembles validated data only; gaps are shown as gaps."""
    p.require("report:export")
    a = core.get_scoped(db, Assessment, assessment_id, p)
    system = core.get_scoped(db, System, a.system_id, p)
    pkg = catalog.load(a.framework_id, a.framework_version)
    reqs = core.requirement_statuses(db, a)
    assets = db.scalars(select(Asset).where(Asset.system_id == system.id)).all()
    out = [f"# System Security Plan - DRAFT", f"**System:** {system.name}", "",
           "> Draft assembled from data entered in AegisRMF. Sections marked NOT PROVIDED must be completed "
           "by the system owner. This draft is not an approved SSP.", "",
           "## 1. System description", system.description or NOT_PROVIDED, "",
           "## 2. Authorization boundary", system.boundary_description or NOT_PROVIDED, "",
           f"Data types: {', '.join(system.data_types) or NOT_PROVIDED}", "",
           "## 3. Assets in scope", "", "| Asset | Category | Type | ESP |", "|---|---|---|---|"]
    out += [f"| {x.name} | {x.category} | {x.asset_type} | {'yes' if x.is_external_service_provider else ''} |" for x in assets] \
        or [f"| {NOT_PROVIDED} | | | |"]
    out += ["", "## 4. Requirement implementation", ""]
    for c in pkg["controls"]:
        key = catalog.requirement_key(c)
        info = reqs[key]
        out += [f"### {c['id']} - {c['title']}", f"*Requirement:* {c['statement']}", "",
                f"*Implementation:* {info['implementation_statement'] or NOT_PROVIDED}", "",
                f"*Current assessment status:* {info['status'].value}", ""]
    audit.record(db, p, "ssp.draft", "assessment", a.id, {})
    return "\n".join(out) + "\n"
