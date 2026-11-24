"""Run the full vertical slice in-process on SYNTHETIC data and write the outputs.

    python tools/demo.py [output_dir]

Everything describes a fictional company. Nothing here is a real compliance result.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SYN = ROOT / "tests" / "fixtures" / "synthetic"


def main(out_dir: str = "demo_output", keep_db: str | None = None) -> None:
    """keep_db: path for a persistent SQLite file (to browse the result in the dashboard).
    The owner API key is then written to <out_dir>/demo_api_key.txt."""
    tmp = tempfile.mkdtemp()
    db = keep_db or f"{tmp}/demo.db"
    os.environ.update(AEGIS_DATABASE_URL=f"sqlite:///{db}", AEGIS_DATA_DIR=os.path.dirname(os.path.abspath(db)) + "/data",
                      AEGIS_BOOTSTRAP_TOKEN="demo-bootstrap")
    from fastapi.testclient import TestClient

    from aegisrmf.api.main import app
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    with TestClient(app) as c:
        t = c.post("/v1/tenants", headers={"X-Bootstrap-Token": "demo-bootstrap"}, json={
            "name": "Northwind Precision Machining LLC (SYNTHETIC)", "slug": "northwind",
            "owner_email": "owner@northwind.example", "owner_name": "Demo Owner"}).json()
        H = {"Authorization": f"Bearer {t['api_key']}"}
        if keep_db:
            Path(out_dir).mkdir(exist_ok=True)
            (Path(out_dir) / "demo_api_key.txt").write_text(t["api_key"])
        s = c.post("/v1/systems", headers=H, json={
            "name": "Engineering CUI enclave", "description": "CAD/CAM workstations and CNC controllers handling CUI drawings.",
            "boundary": "Azure tenant + 3 endpoints + CNC controller VLAN", "data_types": ["FCI", "CUI"]}).json()
        for n, cat in [("NW-ENG-01", "CUI_ASSET"), ("Defender for Endpoint", "SECURITY_PROTECTION_ASSET"),
                       ("NW-CNC-PC1 (CNC controller)", "SPECIALIZED_ASSET")]:
            c.post(f"/v1/systems/{s['id']}/assets", headers=H, json={"name": n, "category": cat})
        a = c.post("/v1/assessments", headers=H, json={"system_id": s["id"], "title": "Q4 readiness review"}).json()
        for f in sorted(SYN.glob("*")):
            if f.name != "README.md":
                c.post(f"/v1/systems/{s['id']}/evidence", headers=H, files={"file": (f.name, f.read_bytes())})
        an = c.post(f"/v1/assessments/{a['id']}/analyze", headers=H).json()
        links = c.get(f"/v1/assessments/{a['id']}/evidence-links", headers=H).json()
        accepted = {}
        for l in links:
            if l["objective_id"].startswith(("3.1.1[", "3.5.3[", "3.14.4[")) and l["confidence"] >= 0.8:
                c.post(f"/v1/evidence-links/{l['id']}/review", headers=H, json={"decision": "ACCEPTED"})
                accepted.setdefault(l["objective_id"], []).append(l["id"])
        c.post(f"/v1/assessments/{a['id']}/findings/propose", headers=H)
        # Synthetic assessor determinations: illustrative gaps
        gaps = {"3.1.1[d]": "NOT_MET", "3.13.11[a]": "NOT_MET", "3.3.1[c]": "NOT_MET", "3.10.4[a]": "NOT_MET"}
        for ctl in c.get("/v1/frameworks/cmmc-l2/controls", headers=H).json():
            for o in ctl["assessment_objectives"]:
                st = gaps.get(o["id"], "MET")
                c.put(f"/v1/assessments/{a['id']}/objectives/{o['id']}", headers=H, json={
                    "status": st, "rationale": "Synthetic demo determination", "methods": ["examine"],
                    "evidence_link_ids": accepted.get(o["id"], [])})
        c.put(f"/v1/assessments/{a['id']}/requirements/3.13.11", headers=H, json={
            "partial_condition": "encryption_not_fips_validated",
            "implementation_statement": "BitLocker XTS-AES 256 on all CUI endpoints; FIPS mode not yet enabled."})
        c.put(f"/v1/assessments/{a['id']}/requirements/3.5.3", headers=H, json={
            "implementation_statement": "Entra ID Conditional Access requires MFA for all users (see export)."})
        score = c.get(f"/v1/assessments/{a['id']}/score?mode=OFFICIAL", headers=H).json()
        poams = c.post(f"/v1/assessments/{a['id']}/poams/generate", headers=H).json()
        for p in poams:  # give the permitted item an owner and date so the board shows a realistic state
            if p["cmmc_poam_permitted"]:
                c.patch(f"/v1/poams/{p['id']}", headers=H, json={"risk_owner": "CISO (demo)", "remediation_owner": "IT lead (demo)",
                        "corrective_action": "Enable FIPS mode for BitLocker via Intune policy", "scheduled_completion": "2027-02-15"})
                c.post(f"/v1/poams/{p['id']}/transition", headers=H, json={"to_status": "OPEN"})
                c.post(f"/v1/poams/{p['id']}/transition", headers=H, json={"to_status": "IN_PROGRESS"})
        (out / "report.json").write_text(json.dumps(c.get(f"/v1/assessments/{a['id']}/report", headers=H).json(), indent=1, default=str))
        (out / "report.md").write_text(c.get(f"/v1/assessments/{a['id']}/report?format=md", headers=H).text)
        (out / "report.docx").write_bytes(c.get(f"/v1/assessments/{a['id']}/report?format=docx", headers=H).content)
        (out / "ssp_draft.md").write_text(c.get(f"/v1/assessments/{a['id']}/ssp", headers=H).text)
        audit = c.get("/v1/audit/verify", headers=H).json()
    print(f"proposed links: {an['proposed_links']}  accepted: {sum(len(v) for v in accepted.values())}  "
          f"injection-flagged artifacts: {len(an['artifacts_with_injection_flags'])}")
    print("\n".join(score["trace"]))
    print(f"POA&M eligibility: {score['poam_evaluation']}")
    for p in poams:
        print(f"  {p['display_id']} {p['requirement_id']} {p['point_value']}pt permitted={p['cmmc_poam_permitted']} ({p['cmmc_poam_basis']})")
    print(f"audit chain: {audit}")
    print(f"outputs written to {out.resolve()}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir", nargs="?", default="demo_output")
    ap.add_argument("--keep-db", help="persistent SQLite path, to browse the demo in the dashboard")
    a = ap.parse_args()
    main(a.out_dir, a.keep_db)
