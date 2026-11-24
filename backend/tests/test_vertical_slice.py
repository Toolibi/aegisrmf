"""End-to-end acceptance: tenant -> system -> catalog -> evidence -> findings -> score -> POA&M -> SSP -> report."""
import io

from conftest import FIX, H, user_key

from aegisrmf.evidence.extract import line_text

SYN = FIX / "synthetic"


def upload(client, key, sid, name, classification="INTERNAL"):
    r = client.post(f"/v1/systems/{sid}/evidence", headers=H(key),
                    files={"file": (name, (SYN / name).read_bytes())}, data={"classification": classification})
    assert r.status_code == 201, r.text
    return r.json()


def setup_assessment(client, tenant):
    owner, _ = tenant("northwind")
    assessor = user_key(client, owner, "assessor")
    s = client.post("/v1/systems", headers=H(owner), json={
        "name": "CUI Enclave (synthetic)", "description": "Engineering enclave for CUI drawings.",
        "boundary": "Azure tenant northwind-synthetic + 3 endpoints", "data_types": ["FCI", "CUI"]}).json()
    for name, cat in [("NW-ENG-01", "CUI_ASSET"), ("Defender for Endpoint", "SECURITY_PROTECTION_ASSET"),
                      ("NW-CNC-PC1", "SPECIALIZED_ASSET")]:
        assert client.post(f"/v1/systems/{s['id']}/assets", headers=H(owner),
                           json={"name": name, "category": cat}).status_code == 201
    a = client.post("/v1/assessments", headers=H(owner), json={"system_id": s["id"]}).json()
    return owner, assessor, s, a


def test_full_vertical_slice(client, tenant):
    owner, assessor, s, a = setup_assessment(client, tenant)
    aid = a["id"]

    # catalog
    ctrls = client.get("/v1/frameworks/cmmc-l2/controls?family=AC", headers=H(owner)).json()
    assert len(ctrls) == 22 and ctrls[0]["assessment_objectives"][0]["id"] == "3.1.1[a]"

    # evidence
    pol = upload(client, owner, s["id"], "access_control_policy.txt")
    cfg = upload(client, owner, s["id"], "entra_conditional_access_export.json")
    edr = upload(client, owner, s["id"], "defender_endpoint_status.csv")
    memo = upload(client, owner, s["id"], "vendor_memo_untrusted.txt")
    assert pol["evidence_kind"] == "policy" and cfg["evidence_kind"] == "configuration"
    assert len(pol["sha256"]) == 64 and memo["injection_flags"]

    # analysis -> proposed links with exact citations
    res = client.post(f"/v1/assessments/{aid}/analyze", headers=H(owner)).json()
    assert res["proposed_links"] > 0 and memo["id"] in res["artifacts_with_injection_flags"]
    links = client.get(f"/v1/assessments/{aid}/evidence-links", headers=H(owner)).json()
    assert all(l["status"] == "PROPOSED" and l["origin"] == "AI" for l in links)
    assert not any(l["artifact_id"] == memo["id"] and "Ignore" in l["citation"]["quote"] for l in links)
    # citation accuracy: quote must be on the cited line of the original file
    originals = {pol["id"]: "access_control_policy.txt", cfg["id"]: "entra_conditional_access_export.json",
                 edr["id"]: "defender_endpoint_status.csv", memo["id"]: "vendor_memo_untrusted.txt"}
    for l in links:
        c = l["citation"]
        assert c["sha256"] and c["version"] == 1
        if c["filename"].endswith(".txt"):
            raw_line = (SYN / originals[c["artifact_id"]]).read_text().splitlines()[c["line"] - 1]
            assert c["quote"] in raw_line

    by_obj = {}
    for l in links:
        by_obj.setdefault(l["objective_id"], []).append(l)
    assert "3.1.1[a]" in by_obj, sorted(by_obj)[:20]
    assert "3.5.3[a]" in by_obj or "3.5.3[b]" in by_obj or "3.5.3[c]" in by_obj

    # human review of AI proposals (owner/assessor only)
    accepted = []
    for oid in ("3.1.1[a]", "3.1.1[d]"):
        for l in by_obj.get(oid, []):
            r = client.post(f"/v1/evidence-links/{l['id']}/review", headers=H(assessor),
                            json={"decision": "ACCEPTED", "comment": "reviewed"})
            assert r.status_code == 200
            accepted.append(l)

    # AI findings: policy-only evidence for an implementation objective -> INSUFFICIENT_EVIDENCE
    client.post(f"/v1/assessments/{aid}/findings/propose", headers=H(owner)).raise_for_status()
    f = client.get(f"/v1/assessments/{aid}/score", headers=H(owner)).json()
    assert f["score"] == -203 + 0  # AI suggestions never change the score; nothing determined yet

    # assessor determines every objective: all MET except 3.1.1 (NOT MET) and 3.13.11 partial
    pkg_ctrls = client.get("/v1/frameworks/cmmc-l2/controls", headers=H(owner)).json()
    for c in pkg_ctrls:
        for o in c["assessment_objectives"]:
            st = "MET"
            if o["id"] == "3.1.1[d]":
                st = "NOT_MET"
            if c["nist_id"] == "3.13.11":
                st = "NOT_MET"
            body = {"status": st, "rationale": "synthetic determination", "methods": ["examine"]}
            if o["id"] == "3.1.1[a]" and accepted:
                body["evidence_link_ids"] = [l["id"] for l in accepted if l["objective_id"] == "3.1.1[a]"]
            r = client.put(f"/v1/assessments/{aid}/objectives/{o['id']}", headers=H(assessor), json=body)
            assert r.status_code == 200, r.text
    assert client.put(f"/v1/assessments/{aid}/requirements/3.13.11", headers=H(assessor),
                      json={"partial_condition": "encryption_not_fips_validated",
                            "implementation_statement": "BitLocker enabled; module not FIPS-validated mode."}).status_code == 200

    score = client.get(f"/v1/assessments/{aid}/score?mode=OFFICIAL", headers=H(owner)).json()
    assert score["score"] == 110 - 5 - 3 and not score["errors"], score
    assert score["poam_evaluation"]["eligible"] is False  # 3.1.1 is 5 pts
    assert score["indicator"] == "CONDITIONAL_CRITERIA_NOT_MET"

    # POA&M
    poams = client.post(f"/v1/assessments/{aid}/poams/generate", headers=H(owner)).json()
    by_req = {p["requirement_id"]: p for p in poams}
    assert set(by_req) == {"3.1.1", "3.13.11"}
    assert by_req["3.1.1"]["cmmc_poam_permitted"] is False and by_req["3.13.11"]["cmmc_poam_permitted"] is True
    pid = by_req["3.13.11"]["id"]
    assert client.post(f"/v1/poams/{pid}/transition", headers=H(owner), json={"to_status": "OPEN"}).status_code == 422
    client.patch(f"/v1/poams/{pid}", headers=H(owner), json={
        "risk_owner": "CISO", "remediation_owner": "IT Lead", "corrective_action": "Enable FIPS mode",
        "scheduled_completion": "2027-03-01"}).raise_for_status()
    assert client.post(f"/v1/poams/{pid}/milestones", headers=H(owner),
                       json={"description": "Pilot FIPS policy", "due_date": "2027-01-15"}).status_code == 201
    for st in ("OPEN", "IN_PROGRESS"):
        assert client.post(f"/v1/poams/{pid}/transition", headers=H(owner), json={"to_status": st}).status_code == 200
    assert client.post(f"/v1/poams/{pid}/transition", headers=H(owner),
                       json={"to_status": "CLOSED"}).status_code == 409  # must verify first
    assert client.post(f"/v1/poams/{pid}/transition", headers=H(owner),
                       json={"to_status": "PENDING_VERIFICATION", "closure_evidence": [cfg["id"]]}).status_code == 200
    assert client.post(f"/v1/poams/{pid}/transition", headers=H(assessor),
                       json={"to_status": "CLOSED", "comment": "verified"}).status_code == 200

    # SSP & report
    ssp = client.get(f"/v1/assessments/{aid}/ssp", headers=H(owner)).text
    assert "BitLocker enabled" in ssp and "NOT PROVIDED" in ssp and "NW-CNC-PC1" in ssp
    rep = client.get(f"/v1/assessments/{aid}/report", headers=H(owner)).json()
    assert rep["label"].startswith("READINESS") and rep["manifest_signature"]
    assert {e["sha256"] for e in rep["manifest"]["evidence"]} == {pol["sha256"], cfg["sha256"], edr["sha256"], memo["sha256"]}
    r311 = next(q for q in rep["requirements"] if q["key"] == "3.1.1")
    assert r311["status"] == "NOT_MET" and r311["objectives"][0]["citations"]
    md = client.get(f"/v1/assessments/{aid}/report?format=md", headers=H(owner)).text
    assert "Score trace" in md and "-5 3.1.1 NOT_MET" in md
    docx_bytes = client.get(f"/v1/assessments/{aid}/report?format=docx", headers=H(owner)).content
    import docx
    assert any("Assessment Report" in p.text for p in docx.Document(io.BytesIO(docx_bytes)).paragraphs)

    # finalize, reproduce, reopen without losing history
    fin = client.post(f"/v1/assessments/{aid}/finalize", headers=H(assessor), json={"reason": "done"}).json()
    again = client.get(f"/v1/assessments/{aid}/score?mode=OFFICIAL", headers=H(owner)).json()
    assert fin["score"] == again["score"] == 102 and fin["input_hash"] == again["input_hash"]
    assert client.put(f"/v1/assessments/{aid}/objectives/3.1.1[d]", headers=H(assessor),
                      json={"status": "MET", "rationale": "x"}).status_code == 409
    rep2 = client.get(f"/v1/assessments/{aid}/report", headers=H(owner)).json()
    assert rep2["label"].startswith("FINALIZED")
    ro = client.post(f"/v1/assessments/{aid}/reopen", headers=H(assessor), json={"reason": "new evidence"}).json()
    assert ro["revision"] == 2 and ro["status"] == "DRAFT"
    after = client.get(f"/v1/assessments/{aid}/score?mode=OFFICIAL", headers=H(owner)).json()
    assert after["input_hash"] == fin["input_hash"]  # same approved inputs -> same score

    v = client.get("/v1/audit/verify", headers=H(owner)).json()
    assert v["valid"] and v["events"] > 300


def test_level1_assessment_disallows_poam(client, tenant):
    owner, _ = tenant("l1co")
    s = client.post("/v1/systems", headers=H(owner), json={"name": "FCI system", "data_types": ["FCI"]}).json()
    a = client.post("/v1/assessments", headers=H(owner), json={"system_id": s["id"], "framework_id": "cmmc-l1"}).json()
    sc = client.get(f"/v1/assessments/{a['id']}/score", headers=H(owner)).json()
    assert sc["framework"] == "cmmc-l1" and sc["all_met"] is False and sc["poam_allowed"] is False
    assert client.post(f"/v1/assessments/{a['id']}/poams/generate", headers=H(owner)).status_code == 409


def test_line_text_helper():
    assert line_text("3\tfoo\n4\tbar", 4) == "bar" and line_text("3\tfoo", 9) is None
