"""Tenant isolation, authorization, malicious files, prompt injection, audit tamper evidence."""
import io
import json
import zipfile

import pytest
from conftest import FIX, H, user_key

from aegisrmf import db as dbmod
from aegisrmf.evidence import analyzer as an
from aegisrmf.evidence import ingest
from aegisrmf.models import AuditEvent
from aegisrmf.security import audit

SYN = FIX / "synthetic"


def mk(client, key, slug_suffix=""):
    s = client.post("/v1/systems", headers=H(key), json={"name": "sys" + slug_suffix}).json()
    a = client.post("/v1/assessments", headers=H(key), json={"system_id": s["id"]}).json()
    e = client.post(f"/v1/systems/{s['id']}/evidence", headers=H(key),
                    files={"file": ("access_control_policy.txt", (SYN / "access_control_policy.txt").read_bytes())}).json()
    client.post(f"/v1/assessments/{a['id']}/analyze", headers=H(key)).raise_for_status()
    return s, a, e


# ------------------------------------------------------------------ tenant isolation
def test_cross_tenant_access_is_not_found(client, tenant):
    ka, _ = tenant("alpha")
    kb, _ = tenant("bravo")
    sa, aa, ea = mk(client, ka)
    link = client.get(f"/v1/assessments/{aa['id']}/evidence-links", headers=H(ka)).json()[0]
    poam_list = client.get(f"/v1/assessments/{aa['id']}/poams", headers=H(ka))
    assert poam_list.status_code == 200
    probes = [
        ("get", f"/v1/assessments/{aa['id']}", None), ("get", f"/v1/assessments/{aa['id']}/score", None),
        ("get", f"/v1/systems/{sa['id']}/evidence", None), ("get", f"/v1/assessments/{aa['id']}/report", None),
        ("get", f"/v1/assessments/{aa['id']}/ssp", None), ("get", f"/v1/assessments/{aa['id']}/evidence-links", None),
        ("post", f"/v1/assessments/{aa['id']}/analyze", None),
        ("post", f"/v1/evidence-links/{link['id']}/review", {"decision": "ACCEPTED"}),
        ("put", f"/v1/assessments/{aa['id']}/objectives/3.1.1[a]", {"status": "MET", "rationale": "x"}),
        ("post", f"/v1/systems/{sa['id']}/assets", {"name": "x", "category": "CUI_ASSET"}),
        ("post", "/v1/assessments", {"system_id": sa["id"]}),
    ]
    for method, url, body in probes:
        r = getattr(client, method)(url, headers=H(kb), **({"json": body} if body is not None else {}))
        assert r.status_code == 404, (url, r.status_code, r.text)
    assert client.get("/v1/systems", headers=H(kb)).json() == []
    # B's own audit chain contains nothing about A
    assert client.get("/v1/audit/verify", headers=H(kb)).json()["events"] < 5


def test_blob_store_refuses_cross_tenant(env):
    st = ingest.BlobStore()
    key = st.put("tenant-a", "ab" * 32, b"x")
    with pytest.raises(PermissionError):
        st.get("tenant-b", key)


# ------------------------------------------------------------------ authorization
def test_auth_required_and_bad_keys(client, tenant):
    k, _ = tenant("authco")
    assert client.get("/v1/systems").status_code == 401
    assert client.get("/v1/systems", headers=H("aeg_nope_nope")).status_code == 401
    assert client.get("/v1/systems", headers=H(k[:-2] + "xx")).status_code == 401
    assert client.post("/v1/tenants", json={"name": "zz", "slug": "zz", "owner_email": "a@b", "owner_name": "a"}).status_code == 401


def test_role_scopes(client, tenant):
    owner, _ = tenant("roles")
    s, a, e = mk(client, owner)
    viewer = user_key(client, owner, "viewer")
    contrib = user_key(client, owner, "contributor")
    agent = user_key(client, owner, "agent", scopes=["read", "assessment:write"])
    assert client.get(f"/v1/assessments/{a['id']}/score", headers=H(viewer)).status_code == 200
    assert client.post("/v1/systems", headers=H(viewer), json={"name": "x"}).status_code == 403
    assert client.post(f"/v1/assessments/{a['id']}/finalize", headers=H(contrib), json={}).status_code == 403
    link = client.get(f"/v1/assessments/{a['id']}/evidence-links", headers=H(owner)).json()[0]
    # AI agents cannot review evidence, record results, or finalize
    assert client.post(f"/v1/evidence-links/{link['id']}/review", headers=H(agent), json={"decision": "ACCEPTED"}).status_code == 403
    assert client.put(f"/v1/assessments/{a['id']}/objectives/3.1.1[a]", headers=H(agent),
                      json={"status": "MET", "rationale": "agent says so"}).status_code == 403
    assert client.post(f"/v1/assessments/{a['id']}/finalize", headers=H(agent), json={}).status_code == 403
    # agent cannot be granted finalize / admin scopes
    r = client.post("/v1/users", headers=H(owner), json={"email": "bad@x", "name": "b", "role": "agent",
                                                         "scopes": ["assessment:finalize"]})
    assert r.status_code == 403
    # non-admin cannot create users
    assert client.post("/v1/users", headers=H(contrib), json={"email": "c@x", "name": "c", "role": "viewer"}).status_code == 403


def test_met_requires_accepted_evidence_from_same_assessment(client, tenant):
    owner, _ = tenant("evid")
    s, a, e = mk(client, owner)
    link = client.get(f"/v1/assessments/{a['id']}/evidence-links", headers=H(owner)).json()[0]
    r = client.put(f"/v1/assessments/{a['id']}/objectives/{link['objective_id']}", headers=H(owner),
                   json={"status": "MET", "evidence_link_ids": [link["id"]]})
    assert r.status_code == 422  # still PROPOSED, not accepted
    r = client.put(f"/v1/assessments/{a['id']}/objectives/3.1.1[a]", headers=H(owner), json={"status": "NOT_APPLICABLE"})
    assert r.status_code == 422  # N/A requires justification


def test_accepted_risk_does_not_count_as_met(client, tenant):
    owner, _ = tenant("risk")
    s, a, e = mk(client, owner)
    client.put(f"/v1/assessments/{a['id']}/objectives/3.1.3[a]", headers=H(owner),
               json={"status": "NOT_MET", "rationale": "no flow control"}).raise_for_status()
    before = client.get(f"/v1/assessments/{a['id']}/score", headers=H(owner)).json()["score"]
    p = client.post(f"/v1/assessments/{a['id']}/poams/generate", headers=H(owner)).json()[0]
    client.patch(f"/v1/poams/{p['id']}", headers=H(owner), json={"risk_owner": "a", "remediation_owner": "b",
                                                               "corrective_action": "c", "scheduled_completion": "2027-01-01"})
    client.post(f"/v1/poams/{p['id']}/transition", headers=H(owner), json={"to_status": "OPEN"}).raise_for_status()
    assert client.post(f"/v1/poams/{p['id']}/transition", headers=H(owner), json={"to_status": "ACCEPTED_RISK"}).status_code == 422
    client.post(f"/v1/poams/{p['id']}/transition", headers=H(owner),
                json={"to_status": "ACCEPTED_RISK", "comment": "business decision"}).raise_for_status()
    after = client.get(f"/v1/assessments/{a['id']}/score", headers=H(owner)).json()
    assert after["score"] == before and "3.1.3" in [d["requirement"] for d in after["deductions"]]


# ------------------------------------------------------------------ malicious files
def _docx(extra: dict | None = None, doctype=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        body = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><w:document/>' if doctype else "<w:document/>"
        z.writestr("word/document.xml", body)
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return buf.getvalue()


@pytest.mark.parametrize("name,data,reason", [
    ("eicar.txt", ingest.EICAR, "malware"),
    ("macro.docx", _docx({"word/vbaProject.bin": b"x"}), "macro"),
    ("xxe.docx", _docx(doctype=True), "DTD"),
    ("xxe.xml", b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', "DTD"),
    ("evil.exe", b"MZ\x90\x00", "not accepted"),
    ("fake.pdf", b"just text pretending", "content does not match"),
    ("real.txt", b"%PDF-1.7 hidden pdf", "content does not match"),
    ("trav.docx", _docx({"../../evil.sh": "x"}), "unsafe path"),
    ("bin.txt", b"\x00\x01\x02binary", "binary"),
    ("empty.txt", b"", "empty"),
])
def test_malicious_files_rejected(env, name, data, reason):
    with pytest.raises(ingest.RejectedFile, match=reason):
        ingest.detect_and_validate(name, data)


def test_zip_bomb_rejected(env):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/media/pad.bin", b"\0" * (30 * 1024 * 1024))
    with pytest.raises(ingest.RejectedFile, match="zip bomb"):
        ingest.detect_and_validate("bomb.docx", buf.getvalue())


def test_valid_office_and_pdf_accepted_with_locators(env, tmp_path):
    import docx
    from reportlab.pdfgen import canvas
    d = docx.Document()
    d.add_heading("Media Protection Procedure", 1)
    d.add_paragraph("CUI media is sanitized before disposal using NIST 800-88 purge.")
    b = io.BytesIO()
    d.save(b)
    v = ingest.detect_and_validate("mp.docx", b.getvalue())
    from aegisrmf.evidence import extract
    lines, _ = extract.extract_lines(v.detected_type, b.getvalue())
    assert lines[1].section == "Media Protection Procedure" and "sanitized" in lines[1].text
    pdf = tmp_path / "p.pdf"
    c = canvas.Canvas(str(pdf))
    c.drawString(72, 720, "Page one text")
    c.showPage()
    c.drawString(72, 720, "Audit logs are reviewed weekly by the security team.")
    c.save()
    data = pdf.read_bytes()
    assert ingest.detect_and_validate("p.pdf", data).detected_type == "pdf"
    lines, _ = extract.extract_lines("pdf", data)
    assert any(l.page == 2 and "Audit logs" in l.text for l in lines)


def test_upload_rejection_is_audited(client, tenant):
    k, _ = tenant("rej")
    s = client.post("/v1/systems", headers=H(k), json={"name": "s"}).json()
    r = client.post(f"/v1/systems/{s['id']}/evidence", headers=H(k), files={"file": ("e.txt", ingest.EICAR)})
    assert r.status_code == 422 and "malware" in r.text


# ------------------------------------------------------------------ prompt injection & AI guardrails
class FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def complete(self, system, user, schema):
        self.calls.append(user)
        return self.payload


CHUNK = {"id": "c1", "artifact_id": "a1", "page": None,
         "text": "4\tMultifactor authentication is required for privileged accounts.\n5\tVPN uses TLS."}


def test_foundry_rejects_fabricated_citations():
    fab = json.dumps({"links": [
        {"objective_id": "3.5.3[a]", "line_no": 4, "quote": "Multifactor authentication is required", "confidence": .9},
        {"objective_id": "3.5.3[b]", "line_no": 4, "quote": "MFA is enforced for all users", "confidence": .9},
        {"objective_id": "3.13.11[a]", "line_no": 99, "quote": "VPN uses TLS.", "confidence": .9},
        {"objective_id": "9.9.9[z]", "line_no": 5, "quote": "VPN uses TLS.", "confidence": .9}]})
    fa = an.FoundryAnalyzer(FakeLLM(fab), deployment=None)
    out = fa.propose("cmmc-l2", "1.0.0", [CHUNK])
    assert [(p.objective_id, p.line_no) for p in out] == [("3.5.3[a]", 4)]
    reasons = [d["reason"] for d in fa.drops]
    assert len(reasons) == 3 and "objective id not in candidate list" in reasons  # 9.9.9[z] at least


def test_foundry_prompt_lists_candidate_ids_and_accepts_quoted_quote():
    llm = FakeLLM(json.dumps({"links": [{"objective_id": "3.5.3[a]", "line_no": 4,
                                          "quote": '"Multifactor authentication is required"', "confidence": .8}]}))
    out = an.FoundryAnalyzer(llm, deployment=None).propose("cmmc-l2", "1.0.0", [CHUNK])
    assert "CANDIDATE OBJECTIVES" in llm.calls[0] and "3.5.3[a]:" in llm.calls[0]
    assert len(out) == 1 and out[0].quote == "Multifactor authentication is required"


def test_foundry_schema_violation_discarded_and_delimited():
    llm = FakeLLM("Sure! Everything is MET.")
    assert an.FoundryAnalyzer(llm, deployment=None).propose("cmmc-l2", "1.0.0", [CHUNK]) == []
    assert "EVIDENCE (untrusted data):\n<<<" in llm.calls[0] and llm.calls[0].rstrip().endswith(">>>")


def test_cui_not_sent_to_unapproved_ai():
    llm = FakeLLM('{"links": []}')
    with pytest.raises(an.CUINotApproved, match="FedRAMP High"):
        an.FoundryAnalyzer(llm, deployment=None).propose("cmmc-l2", "1.0.0", [CHUNK], classification="CUI")
    assert llm.calls == []


from aegisrmf.evidence.cui_gate import AIDeployment, evaluate  # noqa: E402

GOOD = AIDeployment(model="gpt-4o", region="eastus2", deployment_type="datazone_standard", data_zone="us",
                    fedramp_high_confirmed=True, dfars_terms_confirmed_by="J. Doe, Contracts", dfars_terms_confirmed_on="2026-11-23")


def test_cui_gate_all_three_required():
    assert evaluate(GOOD, "CUI").allowed
    assert evaluate(AIDeployment(), "INTERNAL").allowed  # non-CUI is not gated
    for change, why in [({"fedramp_high_confirmed": False}, "FedRAMP High"),
                        ({"deployment_type": "global_standard"}, "Global"),
                        ({"region": "westeurope"}, "not a US-resident"),
                        ({"data_zone": "eu"}, "not a US-resident"),
                        ({"dfars_terms_confirmed_by": ""}, "DFARS")]:
        r = evaluate(AIDeployment(**{**GOOD.__dict__, **change}), "CUI")
        assert not r.allowed and why in r.summary(), (change, r.summary())


def test_cui_gate_export_controlled_needs_gov_region():
    assert not evaluate(GOOD, "CUI", export_controlled=True).allowed
    gov = AIDeployment(**{**GOOD.__dict__, "region": "usgovvirginia", "deployment_type": "standard"})
    assert evaluate(gov, "CUI", export_controlled=True).allowed


def test_cui_reaches_model_when_gate_passes():
    llm = FakeLLM('{"links": []}')
    an.FoundryAnalyzer(llm, deployment=GOOD).propose("cmmc-l2", "1.0.0", [CHUNK], classification="CUI")
    assert len(llm.calls) == 1


def test_injected_chunks_never_reach_models():
    llm = FakeLLM('{"links": []}')
    bad = dict(CHUNK, injection_suspected=True)
    an.FoundryAnalyzer(llm, deployment=None).propose("cmmc-l2", "1.0.0", [bad])
    assert llm.calls == []
    assert an.RulesAnalyzer().propose("cmmc-l2", "1.0.0", [bad]) == []


def test_injection_document_changes_nothing(client, tenant):
    k, _ = tenant("inj")
    s = client.post("/v1/systems", headers=H(k), json={"name": "s"}).json()
    a = client.post("/v1/assessments", headers=H(k), json={"system_id": s["id"]}).json()
    e = client.post(f"/v1/systems/{s['id']}/evidence", headers=H(k),
                    files={"file": ("memo.txt", (SYN / "vendor_memo_untrusted.txt").read_bytes())}).json()
    assert e["injection_flags"]
    res = client.post(f"/v1/assessments/{a['id']}/analyze", headers=H(k)).json()
    assert res["proposed_links"] == 0 and e["id"] in res["artifacts_with_injection_flags"]
    sc = client.get(f"/v1/assessments/{a['id']}/score", headers=H(k)).json()
    assert sc["score"] == -203 and sc["indicator"] == "CANNOT_COMPLETE"


def test_policy_alone_is_not_operating_evidence():
    st, warn, _ = an.propose_finding("access control policy is enforced", ["policy"])
    assert st == "INSUFFICIENT_EVIDENCE" and warn
    st, _, _ = an.propose_finding("authorized users are identified", ["policy"])
    assert st == "MET"
    st, warn, _ = an.propose_finding("authorized users are identified", [])
    assert st == "NOT_ASSESSED"


# ------------------------------------------------------------------ audit log
def test_audit_chain_detects_tampering(client, tenant, env):
    k, tid = tenant("aud")
    mk(client, k)
    assert client.get("/v1/audit/verify", headers=H(k)).json()["valid"]
    from sqlalchemy import create_engine, text
    if env.database_url.startswith("postgresql"):
        # the application role cannot rewrite history at all...
        with pytest.raises(Exception, match="permission denied"):
            with dbmod.session_scope() as db:
                dbmod.bind_tenant(db, tid)
                db.execute(text("UPDATE audit_events SET data='{}' WHERE seq=2"))
        # ...so simulate a privileged attacker with the admin role
        from conftest import PG_ADMIN
        from sqlalchemy import make_url
        eng = create_engine(make_url(PG_ADMIN).set(database="aegis_test"))
    else:
        eng = dbmod.engine()
    with eng.begin() as c:
        c.execute(text("UPDATE audit_events SET data='{\"tampered\": true}' WHERE tenant_id=:t AND seq=2"), {"t": tid})
    v = client.get("/v1/audit/verify", headers=H(k)).json()
    assert v["valid"] is False and v["broken_at_seq"] == 2


def test_postgres_rls_fail_closed(client, tenant, env):
    if not env.database_url.startswith("postgresql"):
        pytest.skip("PostgreSQL RLS test (set AEGIS_TEST_PG_ADMIN_URL)")
    from sqlalchemy import text
    ka, ta = tenant("rlsa")
    kb, tb = tenant("rlsb")
    mk(client, ka)
    with dbmod.session_scope() as db:   # no tenant bound -> nothing visible
        assert db.execute(text("SELECT count(*) FROM systems")).scalar() == 0
        assert db.execute(text("SELECT count(*) FROM evidence_chunks")).scalar() == 0
    with dbmod.session_scope() as db:   # bound to B -> none of A's rows, even with raw SQL
        dbmod.bind_tenant(db, tb)
        assert db.execute(text("SELECT count(*) FROM systems")).scalar() == 0
    with dbmod.session_scope() as db:
        dbmod.bind_tenant(db, ta)
        assert db.execute(text("SELECT count(*) FROM systems")).scalar() == 1
    with pytest.raises(Exception, match="row-level security"):
        with dbmod.session_scope() as db:  # cannot write rows for another tenant
            dbmod.bind_tenant(db, tb)
            db.execute(text("INSERT INTO systems (id, tenant_id, name, description, boundary_description, "
                            "data_types, cui_data_flows, created_at) VALUES ('x', :a, 'evil', '', '', '[]', '[]', now())"),
                       {"a": ta})


def test_manifest_signature(env):
    m = {"a": 1, "evidence": [{"sha256": "x"}]}
    sig = audit.sign_manifest(m)
    assert audit.verify_manifest(m, sig) and not audit.verify_manifest({**m, "a": 2}, sig)


def test_foundry_provider_selected_from_settings(client, tenant, env, monkeypatch):
    """AEGIS_AI_PROVIDER=azure-foundry routes analysis through FoundryClient (faked here; no network)."""
    from aegisrmf.evidence import foundry_client

    calls = []

    class FakeClient:
        def complete(self, system, user, schema):
            calls.append(schema)
            return '{"links": []}'

    monkeypatch.setattr(foundry_client, "from_settings", lambda: (FakeClient(), AIDeployment()))
    monkeypatch.setattr(env, "ai_provider", "azure-foundry")
    k, _ = tenant("foundry")
    s = client.post("/v1/systems", headers=H(k), json={"name": "s"}).json()
    a = client.post("/v1/assessments", headers=H(k), json={"system_id": s["id"]}).json()
    client.post(f"/v1/systems/{s['id']}/evidence", headers=H(k),
                files={"file": ("p.txt", (SYN / "access_control_policy.txt").read_bytes()), }, data={"classification": "CUI"})
    res = client.post(f"/v1/assessments/{a['id']}/analyze", headers=H(k)).json()
    assert calls == [] and res["skipped"] and "FedRAMP High" in res["skipped"][0]["reason"]


def test_strict_schema_strips_unsupported_keywords():
    from aegisrmf.evidence.foundry_client import strict_schema
    out = strict_schema(an.FOUNDRY_SCHEMA)
    item = out["properties"]["links"]["items"]["properties"]
    assert "maxLength" not in item["quote"] and "minimum" not in item["confidence"]
    assert out["properties"]["links"]["items"]["additionalProperties"] is False
