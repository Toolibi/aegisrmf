"""Endpoints the dashboard uses: identity, assessment list, requirement matrix, findings, CORS."""
from conftest import FIX, H


def test_dashboard_endpoints_and_isolation(client, tenant):
    k, _ = tenant("dash")
    other, _ = tenant("dash2")
    me = client.get("/v1/me", headers=H(k)).json()
    assert me["role"] == "owner" and "read" in me["scopes"]
    s = client.post("/v1/systems", headers=H(k), json={"name": "enclave"}).json()
    a = client.post("/v1/assessments", headers=H(k), json={"system_id": s["id"]}).json()
    client.post(f"/v1/systems/{s['id']}/evidence", headers=H(k),
                files={"file": ("p.txt", (FIX / "synthetic" / "access_control_policy.txt").read_bytes())})
    client.post(f"/v1/assessments/{a['id']}/analyze", headers=H(k))
    client.post(f"/v1/assessments/{a['id']}/findings/propose", headers=H(k))
    lst = client.get("/v1/assessments", headers=H(k)).json()
    assert len(lst) == 1 and lst[0]["system_name"] == "enclave"
    m = client.get(f"/v1/assessments/{a['id']}/requirements", headers=H(k)).json()
    assert len(m) == 110 and {r["family"] for r in m} >= {"AC", "SI"}
    r311 = next(r for r in m if r["key"] == "3.1.1")
    assert r311["points"] == 5 and r311["links_proposed"] >= 1 and r311["ai_suggestions"]
    assert next(r for r in m if r["key"] == "3.12.4")["points"] is None
    f = client.get(f"/v1/assessments/{a['id']}/findings?requirement_id=3.1.1", headers=H(k)).json()
    assert f and all(x["origin"] == "AI" for x in f)
    assert client.get("/v1/assessments", headers=H(other)).json() == []
    for url in (f"/v1/assessments/{a['id']}/requirements", f"/v1/assessments/{a['id']}/findings"):
        assert client.get(url, headers=H(other)).status_code == 404
