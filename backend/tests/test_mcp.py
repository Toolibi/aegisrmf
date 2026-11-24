"""MCP schema, permission, confirmation, tenant-isolation and transport-auth tests."""
import base64
import json

import anyio
import pytest
from conftest import FIX, H, user_key

from aegisrmf import mcp_server as M

EXPECTED = {"list_frameworks", "get_framework_controls", "list_systems", "create_assessment",
            "get_assessment_status", "list_assessment_objectives", "upload_evidence_reference",
            "analyze_evidence", "map_evidence_to_controls", "get_control_findings", "calculate_cmmc_score",
            "generate_gap_analysis", "create_poam", "update_poam", "list_overdue_remediations",
            "get_risk_register", "generate_ssp_draft", "generate_sar_draft", "generate_executive_report"}
WRITES = {"create_assessment", "upload_evidence_reference", "analyze_evidence", "create_poam", "update_poam",
          "generate_ssp_draft", "generate_sar_draft"}


def call(key, name, **args):
    tok = M._test_token.set(key)
    try:
        return anyio.run(lambda: M.mcp.call_tool(name, args))
    except Exception as e:  # SDK raises ToolError; surface its message
        raise RuntimeError(str(e)) from e
    finally:
        M._test_token.reset(tok)


def payload(res):
    if getattr(res, "is_error", False):
        raise RuntimeError(res.content[0].text)
    if res.structured_content is not None:
        sc = res.structured_content
        return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc
    return json.loads(res.content[0].text)


def test_tool_catalog_and_annotations():
    tools = {t.name: t for t in anyio.run(M.mcp.list_tools)}
    assert EXPECTED <= set(tools)
    for name, t in tools.items():
        assert t.description and t.input_schema["type"] == "object"
        if name in WRITES:
            assert t.annotations.read_only_hint is False and "confirm" in t.input_schema["properties"]
        else:
            assert t.annotations.read_only_hint is True and "confirm" not in t.input_schema["properties"]


def test_mcp_flow_permissions_and_isolation(client, tenant):
    owner, _ = tenant("mcpco")
    other, _ = tenant("rival")
    s = client.post("/v1/systems", headers=H(owner), json={"name": "enclave"}).json()
    viewer = user_key(client, owner, "viewer")
    agent = user_key(client, owner, "agent", scopes=["read", "assessment:write", "evidence:write", "poam:write"])

    with pytest.raises(RuntimeError, match="invalid credentials|missing credentials"):
        payload(call("aeg_bad_bad", "list_frameworks"))
    assert len(payload(call(viewer, "list_frameworks"))) == 2

    # writes need confirm=true and a write scope
    with pytest.raises(RuntimeError, match="confirm=true"):
        payload(call(agent, "create_assessment", system_id=s["id"]))
    with pytest.raises(RuntimeError, match="missing scope"):
        payload(call(viewer, "create_assessment", system_id=s["id"], confirm=True))
    aid = payload(call(agent, "create_assessment", system_id=s["id"], confirm=True))["assessment_id"]

    content = base64.b64encode((FIX / "synthetic" / "entra_conditional_access_export.json").read_bytes()).decode()
    up = payload(call(agent, "upload_evidence_reference", system_id=s["id"], filename="ca.json",
                      content_base64=content, confirm=True))
    assert len(up["sha256"]) == 64
    assert payload(call(agent, "analyze_evidence", assessment_id=aid, confirm=True))["proposed_links"] > 0
    links = payload(call(viewer, "map_evidence_to_controls", assessment_id=aid, objective_id="3.5.3[a]"))
    assert links["notice"].startswith("Evidence-derived text") and links["links"][0]["citation"]["line"]

    score = payload(call(viewer, "calculate_cmmc_score", assessment_id=aid))
    assert score["score"] == -203 and "certification" in score["disclaimer"]
    gaps = payload(call(viewer, "generate_gap_analysis", assessment_id=aid))
    assert gaps["count"] == 110 and gaps["gaps"][0]["points"] == 5
    assert payload(call(agent, "create_poam", assessment_id=aid, confirm=True))["created"] == []  # nothing NOT_MET yet
    assert "NOT PROVIDED" in payload(call(owner, "generate_ssp_draft", assessment_id=aid, confirm=True))["markdown"]
    ex = payload(call(viewer, "generate_executive_report", assessment_id=aid))
    assert ex["indicator"] == "CANNOT_COMPLETE"

    # other tenant: same tool, real id -> not found
    with pytest.raises(RuntimeError, match="not found"):
        payload(call(other, "get_assessment_status", assessment_id=aid))
    with pytest.raises(RuntimeError, match="not found"):
        payload(call(other, "map_evidence_to_controls", assessment_id=aid))
    assert payload(call(other, "list_systems")) == []

    # input validation
    with pytest.raises(RuntimeError, match="UUID"):
        payload(call(viewer, "get_assessment_status", assessment_id="../../etc"))


def test_rate_limit(client, tenant, monkeypatch):
    k, _ = tenant("ratelim")
    monkeypatch.setattr(M, "RATE_LIMIT", 3)
    M._calls.clear()
    for _ in range(3):
        payload(call(k, "list_frameworks"))
    with pytest.raises(RuntimeError, match="rate limit"):
        payload(call(k, "list_frameworks"))
    M._calls.clear()


def test_streamable_http_requires_bearer(client, tenant):
    from starlette.testclient import TestClient
    k, _ = tenant("httpco")
    app = M.http_app()
    with TestClient(app, base_url="http://127.0.0.1:8001") as c:
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "t", "version": "1"}}}
        hdr = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        assert c.post("/mcp", json=init, headers=hdr).status_code == 401
        assert c.post("/mcp", json=init, headers={**hdr, "Authorization": "Bearer aeg_x_y"}).status_code == 401
        r = c.post("/mcp", json=init, headers={**hdr, **H(k)})
        assert r.status_code == 200, r.text
        sess = {**hdr, **H(k), "mcp-session-id": r.headers.get("mcp-session-id", ""),
                "mcp-protocol-version": "2025-06-18"}
        c.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=sess)
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                 "params": {"name": "list_frameworks", "arguments": {}}}, headers=sess)
        assert r.status_code == 200 and "cmmc-l2" in r.text, r.text[:500]
