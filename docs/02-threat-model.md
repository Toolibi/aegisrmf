# Threat model (STRIDE) — Stage 1

**Assets:** customer CUI/FCI evidence, assessment results and scores, POA&Ms, SSPs, API keys,
audit log, signing keys, AI prompts and outputs.
**Trust boundaries:** (1) Internet → API/MCP ingress, (2) app → PostgreSQL / Blob, (3) app → AI model
endpoint, (4) app → customer cloud connectors, (5) tenant ↔ tenant inside the shared SaaS.

| # | Threat | STRIDE | Control in this release | Test |
|---|---|---|---|---|
| T1 | Tenant B reads/changes tenant A data by guessing IDs | I, T | Tenant taken from credential only; `get_scoped()` returns 404 for foreign rows; PostgreSQL RLS fail-closed on every customer table | `test_cross_tenant_access_is_not_found`, `test_postgres_rls_fail_closed`, MCP isolation test |
| T2 | Stolen / forged API key | S | HMAC-peppered key hashes, constant-time compare, revocation, expiry, uniform 401 | `test_auth_required_and_bad_keys` |
| T3 | AI agent escalates (records MET, finalizes, closes POA&M) | E | `agent` role cannot hold `findings:review`/`assessment:finalize`; service-level role checks; AI only writes PROPOSED rows | `test_role_scopes` |
| T4 | Prompt injection in uploaded evidence | T, E | Regex screen flags chunks; flagged chunks never reach any analyzer; LLM context delimited as untrusted data; strict JSON schema; AI cannot write results | `test_injection_document_changes_nothing`, `test_injected_chunks_never_reach_models` |
| T5 | Fabricated citations / hallucinated evidence | T | Every proposal must quote verbatim text at the cited line in stored extraction or it is dropped | `test_foundry_rejects_fabricated_citations`, citation checks in vertical slice |
| T6 | CUI sent to an unapproved model | I | Default analyzer is local; Foundry analyzer passes CUI only when FedRAMP High scope, US data residency (no Global deployments) and DFARS 7012 terms are all recorded; export-controlled data needs Azure Government | `test_cui_gate_*`, `test_cui_not_sent_to_unapproved_ai` |
| T7 | Malicious upload (malware, macros, XXE, zip bomb, type confusion, path traversal) | T, D, E | Content-sniffed allowlist, EICAR scan hook, macro/DTD rejection, archive limits, filename checks | `test_malicious_files_rejected`, `test_zip_bomb_rejected` |
| T8 | Audit history rewritten | R, T | Per-tenant SHA-256 hash chain; app role has no UPDATE/DELETE on `audit_events` in PostgreSQL | `test_audit_chain_detects_tampering` |
| T9 | Score manipulated or not reproducible | T, R | Pure scoring engine, versioned rules, input hash, snapshot at finalize, finalized assessments immutable until reopened (new revision) | `test_reproducible_regardless_of_order`, finalize/reopen in vertical slice |
| T10 | Readiness score mistaken for certification | R | Every score carries indicator + disclaimer; reports labelled READINESS vs FINALIZED INTERNAL RECORD | `test_rules_require_human_review_flag` |
| T11 | MCP tool abuse / bulk exfiltration | I, D | Read-only default, write/export need scope **and** `confirm=true`, per-key rate limit, result size caps, every call audited | `test_mcp_flow_permissions_and_isolation`, `test_rate_limit` |
| T12 | Unauthenticated MCP over HTTP | S | SDK bearer middleware + `ApiKeyVerifier`, resource-bound tokens (RFC 8707/9728) | `test_streamable_http_requires_bearer` |
| T13 | SSRF via connectors | I | *Not yet built* (Stage 5): egress allowlist, no user-supplied URLs, workload identity | — |
| T14 | Secrets in repo / supply chain | I, T | Env-only secrets, prod config validation, CI: pip-audit, gitleaks, SBOM (CycloneDX) | CI workflow |

## Residual risks (open)
- Rules analyzer is lexical; it over-proposes. Mitigated by mandatory human review, not eliminated.
- Injection screening is pattern-based and bypassable; it is a signal, not the control.
- Built-in malware scanner only detects EICAR. Production must enable Defender for Storage or ClamAV.
- Manifest signing is HMAC (shared key). Production: Key Vault asymmetric signing.
- Entra ID OIDC sign-in for the web UI is designed (ADR-0004) but not implemented.
