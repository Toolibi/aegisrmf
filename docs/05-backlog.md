# Prioritized engineering backlog

Status: ✅ done and tested in this repo · 🟡 partial · ⬜ not started

## Stage 1–3 (this release)
| ID | Item | Status |
|---|---|---|
| B-01 | Research matrix, threat model, architecture, data model, ADRs | ✅ |
| B-02 | Tenant registration, users, scoped API keys, roles | ✅ |
| B-03 | Tenant isolation: service scoping + PostgreSQL RLS (fail closed) | ✅ (tested on PG 16) |
| B-04 | CMMC L2 (Rev. 2, 110/320) and L1 (15) versioned packages | ✅ |
| B-05 | Deterministic L2 scoring, special cases, SSP blocker, POA&M eligibility, L1 rule | ✅ |
| B-06 | Regulatory fixtures — **needs human sign-off** (`review.status`) | 🟡 |
| B-07 | Evidence intake: validation, malware hook, extraction with locators, versioning | ✅ |
| B-08 | Evidence analysis (rules) + verbatim-citation validator + human review | ✅ |
| B-09 | POA&M lifecycle, milestones, history, CMMC eligibility flags, accepted-risk ≠ MET | ✅ |
| B-10 | SSP draft + traceable report (JSON/MD/DOCX) + signed evidence manifest | ✅ |
| B-11 | Finalize / reopen with revision history and reproducible score | ✅ |
| B-12 | MCP server: 19 tools, read-only default, confirm gate, rate limit, HTTP bearer | ✅ |
| B-13 | Hash-chained audit log | ✅ |

## Next (ordered)
| ID | Item | Why next |
|---|---|---|
| B-14 | Next.js dashboard: control explorer, evidence review queue, score, POA&M board | ✅ done 2026-11-24 (write actions beyond evidence review still API/MCP only) |
| B-15 | Entra ID OIDC for UI + Entra-issued tokens for MCP (ADR-0004/0005) | Enterprise sign-in |
| B-16 | Foundry analyzer wired to a real Azure OpenAI deployment + eval set | Better recall than rules |
| B-17 | Azure deployment (Bicep): Container Apps, PG Flexible, Blob immutability, Key Vault, private endpoints | Hosting |
| B-18 | Defender for Storage / ClamAV scanning; OCR (Azure Document Intelligence) for images/scans | Evidence coverage |
| B-19 | Connectors: Entra ID, Intune, Defender, Sentinel (Graph, workload identity); Prowler + SAF/HDF ingest | Technical evidence |
| B-20 | OSCAL export/import via compliance-trestle (SSP, assessment-results, POA&M) | Interop |
| B-21 | Evidence freshness/expiry, drift detection, reminders, Jira/ServiceNow | Continuous monitoring |
| B-22 | RMF module (FIPS 199, baselines, tailoring, SAR, AO decision record — never issues an ATO) | Phase 1 scope |
| B-23 | NIST 800-53 Rev. 5 package and mappings (non-equivalence flagged) | Phase 1 scope |
| B-24 | Retention enforcement, secure deletion, backup/restore drills | Ops |
| B-25 | Load tests, E2E UI tests, SBOM signing, release process | Hardening |
| B-26 | Phase 2 frameworks (CMMC L3, CSF 2.0, FedRAMP, ISO 27001, SOC 2, HIPAA, PCI DSS, AI RMF) | Expansion |
