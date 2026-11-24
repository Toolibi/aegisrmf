# Architecture

```mermaid
flowchart LR
  subgraph Clients
    UI[Next.js dashboard<br/>(Stage 3+)]
    AIA[Azure AI Foundry agent /<br/>desktop MCP client]
    INT[Customer systems<br/>REST + webhooks]
  end
  subgraph AegisRMF["AegisRMF (Azure Container Apps, private VNet)"]
    API[FastAPI REST<br/>/v1 + OpenAPI]
    MCP[MCP server<br/>streamable HTTP, bearer auth]
    SVC[Service layer<br/>authz · tenant scope · audit]
    SCORE[Deterministic scoring<br/>32 CFR 170.24/170.21]
    EVI[Evidence pipeline<br/>validate · scan · extract · chunk · screen]
    AGT[Analyzers<br/>rules (default) · Foundry (opt-in)]
    RPT[Reports · SSP · signed manifest]
    CAT[(Versioned framework<br/>packages JSON)]
  end
  PG[(PostgreSQL<br/>RLS per tenant)]
  BLOB[(Blob Storage<br/>immutable, CMK)]
  KV[Key Vault]
  AOAI[Azure OpenAI / Foundry<br/>approved deployment]
  UI --> API
  INT --> API
  AIA --> MCP
  API --> SVC
  MCP --> SVC
  SVC --> SCORE & EVI & AGT & RPT
  SVC --> PG
  EVI --> BLOB
  SCORE --> CAT
  AGT -. only if approved .-> AOAI
  SVC -. secrets .-> KV
```

**Key rule:** REST and MCP are both thin adapters. Every authorization decision, tenant scope and
audit record happens once, in `services/core.py`.

## Human-in-the-loop data flow
1. Evidence uploaded → validated, hashed, stored, text extracted with page/line locators, screened.
2. Analyzer proposes `EvidenceLink`s (status PROPOSED, origin AI) with verbatim citations.
3. Human reviewer ACCEPTS / REJECTS each link.
4. Assessment Agent proposes per-objective findings from **accepted** links only (UNREVIEWED).
5. Assessor records `ObjectiveResult`s (the only input to scoring). AI cannot write this table.
6. Scoring engine computes from objective results → requirement status → score + trace + hash.
7. Finalize snapshots the official score and locks the assessment; reopen creates revision N+1.

## Repository layout
```
backend/aegisrmf/
  catalog/      versioned framework packages (CMMC L2 Rev.2 = 110 req / 320 obj; CMMC L1 = 15)
  scoring/      pure scoring engine + rules JSON transcribed from 32 CFR 170.24 / 170.21
  evidence/     ingest (validation), extract (locators), injection screen, analyzers
  security/     API keys, roles/scopes, hash-chained audit, manifest signing
  services/     core workflows, reports/SSP
  api/          FastAPI app
  mcp_server.py MCP tools (stdio + streamable HTTP)
backend/alembic/ migrations incl. PostgreSQL RLS
backend/tests/   61 tests incl. regulatory fixtures and synthetic evidence
infra/           Dockerfile, compose, Bicep (draft)
docs/            research, threat model, architecture, data model, backlog, ADRs
```
