# Data model

All customer tables carry `tenant_id` (FK, indexed) and are covered by PostgreSQL row-level
security (migration `0002`). Framework catalogs are immutable versioned files, not tables, so a
catalog revision can never silently change a past assessment.

```mermaid
erDiagram
  TENANT ||--o{ USER : has
  USER ||--o{ API_KEY : holds
  TENANT ||--o{ SYSTEM : owns
  SYSTEM ||--o{ ASSET : "scoped assets (CUI/SPA/CRMA/Specialized/OOS, ESP flag)"
  SYSTEM ||--o{ EVIDENCE_ARTIFACT : "evidence (sha256, version, classification)"
  EVIDENCE_ARTIFACT ||--o{ EVIDENCE_CHUNK : "page/line locators"
  SYSTEM ||--o{ ASSESSMENT : "framework@package, kind, status, revision"
  ASSESSMENT ||--o{ OBJECTIVE_RESULT : "human determinations (score input)"
  ASSESSMENT ||--o{ REQUIREMENT_CONDITION : "partial credit, N/A, implementation stmt"
  ASSESSMENT ||--o{ EVIDENCE_LINK : "objective <- chunk citation (PROPOSED/ACCEPTED)"
  EVIDENCE_CHUNK ||--o{ EVIDENCE_LINK : cited_by
  ASSESSMENT ||--o{ FINDING : "AI suggestions + QA warnings"
  ASSESSMENT ||--o{ POAM : remediation
  POAM ||--o{ MILESTONE : has
  POAM ||--o{ POAM_HISTORY : "status trail"
  ASSESSMENT ||--o{ SCORE_SNAPSHOT : "input_hash + result"
  TENANT ||--o{ APPROVAL : "finalize/reopen decisions"
  TENANT ||--o{ AUDIT_EVENT : "hash chain (seq, prev_hash, hash)"
```

## Constraints worth knowing
- `objective_results (assessment_id, objective_id)` unique — one current determination per objective;
  the audit log keeps every change.
- `audit_events (tenant_id, seq)` unique; the app role has no UPDATE/DELETE on it in PostgreSQL.
- `api_keys.prefix` unique; only an HMAC of the secret is stored.
- Retention: `tenants.retention_days` (default 2,555 ≈ 7 years). Enforcement job is backlog item B-14.

## Entities from the master prompt not yet implemented
Role (roles are an enum today), InformationType, DataFlow (stored as JSON on System), Risk (derived
from POA&Ms), SSP/AssessmentPlan/AssessmentReport (generated, not persisted), AuthorizationDecision,
Connector, IntegrationRun, Notification. See backlog.
