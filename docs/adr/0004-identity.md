# ADR-0004: Identity — API keys now, Entra ID next
**Decision.** Tenant-scoped API keys (HMAC-peppered hashes) for this release. Web UI will use Microsoft Entra
ID OIDC (multi-tenant app, tenant mapping by `tid`), mapping Entra app roles to AegisRMF roles. Customer
passwords are never stored; connectors use workload identity federation / delegated consent.
