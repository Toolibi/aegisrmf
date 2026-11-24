# ADR-0003: Local rules analyzer by default; LLMs opt-in, CUI-gated, citation-validated
**Decision.** Default analyzer is local and deterministic. The Foundry analyzer runs only when configured, receives
evidence as delimited untrusted data, must return schema-valid JSON, and every citation must match stored text
verbatim or it is dropped.

**CUI gate (revised 2026-11-23).** Commercial Azure OpenAI is in Microsoft's FedRAMP High scope and Microsoft
states Azure commercial supports DFARS 252.204-7012, so CUI is not banned outright. CUI reaches a model only when
all three are recorded: (1) the model/feature is confirmed on the FedRAMP High audit-scope list, (2) a US region
with a regional or US Data Zone deployment type (Global types refused), (3) the customer's contracting owner
confirmed DFARS 7012 terms (who + when). Export-controlled data additionally requires an Azure Government region.

**Not covered by this gate.** Azure's authorization is inherited, not transferred. If customers store CUI in the
AegisRMF SaaS, AegisRMF itself becomes a cloud service provider under DFARS 7012 and needs its own FedRAMP
Moderate-equivalent posture and incident-reporting obligations. Until then: non-CUI SaaS, or private deployment
inside the customer's own approved Azure subscription.
