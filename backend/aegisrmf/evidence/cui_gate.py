"""CUI gate for AI model calls.

Commercial Azure OpenAI is in Microsoft's FedRAMP High scope and Microsoft states Azure commercial
supports DFARS 252.204-7012, so CUI is not banned outright. It is allowed to reach a model only when
ALL three conditions are recorded for the deployment:

  1. FedRAMP High scope - the operator confirms the exact model/feature is on Microsoft's
     FedRAMP High audit-scope list (per service, not "all of Azure").
  2. US data residency  - a US region (commercial or US Gov) and a deployment type that keeps
     processing in-region or in the US Data Zone. "Global" deployment types are refused.
  3. DFARS terms        - the customer's contracting/legal owner confirmed Microsoft's current
     DFARS 7012 terms cover this subscription, recorded with who and when.

Export-controlled (ITAR/EAR) evidence is refused unless the region is Azure Government.

This gate does not make AegisRMF itself a FedRAMP-authorized service. Holding customer CUI in the
SaaS also requires AegisRMF's own FedRAMP Moderate-equivalent posture (see docs/adr/0003).
"""
from __future__ import annotations

from dataclasses import dataclass

US_COMMERCIAL_REGIONS = {
    "eastus", "eastus2", "centralus", "northcentralus", "southcentralus", "westcentralus",
    "westus", "westus2", "westus3",
}
US_GOV_REGIONS = {"usgovvirginia", "usgovarizona", "usgovtexas"}
ALLOWED_DEPLOYMENT_TYPES = {"standard", "provisioned", "datazone_standard", "datazone_provisioned"}


@dataclass(frozen=True)
class AIDeployment:
    model: str = ""
    region: str = ""
    deployment_type: str = ""            # standard | provisioned | datazone_* | global_*
    data_zone: str = ""                  # required "us" for datazone_* types
    fedramp_high_confirmed: bool = False
    dfars_terms_confirmed_by: str = ""   # name/role of the person who confirmed
    dfars_terms_confirmed_on: str = ""   # ISO date


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    checks: dict
    reasons: tuple

    def summary(self) -> str:
        return "allowed" if self.allowed else "; ".join(self.reasons)


def evaluate(d: AIDeployment, classification: str, export_controlled: bool = False) -> GateResult:
    """Non-CUI data passes. CUI passes only when all three checks pass."""
    region = d.region.lower().replace(" ", "")
    dtype = d.deployment_type.lower().replace(" ", "_")
    residency_ok = (region in US_COMMERCIAL_REGIONS | US_GOV_REGIONS) and dtype in ALLOWED_DEPLOYMENT_TYPES \
        and (not dtype.startswith("datazone") or d.data_zone.lower() == "us")
    checks = {
        "fedramp_high_scope": bool(d.fedramp_high_confirmed and d.model),
        "us_data_residency": residency_ok,
        "dfars_7012_terms": bool(d.dfars_terms_confirmed_by.strip() and d.dfars_terms_confirmed_on.strip()),
    }
    if classification != "CUI":
        return GateResult(True, checks, ())
    reasons = []
    if not checks["fedramp_high_scope"]:
        reasons.append("model not confirmed on Microsoft's FedRAMP High audit-scope list")
    if not checks["us_data_residency"]:
        if dtype.startswith("global"):
            reasons.append("Global deployment types may process data outside the US")
        else:
            reasons.append(f"region '{d.region}' / deployment type '{d.deployment_type}' is not a US-resident configuration")
    if not checks["dfars_7012_terms"]:
        reasons.append("DFARS 7012 terms not confirmed (need who and when)")
    if export_controlled and region not in US_GOV_REGIONS:
        reasons.append("export-controlled data requires an Azure Government region")
    return GateResult(not reasons, checks, tuple(reasons))
