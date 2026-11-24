"""Live smoke test against YOUR Azure AI Foundry deployment, using SYNTHETIC evidence only.

Run on a machine signed in with `az login` (no API keys):
    set AEGIS_AI_ENDPOINT=https://amoakoheneprince-8882-resource.openai.azure.com
    set AEGIS_AI_DEPLOYMENT=gpt-5-mini
    python tools/foundry_smoke.py

It sends the fictional access-control policy to the model, then shows which proposals survived
AegisRMF's verbatim-citation validator. Expect a few cents of usage at most.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aegisrmf.evidence import analyzer as an, extract  # noqa: E402
from aegisrmf.evidence.cui_gate import AIDeployment  # noqa: E402
from aegisrmf.evidence.foundry_client import FoundryClient  # noqa: E402

data = (ROOT / "tests/fixtures/synthetic/access_control_policy.txt").read_bytes()
chunks = [dict(c, id=f"c{i}", artifact_id="synthetic") for i, c in
          enumerate(extract.chunk(extract.extract_lines("txt", data)[0]))]


class Counting:
    def __init__(self, inner):
        self.inner, self.raw = inner, []

    def complete(self, system, user, schema):
        out = self.inner.complete(system, user, schema)
        self.raw.append(out)
        return out


import json  # noqa: E402

# The real facts of the existing deployment, so the CUI gate message is specific.
DEPLOYMENT = AIDeployment(model="gpt-5-mini", region="westus3", deployment_type="global_standard")

client = Counting(FoundryClient())
analyzer = an.FoundryAnalyzer(client, DEPLOYMENT)
props = analyzer.propose("cmmc-l2", "1.0.0", chunks, classification="INTERNAL")
returned = sum(len(json.loads(r).get("links", [])) for r in client.raw if r.strip().startswith("{"))
print(f"model returned {returned} proposed links; {len(props)} passed citation validation")
for p in sorted(props, key=lambda p: -p.confidence):
    print(f"  KEPT    {p.objective_id:12} line {p.line_no:<3} conf {p.confidence:.2f}  \"{p.quote[:70]}\"")
for d in analyzer.drops:
    it = d.get("item", {})
    print(f"  DROPPED {str(it.get('objective_id')):12} line {it.get('line_no')}  reason: {d['reason']}")
    if d.get("actual_line") is not None:
        print(f"          model quoted: \"{str(it.get('quote'))[:70]}\"")
        print(f"          actual line : \"{d['actual_line'][:70]}\"")
try:
    an.FoundryAnalyzer(client, DEPLOYMENT).propose("cmmc-l2", "1.0.0", chunks, classification="CUI")
except an.CUINotApproved as e:
    print(f"CUI gate (expected block for this deployment): {e}")
