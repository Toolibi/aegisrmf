"""Azure AI Foundry (Azure OpenAI) client for FoundryAnalyzer.

Keyless by default: authenticates with Microsoft Entra ID (DefaultAzureCredential - `az login`
locally, managed identity in Azure). No API key is stored anywhere. The signed-in identity needs
the "Cognitive Services OpenAI User" role on the Foundry resource.

    AEGIS_AI_PROVIDER=azure-foundry
    AEGIS_AI_ENDPOINT=https://<resource>.openai.azure.com
    AEGIS_AI_DEPLOYMENT=gpt-5-mini          # deployment name in Foundry
"""
from __future__ import annotations

import json
import os


class FoundryClient:
    """Implements complete(system, user, schema) -> JSON string, as FoundryAnalyzer expects."""

    def __init__(self, endpoint: str | None = None, deployment: str | None = None, credential=None):
        from openai import OpenAI
        self.endpoint = (endpoint or os.environ["AEGIS_AI_ENDPOINT"]).rstrip("/")
        self.deployment = deployment or os.environ["AEGIS_AI_DEPLOYMENT"]
        if credential is None:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
        from azure.identity import get_bearer_token_provider
        token = get_bearer_token_provider(credential, "https://cognitiveservices.azure.com/.default")
        # v1 API surface; the client calls `token()` per request so tokens refresh automatically.
        self._client = OpenAI(base_url=f"{self.endpoint}/openai/v1/", api_key=token)

    def complete(self, system: str, user: str, schema: dict) -> str:
        schema = strict_schema(schema)
        resp = self._client.responses.create(
            model=self.deployment,
            instructions=system,
            input=user,
            text={"format": {"type": "json_schema", "name": "evidence_links", "schema": schema, "strict": True}},
            store=False,  # do not retain evidence-derived prompts/responses on the service
        )
        return resp.output_text


_UNSUPPORTED = {"maxLength", "minLength", "minimum", "maximum", "pattern", "format"}


def strict_schema(schema):
    """Drop keywords structured-output strict mode may reject. Limits are still enforced locally
    by FoundryAnalyzer's validator, so nothing is lost."""
    if isinstance(schema, dict):
        return {k: strict_schema(v) for k, v in schema.items() if k not in _UNSUPPORTED}
    if isinstance(schema, list):
        return [strict_schema(v) for v in schema]
    return schema


def from_settings():
    """Build (client, deployment facts) from env; used by the API when AEGIS_AI_PROVIDER=azure-foundry."""
    from ..config import get_settings
    s = get_settings()
    return FoundryClient(), s.ai_deployment()


if __name__ == "__main__":  # quick connectivity check: python -m aegisrmf.evidence.foundry_client
    c = FoundryClient()
    out = c.complete("Reply with JSON only.", "Say ok.",
                     {"type": "object", "additionalProperties": False, "required": ["ok"],
                      "properties": {"ok": {"type": "boolean"}}})
    print(json.loads(out))
