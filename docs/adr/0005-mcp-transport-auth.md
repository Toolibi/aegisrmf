# ADR-0005: MCP over streamable HTTP as an OAuth resource server
**Decision.** Use the official MCP Python SDK (v2 `MCPServer`). HTTP transport runs in resource-server mode
(RFC 9728 metadata, `validate_token_resource=True`) with `ApiKeyVerifier`; Entra ID can replace the
verifier without touching tools. Tenant comes from the token, never from arguments. Write/export tools need
a scope and `confirm=true`, are annotated non-read-only, and every call is audited.
