# Archived Files

This folder contains files that require `pydantic-ai` which has been removed from the server dependencies.

## Files

### Client Files (require pydantic-ai for Agent functionality)
- `okta-mcp-client.py` - Main unified MCP client
- `doNotUse-mcp-cli-sse-client.py` - SSE transport client
- `doNOtUse-mcp-cli-stdio-client.py` - STDIO transport client  
- `doNotUse-mcp-cli-streamable-client.py` - Streamable HTTP client
- `doNotUse-mcp-cli-test-sampling.py` - Sampling test client

### Server Files (unused features)
- `sampling.py` - AI-powered SCIM query generation capability
- `model_provider.py` - LLM provider abstraction for pydantic-ai

## Why Archived?

As of February 2026, `pydantic-ai` was removed from the server due to:

1. **Security Vulnerability**: Versions below 1.56.0 have known security issues
2. **Dependency Conflict**: pydantic-ai v1.56.0 requires FastMCP v2.14.0+, which introduced mandatory Docket task scheduler causing high CPU usage (10-15% baseline overhead from continuous Redis polling)
3. **Performance**: We pinned FastMCP to v2.13.3 to avoid Docket scheduler overhead
4. **Design**: Server doesn't need AI agent orchestration - it's a lightweight tool provider per MCP protocol design

**The Dilemma**: Upgrading pydantic-ai for security → forces FastMCP 2.14.0+ → causes performance degradation. Since the server doesn't use these features, we removed pydantic-ai entirely.

## To Use These Files

If you need these files, install pydantic-ai separately:
```bash
pip install pydantic-ai-slim[openai,vertexai,anthropic,mcp]==1.56.0
```

Then move the files back to their original locations:
- Client files → `clients/`
- `sampling.py` → `okta_mcp/capabilities/`
- `model_provider.py` → `okta_mcp/utils/`
