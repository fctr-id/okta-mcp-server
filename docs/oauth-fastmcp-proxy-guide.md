# OAuth FastMCP Proxy Server

This is an implementation of OAuth 2.0 authentication for FastMCP using standard OAuth libraries. Since FastMCP doesn't have built-in OAuth support yet, this solution combines:

1. **FastMCP's proxy capabilities** (`FastMCP.as_proxy()`) for MCP protocol handling
2. **Standard OAuth 2.0 implementation** using Authlib for Okta integration
3. **HTTP server** using aiohttp for OAuth endpoints and protected MCP endpoints

## Architecture

```
AI Client → OAuth Proxy Server → FastMCP Proxy → Backend MCP Server
                    ↕
                 Okta OAuth
```

The proxy server acts as an OAuth 2.0 **Confidential Client** that:
- Handles the OAuth flow with Okta (authorization code with PKCE)
- Protects MCP endpoints with OAuth authentication
- Forwards authenticated MCP requests to the backend server
- Provides user context to MCP tools

## Features

- ✅ **Standard OAuth 2.0** implementation using Authlib
- ✅ **Native FastMCP proxy** capabilities using `FastMCP.as_proxy()`
- ✅ **Session management** with secure cookies
- ✅ **Token validation** and expiration handling
- ✅ **User context injection** into MCP tool calls
- ✅ **Scope-based access control** (basic implementation)
- ✅ **Web interface** for OAuth status and MCP exploration
- ✅ **Proper error handling** and logging

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements-oauth.txt
```

### 2. Set Environment Variables

```bash
# Okta configuration
export OKTA_ORG_URL="https://your-org.okta.com"
export OKTA_CLIENT_ID="your-client-id"
export OKTA_CLIENT_SECRET="your-client-secret"
export OKTA_API_TOKEN="your-api-token"

# OAuth configuration
export OAUTH_REDIRECT_URI="http://localhost:3001/oauth/callback"
```

### 3. Run the Proxy Server

```bash
python okta_oauth_fastmcp_proxy.py --backend ./main.py --port 3001
```

### 4. Test the Implementation

```bash
python test_oauth_fastmcp_proxy.py --url http://localhost:3001
```

## Usage

### OAuth Endpoints

- **GET** `/` - Home page with OAuth status and MCP info
- **GET** `/health` - Health check endpoint
- **GET** `/oauth/login` - Initiate OAuth login flow
- **GET** `/oauth/callback` - OAuth callback handler
- **GET** `/oauth/status` - Check authentication status
- **POST** `/oauth/logout` - Logout and clear session

### Protected MCP Endpoints

All MCP endpoints require OAuth authentication:

- **GET** `/mcp/tools` - List available MCP tools
- **POST** `/mcp/tools/call` - Call an MCP tool
- **GET** `/mcp/resources` - List available MCP resources
- **POST** `/mcp/resources/read` - Read an MCP resource
- **GET** `/mcp/prompts` - List available MCP prompts

### Example MCP Tool Call

```bash
# First authenticate by visiting http://localhost:3001/oauth/login

# Then call a tool
curl -X POST http://localhost:3001/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "list_users",
    "arguments": {
      "limit": 10
    }
  }' \
  --cookie "oauth_session=your-session-cookie"
```

## Configuration

### Okta Application Setup

1. Create a new **Web Application** in Okta
2. Set **Sign-in redirect URIs** to: `http://localhost:3001/oauth/callback`
3. Set **Sign-out redirect URIs** to: `http://localhost:3001/`
4. Grant the necessary scopes:
   - `openid`
   - `profile`
   - `email`
   - `okta.users.read`
   - `okta.groups.read`

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `OKTA_ORG_URL` | Your Okta organization URL | `https://dev-123.okta.com` |
| `OKTA_CLIENT_ID` | OAuth client ID | `0abc123def456ghi789j` |
| `OKTA_CLIENT_SECRET` | OAuth client secret | `secret123` |
| `OKTA_API_TOKEN` | Okta API token | `token123` |
| `OAUTH_REDIRECT_URI` | OAuth redirect URI | `http://localhost:3001/oauth/callback` |

## Implementation Details

### OAuth Flow

1. **Authorization Request**: User visits `/oauth/login`
2. **Authorization Grant**: User authenticates with Okta
3. **Authorization Code**: Okta redirects to `/oauth/callback` with code
4. **Access Token**: Server exchanges code for access token
5. **User Info**: Server extracts user info from JWT token
6. **Session**: Server creates session and sets secure cookie

### FastMCP Integration

The proxy uses `FastMCP.as_proxy()` to create a proxy to the backend MCP server:

```python
self.mcp_proxy = FastMCP.as_proxy(
    backend_server_path,
    name="OktaOAuthMCPProxy"
)
```

This provides native MCP protocol handling while adding OAuth authentication on top.

### User Context Injection

User information is automatically injected into MCP tool calls:

```python
arguments["_oauth_user"] = user_info
result = await self.mcp_proxy.call_tool(tool_name, arguments)
```

This allows MCP tools to access user context for authorization and auditing.

## Testing

### Run Test Suite

```bash
python test_oauth_fastmcp_proxy.py
```

The test suite validates:
- Health check endpoint
- Home page rendering
- OAuth status (unauthenticated)
- OAuth login redirect
- Protected endpoint access control

### Manual Testing

1. Start the proxy server
2. Visit `http://localhost:3001/` in your browser
3. Click "Login with Okta" to authenticate
4. Explore the authenticated interface and MCP endpoints

## Security Considerations

### Current Implementation
- ✅ CSRF protection using state parameter
- ✅ Secure session cookies (httponly)
- ✅ Token expiration checking
- ✅ Input validation
- ✅ Error handling without information disclosure

### Production Recommendations
- 🔒 Enable HTTPS (`secure=True` for cookies)
- 🔒 Implement JWT signature verification
- 🔒 Add rate limiting
- 🔒 Implement token refresh
- 🔒 Add session timeout
- 🔒 Implement proper secret management
- 🔒 Add request/response logging for audit

## Differences from Previous Implementation

### Previous (Custom OAuth Server)
- Custom OAuth 2.0 implementation
- Separate OAuth server and MCP bridge
- Manual MCP client handling
- Custom session management

### Current (FastMCP + OAuth)
- Standard OAuth 2.0 using Authlib
- Native FastMCP proxy integration
- Cleaner separation of concerns
- More maintainable and standard-compliant

## Troubleshooting

### Common Issues

1. **Import Error**: Make sure `authlib` is installed
   ```bash
   pip install authlib
   ```

2. **OAuth Configuration**: Verify environment variables are set
   ```bash
   python -c "from okta_mcp.auth.oauth_provider import OAuthConfig; print(OAuthConfig.from_environment())"
   ```

3. **Backend Connection**: Ensure the backend MCP server is accessible
   ```bash
   python main.py
   ```

### Debug Mode

Enable debug logging:
```bash
export PYTHONPATH="."
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from okta_oauth_fastmcp_proxy import main
main()
"
```

## Future Enhancements

- [ ] JWT signature verification
- [ ] Token refresh implementation
- [ ] Advanced scope-based authorization
- [ ] Rate limiting and throttling
- [ ] Redis session storage
- [ ] OpenID Connect integration
- [ ] Multi-tenant support
- [ ] Metrics and monitoring
