# Okta MCP Server - Architecture Overview

## Current State: FastMCP OAuth Unified Server ✅

The architecture has been completely modernized with a unified FastMCP server that provides both OAuth-protected MCP access and full OAuth 2.1 compliance. The implementation features enterprise-grade security with comprehensive JWT validation, RBAC, and MCP Inspector compatibility.

## Core Components

### 1. Main MCP Server (`okta_mcp/server.py`)
**Purpose**: Core FastMCP server implementation with direct protocol compliance
- **Transport**: STDIO (default) or HTTP 
- **Use Case**: Direct MCP client connections (Claude Desktop, CLI tools)
- **Authentication**: Optional JWT/Bearer token auth via environment variables
- **Protocol**: Native MCP protocol over STDIO or HTTP
- **Entry Point**: `main.py` or `okta_mcp.run_server` (default mode)

### 2. Unified FastMCP OAuth Server (`okta_mcp/fastmcp_oauth_server.py`) 🎯 **NEW PRIMARY**
**Purpose**: Single unified server with OAuth-protected MCP endpoints and virtual OAuth services
- **Transport**: HTTP only (port 3001)
- **Use Case**: MCP Inspector, OAuth-protected MCP clients, web applications
- **Authentication**: Full OAuth 2.0/OIDC flow with Okta + enterprise JWT validation
- **Protocol**: Native FastMCP with OAuth middleware + custom OAuth routes
- **Key Features**:
  - **MCP Inspector Compatible**: Full OAuth discovery, dynamic client registration, consent flow
  - **Virtual OAuth Server**: Accepts any MCP client without Okta registration
  - **Enterprise Security**: JWT validation, RBAC, consent tracking, security headers
  - **FastMCP Middleware**: Proper authentication and RBAC hooks
  - **Unified Architecture**: No proxy needed - direct FastMCP with OAuth routes

### 3. Unified Runner (`okta_mcp/run_server.py`)
**Purpose**: Single entry point for all server modes
- **Default**: Main server (STDIO) - `python -m okta_mcp.run_server`
- **FastMCP OAuth**: Unified server - `python -m okta_mcp.run_server fastmcp-oauth`
- **Both**: Concurrent servers - `python -m okta_mcp.run_server --both`
- **Testing**: HTTP no-auth - `python -m okta_mcp.run_server --danger-mcp-no-auth`

## Key Features Implemented

### ✅ Unified FastMCP OAuth Server
- **Native FastMCP**: Direct tool registration with proper middleware hooks  
- **OAuth 2.1 Compliance**: Full PKCE, consent tracking, JWT validation, refresh token scope validation
- **MCP Inspector Ready**: Complete OAuth discovery, dynamic client registration, consent flow
- **Enterprise Security**: JWT signature verification, RBAC, security headers, audit logging
- **Zero Proxy Overhead**: Direct FastMCP server with OAuth routes (no HTTP proxying)

### ✅ Enterprise-Grade JWT Validation
- **Cryptographic Verification**: RS256 signature validation with Okta JWKS
- **Multi-Audience Support**: Flexible audience validation for different token types  
- **Fail-Secure Architecture**: Any validation failure immediately stops processing
- **Comprehensive Claims Validation**: Issuer, audience, expiration, not-before checks
- **JWKS Caching**: 5-minute TTL with automatic key rotation support

### ✅ OAuth 2.1 Security Best Practices
- **PKCE Mandatory**: SHA256 code challenge for all authorization flows
- **Refresh Token Scope Validation**: RFC 6749 Section 6 compliance (only with `offline_access`)
- **RFC 6750 Error Responses**: Proper WWW-Authenticate headers on 401 responses
- **Per-Client Consent**: Confused deputy mitigation with 24-hour consent expiration
- **Security Headers**: Comprehensive browser protection (XSS, clickjacking, MIME sniffing)

### ✅ Role-Based Access Control (RBAC)
- **Configuration**: `okta_mcp/auth/rbac_config.json`
- **Real-Time Updates**: Group membership refreshed on every token validation
- **Hierarchical Roles**: viewer (12 tools), admin (17 tools), super-admin (18 tools)
- **Tool Filtering**: FastMCP middleware automatically filters tools by role
- **Audit Trail**: All permission decisions logged with user context

## File Structure (Current Implementation)

```
okta-mcp-server/
├── main.py                           # Legacy entry (STDIO only)
├── okta_mcp/
│   ├── run_server.py                 # 🎯 MAIN ENTRY POINT
│   ├── server.py                     # Core MCP server (STDIO/HTTP)
│   ├── fastmcp_oauth_server.py       # 🆕 UNIFIED FASTMCP OAUTH SERVER
│   ├── auth/
│   │   ├── oauth_provider.py         # OAuth configuration
│   │   ├── role_mapper.py            # Group to role mapping
│   │   ├── jwt_validator.py          # 🆕 Enterprise JWT validation
│   │   └── rbac_config.json          # RBAC configuration
│   ├── middleware/
│   │   └── oauth_rbac_middleware.py  # 🆕 FastMCP RBAC middleware
│   ├── oauth_proxy/                  # OAuth models and utilities
│   │   ├── models.py                 # Virtual client, auth code, consent models
│   │   └── utils.py                  # Shared OAuth utilities
│   ├── tools/                        # Tool implementations
│   │   ├── user_tools.py
│   │   ├── apps_tools.py
│   │   ├── group_tools.py
│   │   ├── log_events_tools.py
│   │   ├── policy_network_tools.py
│   │   └── datetime_tools.py
│   └── utils/                        # Shared utilities
├── docs/                             # Updated documentation
│   ├── ARCHITECTURE_OVERVIEW.md     # This file - current architecture
│   ├── security-implementation.md    # Security implementation details  
│   └── Security-Best-Practices.md    # Security best practices compliance
├── clients/                          # Client examples
│   └── basic_mcp_client.py          # Basic MCP client for testing
└── README.md                         # Main project documentation
```

### 🚫 Deprecated Files (To Be Removed)
- `okta_mcp/oauth_proxy/server.py` - Replaced by `fastmcp_oauth_server.py`
- `okta_mcp/oauth_proxy/auth_handler.py` - Logic integrated into unified server
- `okta_mcp/oauth_proxy/discovery_handler.py` - Logic integrated into unified server  
- `okta_mcp/oauth_proxy/ui_handlers.py` - Logic integrated into unified server
- `okta_mcp/middleware/authorization.py` - Replaced by `oauth_rbac_middleware.py`

## Usage Examples

### Production Deployment
```bash
# STDIO MCP server (Claude Desktop, VS Code)
python -m okta_mcp.run_server

# Unified FastMCP OAuth server (MCP Inspector, OAuth clients) - RECOMMENDED
python -m okta_mcp.run_server fastmcp-oauth

# Old OAuth proxy server (deprecated)
python -m okta_mcp.run_server mcp-with-auth

# Both servers concurrently
python -m okta_mcp.run_server --both
```

### Development/Testing
```bash
# HTTP server without auth (TESTING ONLY)
python -m okta_mcp.run_server --danger-mcp-no-auth

# FastMCP OAuth server directly
python -m okta_mcp.fastmcp_oauth_server --port 3001
```

## Environment Configuration

### Required Environment Variables
```bash
# OAuth Client Configuration (for FastMCP OAuth server)
OKTA_CLIENT_ID=your-oauth-client-id
OKTA_CLIENT_SECRET=your-oauth-client-secret
OKTA_ORG_URL=https://your-org.okta.com

# Okta API Configuration (for MCP tools)
OKTA_CLIENT_ORGURL=https://your-org.okta.com
OKTA_API_TOKEN=your-okta-api-token

# OAuth Security Configuration
OKTA_OAUTH_AUDIENCE=fctrid-okta-mcp-server
OAUTH_REDIRECT_URI=http://localhost:3001/oauth/callback
OAUTH_SCOPES=openid profile email groups

# Production Security (set to true for production)
OAUTH_REQUIRE_HTTPS=false
```

### Optional Configuration
```bash
# Session Security
SESSION_SECRET_KEY=your-session-secret-key  # Auto-generated if not provided

# Logging
LOG_LEVEL=INFO

# Server Configuration
HOST=localhost
PORT=3001
```

## Security Implementation

### FastMCP OAuth Server Security Features
- ✅ **Enterprise JWT Validation**: RS256 signature verification with fail-secure architecture
- ✅ **PKCE Protection**: Mandatory PKCE with SHA256 for all authorization flows
- ✅ **Per-Client Consent**: Confused deputy mitigation with 24-hour consent expiration
- ✅ **Refresh Token Scope Validation**: RFC 6749 Section 6 compliance (only with `offline_access`)
- ✅ **RFC 6750 Error Responses**: Proper WWW-Authenticate headers on authentication failures
- ✅ **Security Headers**: XSS, clickjacking, MIME sniffing, and cache control protection
- ✅ **Real-Time RBAC**: Group membership and role assignment on every request
- ✅ **Comprehensive Audit**: All security events logged with user context and timestamps
- ✅ **Automatic Cleanup**: Expired tokens, codes, and consent removed every 5 minutes

### OAuth Flow Security
- ✅ **Virtual Client Support**: Dynamic client registration without requiring Okta registration
- ✅ **State Parameter Protection**: 64-byte cryptographically secure CSRF protection
- ✅ **Authorization Code Security**: One-time use codes with 10-minute expiration
- ✅ **Token Isolation**: Clients never see real Okta tokens (virtual token mapping)
- ✅ **Session Security**: Encrypted session storage with secure cookie attributes

### MCP Protocol Security
- ✅ **FastMCP Middleware Integration**: Proper authentication and RBAC via FastMCP hooks
- ✅ **Tool-Level Permissions**: Granular filtering based on user role hierarchy
- ✅ **Request/Response Validation**: Full MCP protocol compliance with security validation
- ✅ **Error Handling**: Security-conscious error responses without information disclosure

## Next Steps (Optional)

The unified FastMCP OAuth server is now production-ready with enterprise-grade security. Optional improvements could include:

1. **Advanced Security**: Rate limiting, distributed session storage (Redis), token rotation
2. **Monitoring**: Metrics, health checks, performance monitoring
3. **High Availability**: Load balancing, failover mechanisms, session replication  
4. **Compliance**: SIEM integration, compliance reporting, advanced audit features
5. **Testing**: Comprehensive test suite, security penetration testing
6. **Deployment**: Docker/Kubernetes deployment, CI/CD pipeline

## Summary

✅ **Complete**: Unified FastMCP OAuth server with enterprise security implemented and tested  
✅ **MCP Inspector Compatible**: Full OAuth discovery, dynamic client registration, consent flow  
✅ **OAuth 2.1 Compliant**: PKCE, JWT validation, refresh token scope validation, RFC 6750 errors  
✅ **Enterprise Security**: JWT validation, RBAC, consent tracking, security headers, audit logging  
✅ **Production-Ready**: Comprehensive security framework with monitoring and cleanup automation  
✅ **Architecture Modernized**: Single unified server eliminates proxy complexity and improves performance

The Okta MCP Server now provides a single, powerful FastMCP server that handles both OAuth-protected access for MCP Inspector and direct MCP protocol access for traditional clients, with enterprise-grade security throughout.
