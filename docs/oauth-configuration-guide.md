# OAuth Configuration Guide for Okta MCP Server

## 🏗️ OAuth Architecture Options

### **Option 1: MCP Proxy Server as OAuth 2.0 Confidential Client** (Recommended)

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Claude/AI     │    │  MCP Proxy      │    │     Okta        │
│   Client        │◄──►│  Server         │◄──►│   (OAuth IdP)   │
│  (No OAuth)     │    │ (Confidential   │    │                 │
│                 │    │  OAuth Client)  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                               │
                      ┌─────────────────┐
                      │ Okta MCP Server │
                      │   (Backend)     │
                      └─────────────────┘
```

**Benefits:**
- ✅ AI clients (Claude) don't need OAuth knowledge
- ✅ Centralized authentication/authorization
- ✅ Better security (confidential client)
- ✅ Easier client integration

### **Option 2: Test Client as OAuth 2.0 Public Client** (Testing only)

```
┌─────────────────┐    ┌─────────────────┐
│  Test Client    │    │     Okta        │
│ (Public OAuth   │◄──►│   (OAuth IdP)   │
│   Client)       │    │                 │
└─────────────────┘    └─────────────────┘
        │
        │              ┌─────────────────┐
        └─────────────►│ MCP Server      │
                       │                 │
                       └─────────────────┘
```

**Benefits:**
- ✅ Good for testing OAuth flows
- ✅ Direct client authentication
- ❌ Each client needs OAuth implementation

## 🔧 **Okta Application Configuration**

### **For Option 1: MCP Proxy Server (Confidential Client)**

#### 1. Create Okta Application
1. Go to Okta Admin Console → **Applications** → **Applications**
2. Click **Create App Integration**
3. Choose **OIDC - OpenID Connect**
4. Choose **Web Application** (for confidential client)

#### 2. Application Settings
| Setting | Value |
|---------|-------|
| **App integration name** | `MCP Proxy Server` |
| **Grant type** | ✅ Authorization Code<br>✅ Refresh Token |
| **Sign-in redirect URIs** | `http://localhost:3001/oauth/callback` |
| **Sign-out redirect URIs** | `http://localhost:3001/oauth/logout` |
| **Controlled access** | Configure as needed |

#### 3. Note Configuration Details
After creation, note these values:
- **Client ID**: `0oa1b2c3d4e5f6g7h8i9`
- **Client Secret**: `ABC123def456GHI789jkl` (keep secure!)
- **Okta domain**: `https://your-org.okta.com`

#### 4. Required Environment Variables
```bash
# OAuth Confidential Client Configuration (for MCP Proxy)
export OKTA_OAUTH_CLIENT_ID="0oa1b2c3d4e5f6g7h8i9"
export OKTA_OAUTH_CLIENT_SECRET="ABC123def456GHI789jkl"
export OKTA_CLIENT_ORGURL="https://your-org.okta.com"
export OAUTH_PROXY_PORT="3001"
export OAUTH_REDIRECT_URI="http://localhost:3001/oauth/callback"

# Okta API Configuration (for backend MCP server)
export OKTA_CLIENT_TOKEN="your_okta_api_token"
```

### **For Option 2: Test Client (Public Client)**

#### 1. Create Okta Application
1. Go to Okta Admin Console → **Applications** → **Applications**
2. Click **Create App Integration**
3. Choose **OIDC - OpenID Connect**
4. Choose **Native Application** (for public client)

#### 2. Application Settings
| Setting | Value |
|---------|-------|
| **App integration name** | `MCP Test Client` |
| **Grant type** | ✅ Authorization Code<br>✅ Refresh Token |
| **Sign-in redirect URIs** | `urn:ietf:wg:oauth:2.0:oob` |
| **Controlled access** | Configure as needed |

#### 3. Environment Variables
```bash
# OAuth Public Client Configuration (for test client)
export OKTA_OAUTH_CLIENT_ID="0oa9z8y7x6w5v4u3t2s1"
export OKTA_OAUTH_CLIENT_SECRET="not_required_for_public_client"
export OKTA_CLIENT_ORGURL="https://your-org.okta.com"
```

## 🚀 **Usage Examples**

### **Option 1: Using MCP Proxy Server (Recommended)**

#### 1. Start the OAuth Proxy Server
```bash
# HTTP mode (recommended for web-based OAuth flow)
python okta_oauth_proxy.py --transport http --port 3001

# The proxy will be available at: http://localhost:3001
```

#### 2. Configure Claude Desktop
Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "okta-oauth-proxy": {
      "command": "node",
      "args": ["-e", "require('http').request('http://localhost:3001').end()"],
      "transport": "stdio"
    }
  }
}
```

#### 3. OAuth Flow for Proxy Server
```
1. Claude/AI client connects to proxy server
2. Proxy detects no OAuth token
3. Proxy redirects user to: https://your-org.okta.com/oauth2/default/v1/authorize?
   client_id=0oa1b2c3d4e5f6g7h8i9&
   response_type=code&
   scope=openid+profile+okta.users.read&
   redirect_uri=http://localhost:3001/oauth/callback&
   state=abc123
4. User authenticates with Okta
5. Okta redirects to: http://localhost:3001/oauth/callback?code=xyz789&state=abc123
6. Proxy exchanges code for access token
7. Proxy stores token and allows MCP operations
8. All subsequent requests are automatically authenticated
```

### **Option 2: Using Test Client**

```bash
# Interactive OAuth testing
python clients/okta-oauth-test-client.py --server ./main.py --oauth

# The client will open browser for OAuth flow
```

## 🔐 **OAuth Scopes Configuration**

### Required Scopes for MCP Operations

| Scope | Purpose | Required For |
|-------|---------|--------------|
| `openid` | Basic OpenID Connect | User identification |
| `profile` | User profile information | User details |
| `email` | User email address | User identification |
| `okta.users.read` | Read user information | User management tools |
| `okta.groups.read` | Read group information | Group management tools |
| `okta.apps.read` | Read application information | App management tools |
| `okta.policies.read` | Read authentication policies | Policy tools |
| `okta.logs.read` | Read system logs | Audit/logging tools |
| `okta.networkZones.read` | Read network zones | Network policy tools |

### Scope Assignment in Okta

1. Go to **Security** → **API** → **Authorization Servers**
2. Select **default** authorization server
3. Go to **Scopes** tab
4. Ensure all required scopes are present and enabled
5. Go to **Access Policies** tab
6. Create/modify policies to grant scopes to your application

## 🛡️ **Security Considerations**

### **For Confidential Client (MCP Proxy)**

1. **Client Secret Protection**
   - Store client secret securely (environment variables, secrets manager)
   - Never commit client secret to version control
   - Rotate client secret regularly

2. **Redirect URI Security**
   - Use HTTPS in production: `https://your-domain.com/oauth/callback`
   - Validate redirect URI matches exactly
   - Consider using localhost only for development

3. **Token Storage**
   - Store tokens securely (encrypted at rest)
   - Implement token refresh logic
   - Handle token expiration gracefully

### **For Public Client (Test Client)**

1. **No Client Secret**
   - Public clients don't use client secrets
   - Use PKCE (Proof Key for Code Exchange) if supported
   - Rely on redirect URI validation

2. **Out-of-Band Flow**
   - `urn:ietf:wg:oauth:2.0:oob` is secure for CLI/desktop apps
   - User manually copies authorization code
   - No web server required

## 🧪 **Testing OAuth Configuration**

### Test Confidential Client Flow
```bash
# Test the proxy server OAuth flow
curl -X GET http://localhost:3001/oauth/authorize
# Should redirect to Okta authorization page
```

### Test Public Client Flow
```bash
# Test the test client OAuth flow
python clients/okta-oauth-test-client.py --oauth --debug
```

### Verify Token Exchange
```bash
# Check if tokens are being exchanged correctly
tail -f logs/oauth_proxy.log
# Look for "Token exchange successful" messages
```

## 🔍 **Troubleshooting**

### Common OAuth Configuration Issues

1. **Invalid Redirect URI**
   ```
   Error: redirect_uri_mismatch
   ```
   **Solution**: Ensure redirect URI in Okta app matches exactly

2. **Invalid Client Credentials**
   ```
   Error: invalid_client
   ```
   **Solution**: Verify client ID and secret are correct

3. **Insufficient Scopes**
   ```
   Error: insufficient_scope
   ```
   **Solution**: Grant required scopes to the application

4. **Network Issues**
   ```
   Error: Connection refused
   ```
   **Solution**: Check if proxy server is running on correct port

## 📚 **Next Steps**

1. **Choose Architecture**: Decide between Option 1 (proxy) or Option 2 (client)
2. **Configure Okta Application**: Follow the appropriate configuration above
3. **Set Environment Variables**: Configure OAuth credentials
4. **Test OAuth Flow**: Use provided testing tools
5. **Deploy to Production**: Use HTTPS and secure token storage

For detailed implementation, see:
- [OAuth Test Client Guide](oauth-test-client-guide.md)
- [Authorization Middleware Documentation](../okta_mcp/middleware/README.md)
