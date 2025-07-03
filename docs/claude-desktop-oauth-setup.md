# Claude Desktop OAuth Setup Guide

## Overview

This guide explains how to configure Claude Desktop to connect to your OAuth-protected Okta MCP server using the npx remote approach.

## Prerequisites

1. **OAuth Proxy Server Running**: Your `oauth_proxy.py` should be running on `http://localhost:3001`
2. **Node.js Installed**: Required for the npx command
3. **Claude Desktop**: Latest version installed

## Step 1: Verify Your OAuth Proxy Server

Make sure your OAuth proxy server is running:

```bash
cd C:\Users\Dharanidhar\Desktop\github-repos\okta-mcp-server
python okta_mcp/oauth_proxy/oauth_proxy.py
```

You should see:
```
OAuth FastMCP proxy server started successfully!
Available endpoints:
  - GET  http://localhost:3001/          - Home page
  - GET  http://localhost:3001/oauth/permissions - View OAuth permissions
  - GET  http://localhost:3001/oauth/login - OAuth login
  - GET  http://localhost:3001/mcp/tools  - List MCP tools (protected)
  - POST http://localhost:3001/mcp/tools/call - Call MCP tool (protected)
```

## Step 2: Test OAuth Flow Manually

Before configuring Claude Desktop, test the OAuth flow manually:

1. Open browser to `http://localhost:3001`
2. Click "View Permissions" to see what access will be granted
3. Click "Login with Okta" to test the OAuth flow
4. Verify you can see user information after authentication

## Step 3: Configure Claude Desktop

### Option A: Using npx remote (Recommended)

1. **Locate Claude Desktop config file**:
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

2. **Add the MCP server configuration**:

```json
{
  "mcpServers": {
    "okta-mcp-oauth-proxy": {
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-everything"
      ],
      "env": {
        "MCP_SERVER_URL": "http://localhost:3001"
      }
    }
  }
}
```

### Option B: Alternative HTTP Transport Configuration

If the npx approach doesn't work, you can try an HTTP transport approach:

```json
{
  "mcpServers": {
    "okta-mcp-oauth-proxy": {
      "command": "node",
      "args": [
        "-e",
        "const { spawn } = require('child_process'); const proc = spawn('npx', ['@modelcontextprotocol/server-everything'], { env: { ...process.env, MCP_SERVER_URL: 'http://localhost:3001' }, stdio: 'inherit' }); proc.on('exit', process.exit);"
      ]
    }
  }
}
```

## Step 4: Restart Claude Desktop

1. **Close Claude Desktop completely**
2. **Restart Claude Desktop**
3. **Check for MCP connection**

## Step 5: Test the Integration

1. **Start a new conversation in Claude Desktop**
2. **Look for MCP tools availability** - Claude should show available tools
3. **Try using an Okta tool** like "list users" or "get user info"

## Authentication Flow

When Claude Desktop tries to use MCP tools:

1. **First Request**: Claude Desktop → HTTP request to `localhost:3001/mcp/tools`
2. **Redirect**: Server responds with `401 Unauthorized` 
3. **OAuth Flow**: 
   - Browser opens to `localhost:3001/oauth/login`
   - Redirects to Okta for authentication
   - User logs in and grants permissions
   - Returns to proxy with access token
4. **Retry**: Claude Desktop retries the MCP request with session cookie
5. **Success**: MCP tools are now available

## Troubleshooting

### Check OAuth Proxy Status
```bash
curl http://localhost:3001/health
```

### Check MCP Tools Endpoint
```bash
curl http://localhost:3001/mcp/tools
```
Should return `401 Unauthorized` if not authenticated.

### Check Claude Desktop Logs
- Windows: Check Windows Event Viewer or Claude Desktop's internal logs
- macOS: Check Console app for Claude-related logs

### Test OAuth Flow Manually
```bash
# Test the OAuth flow
curl -v http://localhost:3001/oauth/login
```

### Verify Environment Variables
Make sure these are set:
- `OKTA_CLIENT_ID`
- `OKTA_CLIENT_SECRET` 
- `OKTA_ORG_URL`

## Expected Behavior

### Successful Configuration
- Claude Desktop shows MCP tools in the interface
- When you try to use a tool, it triggers OAuth authentication
- Browser opens for Okta login
- After authentication, tools become available

### Authentication Required
- First tool use will trigger OAuth flow
- Browser window opens automatically
- User authenticates with Okta
- Claude Desktop can then use MCP tools

## Security Notes

### Session Management
- Sessions expire after 2 hours
- Re-authentication required after expiration
- Sessions are encrypted and secure

### OAuth Scopes
The MCP server requests these permissions:
- `openid`, `profile`, `email` - Basic identity
- `okta.users.read` - Read user information
- `okta.groups.read` - Read group information  
- `okta.apps.read` - Read application information
- `okta.events.read` - Read event logs
- `okta.logs.read` - Read system logs
- `okta.policies.read` - Read policies
- `okta.devices.read` - Read device information
- `okta.factors.read` - Read authentication factors

## Common Issues

### 1. "Connection refused" 
- **Cause**: OAuth proxy server not running
- **Solution**: Start `python okta_mcp/oauth_proxy/oauth_proxy.py`

### 2. "401 Unauthorized"
- **Cause**: Not authenticated or session expired
- **Solution**: Complete OAuth flow in browser

### 3. "Invalid token audience"
- **Cause**: Token validation failed
- **Solution**: Check Okta configuration and try re-authenticating

### 4. "Tools not showing in Claude Desktop"
- **Cause**: MCP configuration issue
- **Solution**: Check Claude Desktop config file syntax and restart

### 5. OAuth redirect fails
- **Cause**: Redirect URI mismatch
- **Solution**: Verify Okta app configuration allows `http://localhost:3001/oauth/callback`

## Advanced Configuration

### Custom Port
If you need to run on a different port:

1. **Update OAuth proxy startup**:
```bash
python okta_mcp/oauth_proxy/oauth_proxy.py --port 3002
```

2. **Update Claude Desktop config**:
```json
{
  "mcpServers": {
    "okta-mcp-oauth-proxy": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-everything"],
      "env": {
        "MCP_SERVER_URL": "http://localhost:3002"
      }
    }
  }
}
```

### Production Deployment
For production use:
- Set `SESSION_SECRET_KEY` environment variable
- Use HTTPS with proper SSL certificates
- Configure proper CORS settings
- Enable security headers
- Use persistent session storage (Redis/Database)

## Support

If you encounter issues:

1. **Check server logs** for detailed error information
2. **Test manually** using browser and curl commands
3. **Verify Okta configuration** in your Okta admin console
4. **Check Claude Desktop configuration** syntax and file location
