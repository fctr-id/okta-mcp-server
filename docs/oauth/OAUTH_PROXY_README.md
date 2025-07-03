# Okta MCP OAuth Proxy

A production-ready OAuth 2.0 proxy server that enables MCP (Model Context Protocol) clients to authenticate with Okta and access MCP servers through OAuth flows.

## Features

- **Complete OAuth 2.0 Implementation**: Supports all standard OAuth flows including Dynamic Client Registration (DCR)
- **MCP Protocol Compatibility**: Full compatibility with MCP Inspector and other MCP clients
- **Okta Integration**: Seamless integration with Okta Identity Cloud
- **CORS Support**: Browser-based client support with proper CORS headers
- **Security**: State management, token validation, and secure session handling
- **Audit Logging**: Comprehensive logging for security and debugging

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file with your Okta configuration:

```env
OKTA_ORG_URL=https://your-org.okta.com
OKTA_CLIENT_ID=your_client_id
OKTA_CLIENT_SECRET=your_client_secret
OKTA_SCOPES=openid profile email okta.users.read okta.groups.read okta.apps.read
```

### 3. Start the Proxy

```bash
# Simple startup
python okta_mcp/oauth_proxy/start_oauth_proxy.py

# Or with custom settings
python okta_mcp/oauth_proxy/oauth_proxy.py --backend ./main.py --host localhost --port 3001
```

### 4. Use with MCP Inspector

1. Open MCP Inspector in your browser
2. Configure server URL: `http://localhost:3001`
3. The proxy will handle OAuth discovery, client registration, and authentication automatically

## Architecture

```
MCP Client (Inspector) → OAuth Proxy → Okta OAuth → MCP Server
                            ↓
                      Well-Known Endpoints
                      Dynamic Client Registration
                      Authorization & Token Exchange
```

## OAuth Endpoints

The proxy provides these standard OAuth 2.0 endpoints:

- `/.well-known/oauth-protected-resource` - Resource metadata
- `/.well-known/oauth-authorization-server` - Authorization server metadata  
- `/.well-known/jwks.json` - JSON Web Key Set
- `/oauth2/v1/clients` - Dynamic Client Registration (DCR)
- `/oauth2/v1/authorize` - Authorization endpoint
- `/oauth2/v1/token` - Token endpoint
- `/oauth/callback` - OAuth callback handler

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `OKTA_ORG_URL` | Your Okta organization URL | Yes |
| `OKTA_CLIENT_ID` | Okta application client ID | Yes |
| `OKTA_CLIENT_SECRET` | Okta application client secret | Yes |
| `OKTA_SCOPES` | Space-separated list of OAuth scopes | No |
| `SESSION_SECRET_KEY` | Secret key for session management | No |

### Command Line Options

```bash
python okta_mcp/oauth_proxy/oauth_proxy.py --help
```

- `--backend`: Path to the backend MCP server
- `--host`: Host to bind the proxy server (default: localhost)
- `--port`: Port to bind the proxy server (default: 3001)

## Security Features

- **State Parameter Management**: Prevents CSRF attacks
- **Token Validation**: JWT token validation with Okta's public keys
- **Secure Sessions**: Server-side session management
- **Audit Logging**: All requests and authentication events are logged
- **CORS Protection**: Configurable CORS policies

## Logging

The proxy provides comprehensive logging:

- **Audit Events**: All HTTP requests and authentication events
- **OAuth Flow**: Detailed logging of OAuth state transitions
- **Error Handling**: Detailed error logging for troubleshooting

## Production Deployment

### Docker

```dockerfile
FROM python:3.11-slim

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . /app
WORKDIR /app

CMD ["python", "oauth_proxy.py", "--backend", "./main.py", "--host", "0.0.0.0", "--port", "3001"]
```

### Environment Configuration

- Set `SESSION_SECRET_KEY` to a secure random value
- Configure proper CORS origins for production
- Enable HTTPS in production environments
- Set up proper logging and monitoring

## Troubleshooting

### Common Issues

1. **CORS Errors**: Ensure the proxy is configured for your client's origin
2. **Token Validation Errors**: Check Okta configuration and network connectivity
3. **State Mismatch**: Clear browser cache and retry authentication

### Debug Mode

Enable debug logging by setting the environment variable:

```env
PYTHONPATH=.
LOGLEVEL=DEBUG
```

## License

See LICENSE file for details.
