# OAuth-Enabled MCP Test Client Usage Guide

## Overview

The `okta-oauth-test-client.py` is a comprehensive OAuth-enabled test client for the Okta MCP Server that supports OAuth 2.0 authentication flows and authorization testing. This client extends the standard MCP client with OAuth capabilities for testing authorization policies and access controls.

## Features

### 🔐 OAuth 2.0 Support
- **Authorization Code Flow**: Complete OAuth 2.0 authorization code flow implementation
- **Token Management**: Automatic token exchange, storage, and Bearer token generation
- **JWT Decoding**: Parse user information from JWT tokens (for testing purposes)
- **Browser Integration**: Automatic browser opening for OAuth authorization

### 🧪 Authorization Testing
- **Role-Based Access Control Testing**: Test different user roles and permissions
- **Scope-Based Permission Testing**: Validate OAuth scopes and API access
- **Contextual Authorization Rules**: Test context-aware authorization logic
- **Bulk Operation Limits**: Test limits for bulk operations based on user roles
- **Self-Service vs Admin Operations**: Differentiate between user and admin capabilities

### 📊 Rich User Interface
- **Formatted Output**: Rich console output with colors, tables, and panels
- **Test Result Summaries**: Detailed test execution reports
- **OAuth Status Display**: Real-time OAuth authentication status
- **Interactive Commands**: Enhanced shell with OAuth-specific commands

### 🔍 Debug and Monitoring
- **Comprehensive Logging**: Detailed protocol and authentication logging
- **Debug Mode**: Enhanced debug output for troubleshooting
- **Error Handling**: Graceful error handling with detailed error messages

## Prerequisites

### Environment Variables
Set the following environment variables for OAuth configuration:

```bash
# Okta OAuth Application Configuration
export OKTA_OAUTH_CLIENT_ID="your_oauth_client_id"
export OKTA_OAUTH_CLIENT_SECRET="your_oauth_client_secret"
export OKTA_CLIENT_ORGURL="https://your-org.okta.com"

# AI Provider Configuration (same as standard client)
export AI_PROVIDER="openai"  # or "anthropic", "groq", etc.
export OPENAI_API_KEY="your_openai_key"  # if using OpenAI

# Optional: Logging Configuration
export LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR
```

### Dependencies
The client requires additional dependencies for OAuth support:
```bash
pip install httpx PyJWT
```

## Usage

### Basic Usage

#### 1. Standard MCP Client (No OAuth)
```bash
python clients/okta-oauth-test-client.py --server ./main.py
```

#### 2. OAuth-Enabled Client
```bash
python clients/okta-oauth-test-client.py --server ./okta_oauth_proxy.py --oauth
```

#### 3. HTTP Transport with OAuth
```bash
python clients/okta-oauth-test-client.py --http http://localhost:8001 --oauth
```

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--server <path>` | Path to server script for STDIO transport | `--server ./okta_oauth_proxy.py` |
| `--http <url>` | HTTP URL for server transport | `--http http://localhost:8001` |
| `--oauth` | Enable OAuth authentication flow | `--oauth` |
| `--debug` | Enable debug mode with detailed logging | `--debug` |
| `--query <query>` | Run a single query and exit | `--query "List 5 users"` |
| `--test-auth` | Run authorization test suite and exit | `--test-auth` |

### Interactive Commands

Once in the interactive shell, you can use these commands:

| Command | Description |
|---------|-------------|
| `exit` or `quit` | Exit the client |
| `tools` | Show available MCP tools |
| `oauth-info` | Display OAuth authentication status |
| `test-auth` | Run comprehensive authorization test suite |
| `debug on/off` | Toggle debug mode |

## OAuth Flow Process

### 1. Authorization Request
```
┌─────────────────────────────────────────────────────────────┐
│ 1. Client generates authorization URL with:                 │
│    - client_id                                              │
│    - response_type=code                                     │
│    - scope (okta.users.read, okta.apps.read, etc.)        │
│    - redirect_uri                                           │
│    - state (for CSRF protection)                           │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. User browser opens Okta authorization page              │
│    - User authenticates with Okta                          │
│    - User consents to application permissions              │
│    - Okta redirects with authorization code                │
└─────────────────────────────────────────────────────────────┘
```

### 2. Token Exchange
```
┌─────────────────────────────────────────────────────────────┐
│ 3. Client exchanges authorization code for access token:   │
│    POST /oauth2/default/v1/token                           │
│    - grant_type=authorization_code                         │
│    - client_id + client_secret                             │
│    - code (from step 2)                                    │
│    - redirect_uri                                           │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Okta returns:                                           │
│    - access_token (JWT)                                     │
│    - token_type=Bearer                                      │
│    - expires_in                                             │
│    - scope                                                  │
└─────────────────────────────────────────────────────────────┘
```

### 3. Authenticated API Calls
```
┌─────────────────────────────────────────────────────────────┐
│ 5. All subsequent MCP tool calls include:                  │
│    Authorization: Bearer <access_token>                     │
│                                                             │
│ 6. OAuth proxy validates token and enforces:               │
│    - User identity and roles                                │
│    - OAuth scopes                                           │
│    - Authorization policies                                 │
└─────────────────────────────────────────────────────────────┘
```

## Authorization Test Suite

The client includes a comprehensive test suite that validates:

### Test Categories

#### 1. Public Tool Access
- **Purpose**: Test access to public tools that don't require authentication
- **Example**: Time/date utilities
- **Expected**: Should always work

#### 2. User Read Access
- **Purpose**: Test basic user data access
- **Example**: List users, get user details
- **Expected**: Works with `okta.users.read` scope

#### 3. Admin-Only Access
- **Purpose**: Test administrative functions
- **Example**: System logs, advanced configurations
- **Expected**: Requires admin role/elevated permissions

#### 4. Bulk Operation Limits
- **Purpose**: Test limits on bulk operations
- **Example**: Requesting 100+ users vs 5 users
- **Expected**: Limited for non-admin users

#### 5. Self-Access Test
- **Purpose**: Test access to own user data
- **Example**: Get own user information
- **Expected**: Should work regardless of broader permissions

### Running Tests

#### Automated Test Suite
```bash
# Run all authorization tests
python clients/okta-oauth-test-client.py --server ./okta_oauth_proxy.py --oauth --test-auth
```

#### Manual Testing in Interactive Mode
```bash
python clients/okta-oauth-test-client.py --server ./okta_oauth_proxy.py --oauth

# In the interactive shell:
> test-auth
```

### Test Results

The test suite provides detailed results including:

```
┌─────────────────────────────────────────────────────────────┐
│                Authorization Test Results                   │
├─────────────────┬──────────────┬────────┬─────────────────┤
│ Test            │ Type         │ Status │ Result Preview  │
├─────────────────┼──────────────┼────────┼─────────────────┤
│ Public Tool     │ public       │ ✅ PASS │ Current time... │
│ User Read       │ user_read    │ ✅ PASS │ {"users": [...] │
│ Admin-Only      │ admin_only   │ ❌ FAIL │ Access denied   │
│ Bulk Operation  │ bulk_limit   │ ✅ PASS │ Limited to 10   │
│ Self-Access     │ self_access  │ ✅ PASS │ {"user": {...   │
└─────────────────┴──────────────┴────────┴─────────────────┘

Test Summary: 4/5 tests passed
```

## OAuth Status Information

Use the `oauth-info` command to view detailed OAuth status:

```
┌─────────────────────────────────────────────────────────────┐
│                OAuth Authentication Status                  │
├─────────────────┬───────────────────────────────────────────┤
│ Property        │ Value                                     │
├─────────────────┼───────────────────────────────────────────┤
│ Status          │ ✅ Authenticated                          │
│ Token Present   │ Yes                                       │
│ User ID         │ 00u1a2b3c4d5e6f7g8h9                     │
│ Email           │ user@company.com                          │
│ Name            │ John Doe                                  │
│ Issuer          │ https://your-org.okta.com/oauth2/default  │
│ Audience        │ api://default                             │
│ Roles           │ user, app_admin                           │
│ Scopes          │ okta.users.read okta.apps.read           │
│ Expires         │ 2024-01-15 14:30:00                       │
└─────────────────┴───────────────────────────────────────────┘
```

## Troubleshooting

### Common Issues

#### 1. OAuth Configuration Missing
```
❌ Missing OAuth configuration. Set OKTA_OAUTH_CLIENT_ID, OKTA_OAUTH_CLIENT_SECRET, and OKTA_CLIENT_ORGURL
```
**Solution**: Ensure all required environment variables are set.

#### 2. Authorization Code Invalid
```
❌ Token exchange failed: invalid_grant
```
**Solution**: The authorization code may have expired or been used already. Restart the OAuth flow.

#### 3. Access Denied Errors
```
{"error": "Access denied", "details": {"required_roles": ["admin"], "user_roles": ["user"]}}
```
**Solution**: The authenticated user lacks required permissions. Contact your Okta administrator.

#### 4. Token Expired
```
❌ Token expired and refresh failed
```
**Solution**: Re-authenticate using the OAuth flow.

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
python clients/okta-oauth-test-client.py --server ./okta_oauth_proxy.py --oauth --debug
```

Debug mode provides:
- Detailed HTTP request/response logs
- JWT token parsing information
- MCP protocol message exchange
- Authorization middleware execution traces

## Integration Examples

### Example 1: Testing User Access
```python
# Query with OAuth context
query = "List the first 5 active users and show their group memberships"

# The client automatically adds OAuth context:
# [OAuth Context: User=john.doe@company.com, Roles=['user']] List the first 5 active users...
```

### Example 2: Authorization Policy Testing
```python
# Test different scenarios programmatically
test_queries = [
    "Get user details for user@company.com",  # Should work - user data
    "Get system audit logs",                   # Should fail - admin only
    "List my applications",                    # Should work - self-service
]
```

### Example 3: Role-Based Testing
```python
# Different users will see different results based on their roles:
# - Regular user: Limited to own data and basic read operations
# - App admin: Can manage applications but not system settings
# - Super admin: Full access to all operations
```

## Security Considerations

1. **Token Storage**: Tokens are stored in memory only and not persisted to disk
2. **HTTPS Only**: Always use HTTPS in production environments
3. **Scope Limitation**: Request only the minimum required OAuth scopes
4. **Token Expiration**: Tokens have limited lifetime and should be refreshed appropriately
5. **Audit Logging**: All OAuth operations are logged for security monitoring

## Next Steps

1. **Custom Authorization Rules**: Extend the authorization middleware with custom rules
2. **Integration Testing**: Use the client for automated integration testing
3. **Performance Testing**: Test OAuth overhead on API performance
4. **Multi-User Testing**: Test with different user roles and permissions
5. **Error Scenario Testing**: Test various error conditions and edge cases
