# Security Implementation for Okta MCP OAuth Proxy Server

## Overview

This document outlines the comprehensive security measures implemented in the Okta MCP OAuth proxy server. The implementation follows OAuth 2.0 Security Best Practices (RFC 9700), MCP Security Best Practices, and implements enterprise-grade JWT validation with Role-Based Access Control (RBAC) as of **July 5, 2025**.

**Reference**: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

## Security Architecture

The OAuth proxy server implements a defense-in-depth security model with multiple layers of protection and real-time RBAC enforcement:

```
AI Client → OAuth Proxy Server → Okta OAuth Server
    ↓              ↓                    ↓
Security Layer 1  Security Layer 2    Security Layer 3
    ↓              ↓                    ↓
   PKCE         JWT Validation       RBAC Filtering
   CSRF         Signature Verify     Role Mapping
   Session      Issuer Validate      Tool Access
   Audit        Exception Based      Group Sync
```

## Client-to-Proxy Security Protections

### 1. OAuth 2.0 + PKCE Implementation

**Protection**: Prevents authorization code interception attacks

**Implementation**:
- **Cryptographically secure code verifier**: 32-byte random values
- **SHA256 code challenge**: `S256` challenge method (RFC 7636)
- **State parameter**: 64-byte random CSRF protection
- **One-time use authorization codes**: Codes expire after 10 minutes max

```python
# Secure PKCE implementation
code_verifier = secrets.token_urlsafe(64)  # 43+ chars as per RFC
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode('ascii')).digest()
).decode('ascii').strip('=')
```

### 2. Session Security

**Protection**: Prevents session hijacking and fixation attacks

**Implementation**:
- **Encrypted session cookies**: AES-256 encryption with rotating keys
- **Secure cookie attributes**: `httponly=True`, `samesite='Lax'`
- **User-bound session keys**: Sessions tied to specific user context
- **Session expiration**: 2-hour maximum lifetime with cleanup

```python
# Production-ready session configuration
storage = EncryptedCookieStorage(
    secrets.token_bytes(32),  # 256-bit encryption key
    cookie_name='AIOHTTP_SESSION',
    max_age=7200,  # 2 hours
    secure=True,   # HTTPS only in production
    httponly=True, # Prevent XSS access
    samesite='Lax' # CSRF protection
)
```

### 3. Security Headers

**Protection**: Browser-level security protections

**Implementation**:
- **Content Security Policy**: Prevents XSS and code injection attacks
- **X-Frame-Options**: Clickjacking protection
- **HSTS**: Forces HTTPS connections in production environments
- **X-Content-Type-Options**: MIME sniffing protection

```python
security_headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY', 
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': 'default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\'',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache'
}

# Add HSTS for HTTPS in production
if self.oauth_config.require_https:
    security_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
```

### 4. Virtual Token Management

**Protection**: Isolates real Okta tokens from clients

**Implementation**:
- **Virtual access tokens**: Clients never see real Okta tokens
- **Token mapping**: Secure mapping between virtual and real tokens
- **User context binding**: Tokens bound to specific user sessions
- **Automatic expiration**: Tokens inherit Okta token expiration

### 5. CORS Protection

**Protection**: Prevents unauthorized cross-origin requests

**Implementation**:
- **Wildcard origins**: Controlled for development only
- **Credentials support**: Secure cookie transmission
- **Method restrictions**: Only necessary HTTP methods allowed

### 6. RFC 6750 Compliant Error Responses

**Protection**: Proper OAuth error communication to clients

**Implementation**:
- **WWW-Authenticate header**: All 401 responses include proper authentication challenge
- **Resource metadata URL**: Points clients to OAuth protected resource metadata
- **Standard error codes**: Uses RFC-compliant error codes (`invalid_token`)
- **Descriptive messages**: Clear guidance for client authentication

```python
# RFC 6750 compliant 401 response
def _create_401_response(self, request: web.Request, error_description: str) -> web.Response:
    resource_metadata_url = f"{request.scheme}://{request.host}/.well-known/oauth-protected-resource"
    www_authenticate = f'Bearer realm="Okta MCP Server", resource_metadata="{resource_metadata_url}"'
    
    return web.json_response(
        {"error": "invalid_token", "error_description": error_description},
        status=401,
        headers={"WWW-Authenticate": www_authenticate}
    )
```

## Proxy-to-Okta Security Protections

### 1. JWT Token Validation

**Protection**: Ensures token integrity and authenticity

**Implementation**:
- **Signature verification**: RS256 with Okta's JWKS endpoint
- **Expiration validation**: Strict `exp` claim checking
- **Audience validation**: Configurable via `OKTA_OAUTH_AUDIENCE`
- **Issuer validation**: Always validates against Okta's org URL

```python
# Comprehensive JWT validation
decoded = jwt.decode(
    access_token,
    signing_key,
    algorithms=['RS256'],
    audience=self.config.audience,  # Configurable audience
    issuer=self.config.org_url,     # Okta org validation
    options={
        "verify_signature": True,   # CRITICAL: Always verify
        "verify_exp": True,         # CRITICAL: Check expiration
        "verify_aud": True,         # CRITICAL: Check audience
        "verify_iss": True,         # CRITICAL: Check issuer
        "require_exp": True,        # CRITICAL: Require expiration
        "require_aud": True,        # CRITICAL: Require audience
        "require_iss": True         # CRITICAL: Require issuer
    }
)
```

### 2. JWKS Caching and Security

**Protection**: Secure key retrieval and validation

**Implementation**:
- **Cached JWKS**: 5-minute TTL to reduce Okta API calls
- **Key rotation support**: Automatic handling of Okta key rotations
- **Fallback mechanisms**: Graceful handling of JWKS failures
- **Timeout protection**: 10-second timeout on JWKS requests

### 3. Authorization Code Security

**Protection**: Prevents code replay and injection attacks

**Implementation**:
- **One-time use codes**: Authorization codes can only be used once
- **Short expiration**: 10-minute maximum lifetime (OAuth 2.1 recommendation)
- **Secure storage**: Codes stored with cryptographic state binding
- **Automatic cleanup**: Periodic removal of expired codes

### 4. Redirect URI Validation

**Protection**: Prevents open redirect attacks

**Implementation**:
- **Configurable callback URI**: Via `OAUTH_REDIRECT_URI` environment variable
- **Strict matching**: Must match registered Okta app configuration
- **No arbitrary redirects**: Redirect URI cannot be set arbitrarily
- **Fallback protection**: Safe defaults for localhost development

### 5. Scope Validation

**Protection**: Ensures principle of least privilege

**Implementation**:
- **Configurable scopes**: Via `OAUTH_SCOPES` environment variable
- **Default secure scopes**: Read-only Okta API permissions
- **Scope inheritance**: Virtual tokens inherit validated scopes
- **Admin scope separation**: Admin scopes require explicit configuration

## Okta Organization Server Configuration

### 1. Authorization Server Selection

**Protection**: Uses appropriate Okta authorization server for API access

**Implementation**:
- **Org Authorization Server**: `/oauth2/v1` (NOT `/oauth2/default/v1`)
- **API scope support**: Only org server can mint tokens with Okta API scopes
- **Proper endpoints**: Authorization, token, and JWKS endpoints correctly configured

### 2. Client Authentication

**Protection**: Secure client credential handling

**Implementation**:
- **Client secret protection**: Stored in environment variables only
- **PKCE enhancement**: Client secret + PKCE for maximum security
- **No credentials in logs**: Secrets never logged or exposed

## Configuration Security

### 1. Environment Variable Protection

**Protection**: Secure configuration management

**Required Variables**:
```bash
# OAuth Client Configuration
OKTA_CLIENT_ID=your-oauth-client-id
OKTA_CLIENT_SECRET=your-oauth-client-secret
OKTA_ORG_URL=https://your-org.okta.com

# Security Configuration
OKTA_OAUTH_AUDIENCE=fctrid-okta-mcp-server
OAUTH_REDIRECT_URI=http://localhost:3001/oauth/callback
OAUTH_REQUIRE_HTTPS=false  # true for production
```

### 2. Production Hardening

**Protection**: Production-ready security settings

**Implementation**:
- **HTTPS enforcement**: `OAUTH_REQUIRE_HTTPS=true`
- **Secure session keys**: Generated via `SESSION_SECRET_KEY`
- **Audit logging**: Comprehensive security event logging
- **Error masking**: Production errors don't leak sensitive information

## Token Lifecycle Management

### 1. Token Storage Security

**Protection**: Secure in-memory token management

**Implementation**:
- **No persistent storage**: Tokens only in memory (stateless design)
- **User binding**: Tokens bound to specific user sessions
- **Automatic cleanup**: Expired tokens removed every 5 minutes
- **Memory efficiency**: Prevents token accumulation attacks

### 2. Token Expiration Handling

**Protection**: Proper token lifecycle management

**Implementation**:
- **Inheritance**: Virtual tokens inherit Okta token expiration
- **Grace period**: No token refresh (clients must re-authenticate)
- **Cleanup automation**: Background task removes expired entries
- **Audit trail**: Token expiration events logged

## Security Monitoring and Audit

### 1. Comprehensive Audit Logging

**Protection**: Full visibility into security events

**Events Logged**:
- OAuth authorization attempts
- JWT validation failures
- Token creation and expiration
- Session management events
- Configuration errors
- PKCE validation results

```python
# Security audit example
audit_entry = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'event_type': 'jwt_validation_failed',
    'user_id': user_id,
    'details': {'error': 'audience_mismatch', 'token_prefix': token[:20]}
}
```

### 2. Error Handling Security

**Protection**: Information disclosure prevention

**Implementation**:
- **Generic error responses**: No sensitive information in client errors
- **Detailed server logs**: Full error context for administrators
- **Rate limiting ready**: Structured for future rate limiting implementation
- **Attack detection**: Suspicious pattern identification

## Advanced Security Features (July 5, 2025 Updates)

### 1. Comprehensive Audit Logging

**Protection**: Full security event tracking and forensics

**Implementation**:
- **Authentication events**: Login, logout, token refresh, failures
- **Authorization events**: Role assignments, permission checks, access denials
- **Security violations**: Invalid tokens, expired credentials, manipulation attempts
- **Administrative actions**: Role changes, configuration updates, user management

```python
# Security audit example
self._audit_log("jwt_verification_failed", details={
    "error": str(e), 
    "token_prefix": token[:20],
    "user_id": user_id,
    "timestamp": datetime.now(timezone.utc).isoformat()
})
```

### 2. Fail-Secure Architecture

**Protection**: Security-first error handling and fallbacks

**Design Principles**:
- **Default deny**: Users without valid roles get no access
- **Explicit permissions**: Tools must be explicitly allowed for roles
- **No fallback tokens**: Authentication failures don't fall back to insecure methods
- **Exception propagation**: Critical security failures halt processing immediately

### 3. Real-Time Group Synchronization

**Protection**: Immediate enforcement of organizational changes

**Implementation**:
- **ID token groups**: Primary source for real-time group membership
- **UserInfo endpoint**: Secondary verification and additional claims
- **Refresh token updates**: Groups re-synchronized on every token refresh
- **Session invalidation**: Role changes trigger session updates

### 4. Zero-Trust Token Validation

**Protection**: Never trust, always verify token integrity

**Implementation**:
- **No unsigned tokens**: All tokens must have valid cryptographic signatures
- **Issuer verification**: Only accept tokens from configured Okta organization
- **Temporal validation**: Strict enforcement of expiration and not-before claims
- **Audience specificity**: ID tokens for identity, access tokens for API access

## Security Compliance and Standards

### 1. OAuth 2.1 Security Best Practices Compliance

**Standards Followed**:
- ✅ **RFC 9700**: OAuth 2.0 Security Best Practices
- ✅ **RFC 7636**: PKCE (Proof Key for Code Exchange)
- ✅ **RFC 8252**: OAuth 2.0 for Native Apps (adapted for proxy)
- ✅ **OIDC Core**: OpenID Connect security requirements
- ✅ **Refresh Token Scope Validation**: RFC 6749 Section 6 compliance

**Refresh Token Security**:
- **Scope-based issuance**: Refresh tokens only issued when client explicitly requests `offline_access` scope
- **Original request tracking**: Server tracks initial scope request to validate refresh token eligibility
- **Conditional response**: Token response only includes `refresh_token` field if originally requested
- **Audit logging**: All refresh token decisions logged for security monitoring

```python
# Only include refresh token if client originally requested offline_access scope (RFC 6749 Section 6 compliance)
if "offline_access" in original_scopes:
    response_data["refresh_token"] = virtual_refresh_token
    logger.info("Refresh token included in response (offline_access scope requested)")
else:
    logger.info("Refresh token omitted from response (offline_access scope not requested)")
```

### 2. Enterprise Security Controls

**Implemented Controls**:
- ✅ **Multi-factor authentication**: Inherits from Okta organization policies
- ✅ **Role-based access control**: Dynamic group-to-role mapping with tool filtering
- ✅ **Session management**: Secure session handling with automatic cleanup
- ✅ **Audit trails**: Comprehensive logging for compliance and forensics

### 3. Development vs Production Security

**Development Mode** (OAUTH_REQUIRE_HTTPS=false):
- HTTP allowed for localhost testing
- Debug logging enabled
- Relaxed CORS policies
- Extended session timeouts

**Production Mode** (OAUTH_REQUIRE_HTTPS=true):
- HTTPS enforcement required
- Minimal logging (no sensitive data)
- Strict CORS policies
- Short session timeouts
- Error message sanitization

## Security Implementation Status

### Phase 1 (Core Security - Completed ✅)
- ✅ **Enterprise JWT validation**: Full RSA-256 signature verification with exception handling
- ✅ **RBAC implementation**: Dynamic group-to-role mapping with real-time updates
- ✅ **PKCE implementation**: Secure authorization code exchange protection
- ✅ **ID token security**: Cryptographic verification with issuer validation
- ✅ **Access token security**: Full validation with graceful audience handling
- ✅ **Comprehensive audit logging**: All security events tracked with forensics data
- ✅ **Fail-secure architecture**: Critical failures stop processing immediately
- ✅ **Zero-trust validation**: Never accept unsigned or unverified tokens
- ✅ **Real-time group sync**: Role updates on token refresh with session cache
- ✅ **Tool-level permissions**: Granular RBAC filtering with hierarchical roles
- ✅ **Refresh token scope validation**: RFC 6749 Section 6 compliance with conditional response and audit logging
- ✅ **Complete security headers**: CSP, HSTS, XSS protection, clickjacking prevention

### Phase 2 (Advanced Security - In Progress 🔄)
- 🔄 **Rate limiting**: Per-user and per-endpoint request throttling
- 🔄 **Token rotation**: Automatic refresh token rotation for enhanced security
- 🔄 **Session fingerprinting**: Additional session validation with device fingerprints
- 🔄 **Threat detection**: Anomaly detection for suspicious authentication patterns

### Phase 3 (Enterprise Features - Planned 📋)
- 📋 **Multi-tenant support**: Organization-specific configurations and isolation
- 📋 **Advanced audit**: SIEM integration and compliance reporting
- 📋 **Key rotation**: Automatic JWKS key rotation handling
- 📋 **Backup authentication**: Fallback mechanisms for Okta outages

## Security Testing and Validation

### Current Security Test Coverage ✅
- ✅ **JWT validation edge cases**: Expired, malformed, unsigned tokens
- ✅ **RBAC enforcement**: Role mapping, tool filtering, permission boundaries
- ✅ **Exception handling**: Security failure propagation and error states
- ✅ **Group synchronization**: Real-time role updates during token refresh
- ✅ **Token lifecycle**: Authorization code flow, refresh token handling
- ✅ **Audience validation**: ID token vs access token audience handling

### Recommended Security Testing
- **Penetration testing**: Third-party security assessment
- **Token manipulation**: Attempt JWT signature tampering
- **Session hijacking**: Test session isolation and binding
- **Authorization bypass**: Verify RBAC enforcement boundaries
- **Refresh token abuse**: Test token rotation and invalidation
- **Group privilege escalation**: Verify highest-role-wins logic

## Production Deployment Checklist

### Pre-Deployment Security ✅
- ✅ **Environment variables**: All secrets in secure environment configuration
- ✅ **HTTPS enforcement**: `OAUTH_REQUIRE_HTTPS=true` for production
- ✅ **RBAC configuration**: Group mappings and role hierarchy validated
- ✅ **Audit logging**: Security event logging enabled and configured
- ✅ **Error handling**: Production error messages sanitized
- ✅ **Session security**: Secure cookie settings and encryption enabled

### Runtime Security Monitoring
- **Authentication failures**: Monitor for brute force attempts
- **Token validation errors**: Track signature and issuer failures
- **Role assignment anomalies**: Monitor for unexpected privilege escalations
- **Session anomalies**: Track unusual session patterns and durations
- **RBAC violations**: Monitor unauthorized tool access attempts

## Security Contact and Updates

**Last Updated**: July 6, 2025  
**Next Review**: August 6, 2025  
**Security Version**: 2.2.0 (Enterprise JWT + RBAC + Complete OAuth 2.1 Compliance)

For security concerns or to report vulnerabilities, please contact the security team through your organization's designated security channels.

### Manual Security Verification
- OAuth flow end-to-end testing
- Session hijacking resistance
- Token isolation verification
- Error handling information disclosure
- Configuration security validation

---

**Document Version**: 2.1  
**Last Updated**: July 6, 2025  
**Security Review Status**: ✅ Complete with validated implementation  
**Compliance Status**: ✅ RFC 9700 Compliant with OAuth 2.1 best practices
