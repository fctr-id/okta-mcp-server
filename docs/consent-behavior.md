# OAuth Consent Behavior in Okta MCP Server

## Current Implementation

The Okta MCP OAuth proxy currently uses the **Okta org authorization server** (`/oauth2/v1/`) to request both OpenID Connect scopes and Okta API scopes in a single flow.

### Requested Scopes
- **OpenID Connect**: `openid`, `profile`, `email`
- **Okta API**: `okta.users.read`, `okta.groups.read`, `okta.apps.read`, `okta.events.read`, `okta.logs.read`, `okta.policies.read`, `okta.devices.read`, `okta.factors.read`

## Consent Dialog Limitation

**Important**: Okta's hosted consent dialogs are only available with **custom authorization servers**, not the org authorization server. Since we need Okta API scopes (which require the org server), we cannot use Okta's built-in consent dialogs.

### Why No Consent Dialog?

1. **Okta API Scopes Requirement**: API scopes like `okta.users.read` can only be granted by the org authorization server
2. **Consent Feature Limitation**: Okta consent dialogs only work with custom authorization servers (`/oauth2/default/v1/` or `/oauth2/{custom-id}/v1/`)
3. **Architecture Choice**: We prioritized comprehensive API access over consent dialogs

## Current User Experience

Users will see:
1. **Okta Login Screen**: Standard username/password authentication
2. **MFA Prompt** (if enabled): Multi-factor authentication
3. **No Explicit Consent Dialog**: Users are redirected back to the app after authentication

The lack of a consent dialog means users grant all requested permissions implicitly upon successful authentication.

## Security Considerations

### Current Protections
- **PKCE**: Proof Key for Code Exchange prevents authorization code interception
- **State Parameter**: Prevents CSRF attacks
- **HTTPS**: All OAuth flows use encrypted connections
- **Token Validation**: Access tokens are validated before API access
- **Session Management**: Secure session handling with encrypted cookies

### Trust Model
This implementation assumes:
- **Trusted Application**: The MCP server is a first-party application
- **Informed Users**: Users understand they're granting API access
- **Controlled Environment**: Deployment in controlled/enterprise environments

## Alternative Approaches

### Option 1: Custom Consent Screen
Implement a custom consent screen in the proxy before OAuth redirect:

```
User → Custom Consent Page → Okta Auth → API Access
```

### Option 2: Hybrid Authorization Flow
Split into two flows:
1. **Custom server**: OpenID scopes with consent dialog
2. **Org server**: API scopes (no consent)

### Option 3: Scope-based Consent
Allow users to select which API scopes they want to grant.

## Implementation Examples

### Custom Consent Screen Integration
```python
@routes.get('/oauth/consent')
async def consent_screen(request):
    """Display custom consent screen before OAuth"""
    scopes = request.query.get('scopes', '').split()
    
    return web.Response(text=f"""
    <html><body>
        <h2>Grant Permissions</h2>
        <p>The MCP Server is requesting access to:</p>
        <ul>
            {''.join(f'<li>{scope}</li>' for scope in scopes)}
        </ul>
        <form action="/oauth/login" method="get">
            <button type="submit">Grant Access</button>
            <a href="/">Cancel</a>
        </form>
    </body></html>
    """, content_type='text/html')
```

### Scope Description Mapping
```python
SCOPE_DESCRIPTIONS = {
    'openid': 'Verify your identity',
    'profile': 'Access your basic profile information',
    'email': 'Access your email address',
    'okta.users.read': 'Read user information from your Okta org',
    'okta.groups.read': 'Read group information from your Okta org',
    'okta.apps.read': 'Read application information from your Okta org',
    # ... etc
}
```

## Recommendations

### For Production Deployments
1. **Document Permissions**: Clearly communicate what data access is granted
2. **Admin Consent**: Consider requiring admin pre-approval for API scopes
3. **Custom Consent**: Implement custom consent screen if user choice is required
4. **Audit Logging**: Log all OAuth grants and API access

### For Development/Testing
1. **Current Implementation**: Sufficient for testing and development
2. **Clear Documentation**: Ensure developers understand the trust model
3. **Environment Separation**: Use different apps for dev/test/prod

## Future Enhancements

If Okta extends consent dialog support to org authorization servers, we could:
1. **Enable Native Consent**: Configure consent for API scopes
2. **Granular Permissions**: Allow scope-level user choice
3. **Consent Management**: Provide consent revocation interfaces

## References

- [Okta OAuth Consent Documentation](https://developer.okta.com/docs/guides/request-user-consent/main/)
- [Authorization Servers Types](https://developer.okta.com/docs/concepts/auth-servers/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
