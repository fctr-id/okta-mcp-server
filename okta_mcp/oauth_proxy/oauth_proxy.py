#!/usr/bin/env python3
"""
FastMCP OAuth Proxy Server

This implementation combines FastMCP's proxy capabilities with OAuth 2.0 authentication.
It uses a standard OAuth library (Authlib) to handle the OAuth flow with Okta, 
and FastMCP's as_proxy() method to handle MCP protocol forwarding.

Architecture:
AI Client → OAuth Proxy Server → FastMCP Proxy → Backend MCP Server
                    ↕
                 Okta OAuth

This approach provides:
1. Standard OAuth 2.0 implementation using Authlib
2. Native FastMCP proxy capabilities
3. Clean separation of concerns
4. HTTP transport for OAuth endpoints
"""

import os
import asyncio
import logging
import secrets
import hashlib
import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import base64
from urllib.parse import urlencode
from cryptography.fernet import Fernet
import jwt  # PyJWT for token validation

from fastmcp import FastMCP
from aiohttp import web, ClientSession
# Note: Using httpx client for OAuth since aiohttp integration may not be available
import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from aiohttp_session import setup
from aiohttp_session.cookie_storage import EncryptedCookieStorage

# Import our custom OAuth configuration
from okta_mcp.auth.oauth_provider import OAuthConfig

logger = logging.getLogger("oauth_proxy")

class OAuthFastMCPProxy:
    """OAuth-protected FastMCP proxy server"""
    
    def __init__(self, backend_server_path: str = "./main.py"):
        self.backend_server_path = backend_server_path
        self.config = OAuthConfig.from_environment()
        self.mcp = FastMCP("okta-oauth-proxy")
        
        # Security enhancements
        self.session_secret = self._generate_secure_session_key()
        self.state_store = {}  # In-memory store for OAuth state (production should use Redis/DB)
        
        # Security headers for production
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY', 
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        # OAuth client setup using Authlib with httpx
        self.oauth_client = AsyncOAuth2Client(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            scope=' '.join(self.config.get_all_scopes())
        )
        
        # Session and token storage
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.tokens: Dict[str, Dict[str, Any]] = {}
        
        # Virtual client registry and consent tracking
        self.virtual_clients: Dict[str, Dict[str, Any]] = {}
        self.user_consents: Dict[str, Dict[str, Any]] = {}  # user_id -> {client_id -> consent_data}
        
        # Create FastMCP proxy
        self.mcp_proxy = FastMCP.as_proxy(
            backend_server_path,
            name="OktaOAuthMCPProxy"
        )
        
        # Setup combined HTTP server with session support
        self.app = web.Application()
        
        # Add security middleware first
        self.app.middlewares.append(self.security_middleware)
        
        # Setup encrypted cookie session storage with secure settings
        from aiohttp_session.cookie_storage import EncryptedCookieStorage
        
        # For aiohttp-session, we need raw bytes, not Fernet key
        session_key = secrets.token_bytes(32)  # 32 bytes for AES-256
        
        storage = EncryptedCookieStorage(
            session_key,  # Use raw bytes for aiohttp-session
            cookie_name='AIOHTTP_SESSION',
            domain=None,
            max_age=7200,  # 2 hours
            path='/',
            secure=False,  # Set to True in production with HTTPS
            httponly=True,  # Prevent XSS access to session cookie
            samesite='Lax'
        )
        setup(self.app, storage)
        
        # Also maintain a simple in-memory store as backup
        self.state_store: Dict[str, Dict[str, Any]] = {}
        
        self._setup_oauth_routes()
        self._setup_mcp_routes()
        
    def _generate_secure_session_key(self) -> bytes:
        """Generate cryptographically secure session key"""
        # Use environment variable if provided, otherwise generate
        key_env = os.getenv('SESSION_SECRET_KEY')
        if key_env:
            try:
                return base64.b64decode(key_env.encode())
            except Exception as e:
                logger.warning(f"Invalid SESSION_SECRET_KEY format, generating new key: {e}")
        
        # Generate new Fernet key (already 32 bytes, base64-encoded)
        key = Fernet.generate_key()
        logger.warning(f"Generated new session key. For production, set SESSION_SECRET_KEY={key.decode()}")
        return key
    
    def _generate_secure_state(self) -> str:
        """Generate cryptographically secure OAuth state parameter"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    def _generate_secure_code_verifier(self) -> str:
        """Generate cryptographically secure PKCE code verifier"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    def _create_user_bound_session_key(self, user_id: str, session_id: str) -> str:
        """Create session key bound to user information (MCP security best practice)"""
        return f"{user_id}:{session_id}"
    
    def _create_401_response(self, request: web.Request, error_description: str) -> web.Response:
        """Create RFC 6750 compliant 401 response with WWW-Authenticate header"""
        resource_metadata_url = f"{request.scheme}://{request.host}/.well-known/oauth-protected-resource"
        www_authenticate = f'Bearer realm="Okta MCP Server", resource_metadata="{resource_metadata_url}"'
        
        return web.json_response(
            {"error": "invalid_token", "error_description": error_description},
            status=401,
            headers={
                "WWW-Authenticate": www_authenticate,
                **self.security_headers,
                "Access-Control-Allow-Origin": "*"
            }
        )
    
    def _validate_token_audience(self, token: Dict[str, Any]) -> bool:
        """Validate that token was issued for this MCP server"""
        token_audience = token.get('aud')
        
        # For Okta's org authorization server, the audience is typically the org URL
        # even when a custom audience is requested. This is expected behavior.
        # We accept both the configured audience and the Okta org URL as valid.
        valid_audiences = [
            self.config.audience,           # Custom audience (if configured)
            self.config.org_url,           # Okta org URL (default for org auth server)
            f"https://{self.config.okta_domain}"  # Alternative format
        ]
        
        # Remove None values and duplicates
        valid_audiences = list(set([aud for aud in valid_audiences if aud]))
        
        if token_audience not in valid_audiences:
            logger.error(f"Token audience mismatch. Expected one of: {valid_audiences}, Got: {token_audience}")
            return False
            
        logger.info(f"Token audience validation successful: {token_audience}")
        return True
    
    def _audit_log(self, event_type: str, user_id: str = None, details: Dict[str, Any] = None):
        """Security audit logging"""
        audit_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'details': details or {}
        }
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")
    
    def _has_user_consent(self, user_id: str, virtual_client_id: str) -> bool:
        """Check if user has granted consent for a specific virtual client"""
        user_consents = self.user_consents.get(user_id, {})
        consent_data = user_consents.get(virtual_client_id)
        
        if not consent_data:
            return False
        
        # Check if consent is still valid (not expired)
        consent_expires = consent_data.get('expires_at')
        if consent_expires:
            expires_dt = datetime.fromisoformat(consent_expires.replace('Z', '+00:00'))
            if datetime.now(timezone.utc) > expires_dt:
                logger.info(f"Consent expired for user {user_id}, client {virtual_client_id}")
                return False
        
        return True
    
    def _grant_user_consent(self, user_id: str, virtual_client_id: str, scopes: list, consent_duration_hours: int = 24):
        """Grant user consent for a specific virtual client"""
        if user_id not in self.user_consents:
            self.user_consents[user_id] = {}
        
        expires_at = datetime.now(timezone.utc) + timedelta(hours=consent_duration_hours)
        
        self.user_consents[user_id][virtual_client_id] = {
            'granted_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': expires_at.isoformat(),
            'scopes': scopes,
            'client_name': self.virtual_clients.get(virtual_client_id, {}).get('client_name', 'Unknown')
        }
        
        self._audit_log('consent_granted', user_id, {
            'virtual_client_id': virtual_client_id,
            'scopes': scopes,
            'expires_at': expires_at.isoformat()
        })
    
    def _revoke_user_consent(self, user_id: str, virtual_client_id: str):
        """Revoke user consent for a specific virtual client"""
        if user_id in self.user_consents and virtual_client_id in self.user_consents[user_id]:
            del self.user_consents[user_id][virtual_client_id]
            
            self._audit_log('consent_revoked', user_id, {
                'virtual_client_id': virtual_client_id
            })
    
    def _get_user_from_session(self, request: web.Request) -> Optional[str]:
        """Extract user ID from session - helper method for consent checks"""
        # This is a simplified version - in a real implementation, you'd verify the session token
        # and extract the user ID from the validated JWT token or session store
        user_token = None
        
        # Try to get from session cookie or authorization header
        if hasattr(request, 'headers') and 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                user_token = auth_header[7:]
        
        if user_token and user_token in self.tokens:
            token_data = self.tokens[user_token]
            return token_data.get('sub')  # User ID from token
        
        return None

    def _setup_oauth_routes(self):
        """Setup OAuth authentication routes"""
        self.app.router.add_get("/", self.home)
        self.app.router.add_post("/", self.handle_post_root)
        self.app.router.add_get("/health", self.health_check)
        
        # OAuth discovery endpoints (RFC 8414) with CORS support
        self.app.router.add_route('*', '/.well-known/oauth-protected-resource', self.oauth_protected_resource_metadata)
        self.app.router.add_route('*', '/.well-known/oauth-authorization-server', self.oauth_authorization_server_metadata)
        self.app.router.add_route('*', '/.well-known/jwks.json', self.oauth_jwks_proxy)
        
        # OAuth routes
        self.app.router.add_get('/oauth/permissions', self.permissions_info)
        self.app.router.add_get('/oauth/consent', self.consent_page)
        self.app.router.add_post('/oauth/consent', self.handle_consent)
        self.app.router.add_get('/oauth/login', self.oauth_login)
        self.app.router.add_get('/oauth/callback', self.oauth_callback)
        self.app.router.add_get('/oauth/status', self.oauth_status)
        self.app.router.add_get('/oauth/logout', self.oauth_logout)
        
        # Dynamic Client Registration endpoint (for MCP Inspector etc.)
        self.app.router.add_post('/oauth2/v1/clients', self.oauth_register_client)
        self.app.router.add_options('/oauth2/v1/clients', self.oauth_register_client)
        
        # Authorization endpoint proxy (maps virtual client IDs to real client ID)
        self.app.router.add_get('/oauth2/v1/authorize', self.oauth_authorize_proxy)
        
        # Token endpoint proxy (maps virtual client IDs to real client ID)
        self.app.router.add_post('/oauth2/v1/token', self.oauth_token_proxy)
        self.app.router.add_options('/oauth2/v1/token', self.oauth_token_proxy)
        
        # OAuth endpoints for virtual clients (maps to real Okta endpoints)
        self.app.router.add_get('/oauth/authorize', self.oauth_authorize_virtual)
        self.app.router.add_post('/oauth/token', self.oauth_token_virtual)
        self.app.router.add_get('/oauth/userinfo', self.oauth_userinfo_virtual)
        
    def _setup_mcp_routes(self):
        """Setup MCP proxy routes with OAuth protection"""
        # Protected MCP endpoints
        self.app.router.add_get("/mcp/tools", self.protected_mcp_tools)
        self.app.router.add_post("/mcp/tools/call", self.protected_mcp_call)
        self.app.router.add_get("/mcp/resources", self.protected_mcp_resources)
        self.app.router.add_post("/mcp/resources/read", self.protected_mcp_read_resource)
        self.app.router.add_get("/mcp/prompts", self.protected_mcp_prompts)
        
    async def home(self, request: web.Request) -> web.Response:
        """Home page with OAuth status and MCP info"""
        user_info = await self.get_user_from_request(request)
        
        if user_info:
            html = f"""
            <html>
            <head><title>Okta MCP OAuth Proxy</title></head>
            <body style="font-family: Arial; margin: 50px;">
                <h1>🔐 Okta MCP OAuth Proxy</h1>
                <div style="background: #e8f5e8; padding: 20px; margin: 20px 0;">
                    <h3>✅ Authenticated</h3>
                    <p><strong>User:</strong> {user_info.get('email', 'Unknown')}</p>
                    <p><strong>Name:</strong> {user_info.get('name', 'Unknown')}</p>
                    <p><strong>Scopes:</strong> {', '.join(user_info.get('scopes', []))}</p>
                </div>
                <h3>Available MCP Endpoints:</h3>
                <ul>
                    <li><a href="/mcp/tools">GET /mcp/tools</a> - List available tools</li>
                    <li>POST /mcp/tools/call - Call a tool</li>
                    <li><a href="/mcp/resources">GET /mcp/resources</a> - List resources</li>
                    <li>POST /mcp/resources/read - Read a resource</li>
                    <li><a href="/mcp/prompts">GET /mcp/prompts</a> - List prompts</li>
                </ul>
                <form method="post" action="/oauth/logout">
                    <button type="submit">Logout</button>
                </form>
            </body>
            </html>
            """
        else:
            html = """
            <html>
            <head><title>Okta MCP OAuth Proxy</title></head>
            <body style="font-family: Arial; margin: 50px;">
                <h1>🔐 Okta MCP OAuth Proxy</h1>
                <p>Please authenticate to access MCP endpoints.</p>
                <p><a href="/oauth/permissions" style="margin-right: 15px;">View Permissions</a></p>
                <a href="/oauth/login"><button>Login with Okta</button></a>
            </body>
            </html>
            """
        
        return web.Response(text=html, content_type="text/html")
        
    async def handle_post_root(self, request: web.Request) -> web.Response:
        """Handle POST requests to root endpoint (required for Claude Desktop/MCP CLI)"""
        user_info = await self.get_user_from_request(request)
        if not user_info:
            return self._create_401_response(request, "Authentication required for MCP requests")
            
        try:
            # This is likely an MCP protocol request from Claude Desktop or MCP CLI
            # Forward it to the underlying MCP proxy server
            logger.info(f"POST / request from {user_info.get('email', 'unknown')} - forwarding to MCP server")
            
            # Get the request body
            request_data = await request.json()
            
            # Add user context to the request for audit/security
            if isinstance(request_data, dict):
                request_data["_oauth_context"] = {
                    "user_id": user_info.get("user_id"),
                    "email": user_info.get("email"),
                    "scopes": user_info.get("scopes", [])
                }
            
            # Forward to the MCP proxy server
            # Note: This is a simplified implementation - a full implementation would
            # need to handle the complete MCP protocol specification
            
            return web.json_response({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {}
                    },
                    "serverInfo": {
                        "name": "Okta MCP OAuth Proxy",
                        "version": "1.0.0"
                    }
                },
                "id": request_data.get("id") if isinstance(request_data, dict) else None
            })
            
        except Exception as e:
            logger.error(f"POST / request failed: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                },
                "id": None
            }, status=500)
        
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        base_url = f"{request.scheme}://{request.host}"
        
        return web.json_response({
            "status": "healthy",
            "oauth_configured": bool(self.config.client_id),
            "mcp_backend": self.backend_server_path,
            "timestamp": datetime.utcnow().isoformat(),
            "oauth_discovery": {
                "protected_resource": f"{base_url}/.well-known/oauth-protected-resource",
                "authorization_server": f"{base_url}/.well-known/oauth-authorization-server", 
                "jwks": f"{base_url}/.well-known/jwks.json"
            },
            "mcp_endpoints": {
                "tools": f"{base_url}/mcp/tools",
                "resources": f"{base_url}/mcp/resources",
                "prompts": f"{base_url}/mcp/prompts"
            }
        })
        
    async def oauth_login(self, request: web.Request) -> web.Response:
        """Initiate OAuth login flow with PKCE"""
        try:
            from aiohttp_session import get_session
            session = await get_session(request)
            
            # Generate state and code verifier for PKCE
            state = secrets.token_urlsafe(64)
            code_verifier = secrets.token_urlsafe(64)
            
            # Calculate code challenge (PKCE)
            hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
            encoded = base64.urlsafe_b64encode(hashed)
            code_challenge = encoded.decode('ascii').strip('=')
            
            # Store in session
            session['app_state'] = state
            session['code_verifier'] = code_verifier
            
            # Also store in backup memory store using state as key
            self.state_store[state] = {
                'code_verifier': code_verifier,
                'created_at': datetime.now(timezone.utc),
                'user_agent': request.headers.get("User-Agent", "")
            }
            
            logger.info(f"Storing in session - State: {state}, Code verifier length: {len(code_verifier)}")
            logger.info(f"Backup store now has {len(self.state_store)} entries")
            
            # Use configured redirect URI or fallback to request-based construction
            redirect_uri = self.config.redirect_uri or str(request.url.with_path("/oauth/callback"))
            
            # Create authorization URL with PKCE
            auth_params = {
                "client_id": self.config.client_id,
                "response_type": "code",
                "scope": " ".join(self.config.get_all_scopes()),
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "response_mode": "query"
            }
            
            # Add audience parameter if configured (CRITICAL for JWT audience validation)
            if self.config.audience:
                auth_params["audience"] = self.config.audience
                logger.info(f"Including audience in authorization request: {self.config.audience}")
            
            auth_url = f"{self.config.authorization_url}?{urlencode(auth_params)}"
            
            logger.info(f"Initiating OAuth flow with PKCE. State: {state}")
            
            # Create response with redirect
            response = web.Response(status=302, headers={"Location": auth_url})
            
            # Force session to be saved by setting a dummy value and removing it
            session['_force_save'] = True
            del session['_force_save']
            
            return response
            
        except Exception as e:
            logger.error(f"OAuth login failed: {e}")
            import traceback
            traceback.print_exc()
            return web.json_response({"error": str(e)}, status=500)
            
    async def oauth_callback(self, request: web.Request) -> web.Response:
        """Handle OAuth callback with PKCE"""
        try:
            # Check if this is a proxied callback for MCP Inspector
            received_state = request.query.get("state")
            logger.info(f"Callback received with state: {received_state}")
            logger.info(f"State store contents: {list(self.state_store.keys())}")
            
            if received_state and received_state in self.state_store:
                stored_data = self.state_store[received_state]
                original_redirect_uri = stored_data.get('original_redirect_uri')
                original_state = stored_data.get('original_state')
                
                logger.info(f"Found stored data for state {received_state}: {stored_data}")
                
                if original_redirect_uri and ('127.0.0.1' in original_redirect_uri or 'localhost' in original_redirect_uri):
                    # This is a proxied callback, forward to the virtual client
                    logger.info(f"Proxying callback to virtual client: {original_redirect_uri}")
                    
                    # Build query parameters for MCP Inspector
                    callback_params = dict(request.query)
                    
                    # If original request had no state, don't include it in callback
                    if original_state is None:
                        callback_params.pop('state', None)
                        logger.info("Removing state parameter for virtual client (original had no state)")
                    else:
                        callback_params['state'] = original_state
                        logger.info(f"Using original state for virtual client: {original_state}")
                    
                    # Forward to virtual client
                    from urllib.parse import urlencode
                    query_string = urlencode(callback_params)
                    final_redirect = f"{original_redirect_uri}?{query_string}"
                    
                    logger.info(f"Final redirect URL: {final_redirect}")
                    
                    # Store the authorization code from Okta for PKCE verification during token exchange
                    auth_code = request.query.get('code')
                    if auth_code:
                        # SECURITY FIX: Add proper expiration for authorization codes (OAuth 2.1 recommends 10 minutes max)
                        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
                        
                        # Map the Okta authorization code to our stored PKCE verifier
                        self.state_store[auth_code] = {
                            'virtual_client_id': stored_data.get('virtual_client_id'),
                            'code_verifier': stored_data.get('code_verifier'),
                            'original_state': received_state,
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'expires_at': expires_at.isoformat(),  # SECURITY FIX: Add expiration
                            'used': False  # SECURITY FIX: Track if code has been used
                        }
                        logger.info(f"Stored PKCE verifier for Okta auth code {auth_code} (expires: {expires_at})")
                    
                    # Clean up the original state entry (but keep the auth code mapping)
                    del self.state_store[received_state]
                    
                    return web.Response(status=302, headers={'Location': final_redirect})
            
            logger.info("Processing as regular OAuth callback for web interface")
            # Regular OAuth callback handling for web interface
            from aiohttp_session import get_session
            session = await get_session(request)
            
            logger.info(f"OAuth callback - Session contents: {dict(session)}")
            
            # Check for OAuth errors
            if "error" in request.query:
                error = request.query["error"]
                logger.error(f"OAuth callback error: {error}")
                return web.json_response({"error": error}, status=400)
            
            # Verify state parameter
            received_state = request.query.get("state")
            session_state = session.get("app_state")
            
            logger.info(f"State comparison - Received: {received_state}, Session: {session_state}")
            logger.info(f"Backup store has {len(self.state_store)} entries")
            
            # Try to get code verifier from session first, then backup store
            code_verifier = session.get("code_verifier")
            
            if not received_state:
                return web.json_response({"error": "Missing state parameter"}, status=400)
            
            # If session doesn't have the state, try backup store
            if received_state != session_state:
                logger.info("Session state mismatch, checking backup store...")
                if received_state in self.state_store:
                    stored_data = self.state_store[received_state]
                    code_verifier = stored_data['code_verifier']
                    logger.info("Found state in backup store, using stored code verifier")
                else:
                    logger.error(f"State not found in session or backup store! Received: {received_state}")
                    return web.json_response({
                        "error": "Invalid state parameter",
                        "received_state": received_state,
                        "session_state": session_state,
                        "backup_store_keys": list(self.state_store.keys()),
                        "session_contents": dict(session)
                    }, status=400)
            
            # Get authorization code
            code = request.query.get("code")
            if not code:
                return web.json_response({"error": "Missing authorization code"}, status=400)
            
            if not code_verifier:
                logger.error("Missing code verifier in both session and backup store")
                return web.json_response({"error": "Missing code verifier"}, status=400)
            
            # Exchange code for token using PKCE
            redirect_uri = str(request.url.with_query(None))
            
            token_data = {
                "grant_type": "authorization_code",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier
            }
            
            # Add audience parameter if configured (CRITICAL for JWT audience validation)
            if self.config.audience:
                token_data["audience"] = self.config.audience
                logger.info(f"Including audience in token request: {self.config.audience}")
            
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.config.token_url, 
                    data=token_data,
                    headers=headers
                )
                
                if response.status_code != 200:
                    logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                    return web.json_response({"error": f"Token exchange failed: {response.text}"}, status=500)
                
                token = response.json()
            
            # Validate token type
            if not token.get("token_type") or token.get("token_type").lower() != "bearer":
                return web.json_response({"error": "Unsupported token type"}, status=403)
            
            # Parse user info from token and fetch additional info from userinfo endpoint
            access_token = token.get("access_token")
            
            # SECURITY FIX: Properly validate JWT with signature verification
            decoded_token = self._verify_and_decode_jwt(access_token)
            if not decoded_token:
                self._audit_log("token_validation_failed", details={"reason": "jwt_verification_failed"})
                return web.json_response({"error": "Invalid or expired token"}, status=403)
            
            # Additional audience validation (defense in depth)
            if not self._validate_token_audience(decoded_token):
                self._audit_log("token_validation_failed", details={"reason": "invalid_audience"})
                return web.json_response({"error": "Invalid token audience"}, status=403)
            
            user_info = await self._get_user_info_comprehensive(access_token)
            
            # Store user info in session
            session['authenticated'] = True
            session['user_info'] = user_info
            session['access_token'] = access_token
            session['token_expires_at'] = (datetime.now(timezone.utc) + timedelta(seconds=token.get("expires_in", 3600))).isoformat()
            
            # Process pending consent if this was part of a virtual client authorization flow
            pending_consent = session.get('pending_consent')
            if pending_consent:
                user_id = user_info.get('user_id')
                virtual_client_id = pending_consent.get('virtual_client_id')
                scopes = pending_consent.get('scope', [])
                redirect_uri = pending_consent.get('redirect_uri')
                state = pending_consent.get('state')
                
                logger.info(f"Finalizing consent for user {user_id}, virtual client {virtual_client_id}")
                
                # Grant consent now that we have authenticated user
                if user_id and virtual_client_id:
                    self._grant_user_consent(user_id, virtual_client_id, scopes)
                    
                    # Generate an authorization code for the virtual client
                    auth_code = self._generate_secure_state()  # Use same secure random generation
                    
                    # Get the stored code_verifier from the OAuth state
                    stored_data = self.state_store.get(received_state, {})
                    code_verifier = stored_data.get('code_verifier')
                    
                    # Store the authorization code temporarily for token exchange
                    self.state_store[auth_code] = {
                        'virtual_client_id': virtual_client_id,
                        'user_id': user_id,
                        'scopes': scopes,
                        'redirect_uri': redirect_uri,
                        'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                        'access_token': access_token,  # Store the actual Okta access token
                        'code_verifier': code_verifier  # Store the code verifier for PKCE
                    }
                    
                    logger.info(f"Generated authorization code {auth_code} for virtual client {virtual_client_id} with code_verifier")
                    
                    # Clear pending consent from session
                    session.pop('pending_consent', None)
                    
                    # Redirect back to the virtual client with authorization code
                    if redirect_uri:
                        callback_params = {
                            'code': auth_code,
                            'state': state
                        }
                        callback_query = urlencode({k: v for k, v in callback_params.items() if v})
                        final_redirect = f"{redirect_uri}?{callback_query}"
                        
                        logger.info(f"Redirecting to virtual client: {final_redirect}")
                        
                        return web.Response(status=302, headers={'Location': final_redirect})
                    else:
                        # No redirect URI, show success page
                        return web.Response(
                            text=f"<html><body><h2>Authorization Successful</h2><p>You have successfully authorized {virtual_client_id}</p></body></html>",
                            content_type='text/html'
                        )
            
            # Clear OAuth flow data from both session and backup store
            session.pop('app_state', None)
            session.pop('code_verifier', None)
            self.state_store.pop(received_state, None)
            
            logger.info(f"OAuth authentication successful for: {user_info.get('email', 'unknown')}")
            
            # Audit log successful authentication
            self._audit_log("oauth_authentication_success", 
                          user_id=user_info.get('user_id'),
                          details={
                              "email": user_info.get('email'),
                              "scopes": user_info.get('scopes', [])
                          })
            
            # Redirect to home page
            return web.Response(status=302, headers={"Location": "/"})
            
        except Exception as e:
            logger.error(f"OAuth callback failed: {e}")
            import traceback
            traceback.print_exc()
            return web.json_response({"error": str(e)}, status=500)
            
    async def oauth_status(self, request: web.Request) -> web.Response:
        """Get OAuth authentication status"""
        user_info = await self.get_user_from_request(request)
        
        if user_info:
            return web.json_response({
                "authenticated": True,
                "user": {
                    "email": user_info.get("email"),
                    "name": user_info.get("name"),
                    "user_id": user_info.get("user_id"),
                    "scopes": user_info.get("scopes", [])
                }
            })
        else:
            return web.json_response({"authenticated": False})
            
    async def oauth_logout(self, request: web.Request) -> web.Response:
        """Logout and clear session"""
        try:
            from aiohttp_session import get_session
            session = await get_session(request)
            
            # Clear all session data
            session.clear()
            
            return web.Response(status=302, headers={"Location": "/"})
            
        except Exception as e:
            logger.error(f"OAuth logout failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
        
    async def _get_user_info_comprehensive(self, access_token: str) -> Dict[str, Any]:
        """Get comprehensive user information from both JWT token and UserInfo endpoint"""
        try:
            # First get info from JWT token
            jwt_info = self._extract_user_info(access_token)
            
            # Then fetch additional user profile info from UserInfo endpoint
            userinfo_endpoint = f"https://{self.config.okta_domain}/oauth2/v1/userinfo"
            
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.get(userinfo_endpoint, headers=headers)
                
                if response.status_code == 200:
                    userinfo_data = response.json()
                    logger.info(f"UserInfo endpoint response: {userinfo_data}")
                    
                    # Merge JWT info with UserInfo data, preferring UserInfo for profile data
                    comprehensive_info = {
                        "user_id": userinfo_data.get("sub") or jwt_info.get("user_id"),
                        "email": userinfo_data.get("email") or jwt_info.get("email"),
                        "name": userinfo_data.get("name") or jwt_info.get("name"),
                        "given_name": userinfo_data.get("given_name"),
                        "family_name": userinfo_data.get("family_name"),
                        "preferred_username": userinfo_data.get("preferred_username"),
                        "roles": jwt_info.get("roles", []),  # Usually only in JWT
                        "scopes": jwt_info.get("scopes", []),  # Usually only in JWT
                        "audience": jwt_info.get("audience"),
                        "issuer": jwt_info.get("issuer"),
                        "auth_time": jwt_info.get("auth_time"),
                        "client_id": jwt_info.get("client_id")
                    }
                    
                    # If name is still empty, try to construct it
                    if not comprehensive_info["name"]:
                        given = comprehensive_info.get("given_name", "")
                        family = comprehensive_info.get("family_name", "")
                        if given or family:
                            comprehensive_info["name"] = f"{given} {family}".strip()
                        elif comprehensive_info.get("preferred_username"):
                            comprehensive_info["name"] = comprehensive_info["preferred_username"]
                        elif comprehensive_info.get("email"):
                            # Extract name from email as fallback
                            email_name = comprehensive_info["email"].split("@")[0].replace(".", " ").title()
                            comprehensive_info["name"] = email_name
                    
                    logger.info(f"Comprehensive user info: {comprehensive_info}")
                    return comprehensive_info
                else:
                    logger.warning(f"UserInfo endpoint failed: {response.status_code} - {response.text}")
                    # Fall back to JWT-only info
                    return jwt_info
                    
        except Exception as e:
            logger.error(f"Failed to get comprehensive user info: {e}")
            import traceback
            traceback.print_exc()
            # Fall back to JWT-only info
            return self._extract_user_info(access_token)

    def _extract_user_info(self, access_token: str) -> Dict[str, Any]:
        """Extract user information from JWT access token with PROPER SECURITY VALIDATION"""
        try:
            # SECURITY FIX: Properly verify JWT signature and claims
            decoded = self._verify_and_decode_jwt(access_token)
            if not decoded:
                logger.error("JWT verification failed")
                return self._get_fallback_user_info()
            
            logger.info(f"JWT token contents: {decoded}")
            
            # Get user info from JWT claims
            user_id = decoded.get("sub")  # Subject - usually user identifier
            email = decoded.get("email") or decoded.get("preferred_username") or user_id
            
            # Try to get name from various possible claims
            name = decoded.get("name")
            if not name:
                given_name = decoded.get("given_name", "")
                family_name = decoded.get("family_name", "")
                if given_name or family_name:
                    name = f"{given_name} {family_name}".strip()
                else:
                    # If no name found, try to extract from email
                    if email and "@" in str(email):
                        name = str(email).split("@")[0].replace(".", " ").title()
                    else:
                        name = "Unknown User"
            
            # Get scopes - can be array or space-separated string
            scopes = decoded.get("scp", [])
            if isinstance(scopes, str):
                scopes = scopes.split()
            if not scopes:
                # Try alternative scope claim
                scope_str = decoded.get("scope", "")
                scopes = scope_str.split() if scope_str else []
            
            user_info = {
                "user_id": user_id,
                "email": email,
                "name": name,
                "roles": decoded.get("groups", []) or decoded.get("roles", []),
                "scopes": scopes,
                "audience": decoded.get("aud"),
                "issuer": decoded.get("iss"),
                "auth_time": decoded.get("auth_time"),
                "client_id": decoded.get("cid")
            }
            
            logger.info(f"Extracted user info: {user_info}")
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to extract user info: {e}")
            import traceback
            traceback.print_exc()
            return {
                "user_id": "unknown",
                "email": "unknown@example.com",
                "name": "Unknown User",
                "roles": [],
                "scopes": [],
                "audience": None,
                "issuer": None
            }
            
    async def get_user_from_request(self, request: web.Request) -> Optional[Dict[str, Any]]:
        """Get authenticated user from session or Bearer token with enhanced security validation"""
        try:
            # First, check for Bearer token in Authorization header (for virtual clients)
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
                
                # Check if this is a virtual access token
                if token in self.tokens:
                    token_data = self.tokens[token]
                    
                    # Check if token has expired
                    created_at = datetime.fromisoformat(token_data.get('created_at'))
                    expires_in = token_data.get('expires_in', 3600)
                    if datetime.now(timezone.utc) > created_at + timedelta(seconds=expires_in):
                        # Token expired, clean it up
                        del self.tokens[token]
                        self._audit_log("virtual_token_expired", user_id=token_data.get('user_id'))
                        return None
                    
                    # Return user info from virtual token (SECURITY FIX: Use stored user data)
                    user_info = {
                        'user_id': token_data.get('user_id'),
                        'email': token_data.get('email'),
                        'name': token_data.get('name'),
                        'scopes': token_data.get('scopes', []),
                        'virtual_client_id': token_data.get('virtual_client_id'),
                        'auth_method': 'virtual_token'
                    }
                    
                    # SECURITY: Ensure we have valid user identification
                    if not user_info.get('user_id') or not user_info.get('email'):
                        logger.error(f"Virtual token {token[:20]}... missing user identification")
                        del self.tokens[token]
                        self._audit_log("invalid_virtual_token", details={"token_prefix": token[:20]})
                        return None
                    
                    self._audit_log("virtual_token_access", user_id=token_data.get('user_id'), details={
                        'virtual_client_id': token_data.get('virtual_client_id'),
                        'path': request.path
                    })
                    
                    return user_info
            
            # Fall back to session-based authentication
            from aiohttp_session import get_session
            session = await get_session(request)
            
            if not session.get("authenticated"):
                self._audit_log("authentication_required", details={"path": request.path})
                return None
                
            user_info = session.get("user_info")
            if not user_info:
                self._audit_log("session_invalid", details={"reason": "missing_user_info"})
                return None
                
            # Check token expiration
            expires_at_str = session.get("token_expires_at")
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str)
                if datetime.now(timezone.utc) > expires_at:
                    self._audit_log("token_expired", user_id=user_info.get('user_id'))
                    # Token expired, clear session
                    session.clear()
                    return None
                    
            # Additional security: validate user_id consistency
            if not user_info.get('user_id'):
                self._audit_log("session_invalid", details={"reason": "missing_user_id"})
                return None
                
            # Mark as session-based auth
            user_info['auth_method'] = 'session'
                
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to get user from request: {e}")
            self._audit_log("session_validation_error", details={"error": str(e)})
            return None
            
    # Protected MCP endpoints
    
    async def protected_mcp_tools(self, request: web.Request) -> web.Response:
        """List MCP tools (OAuth protected)"""
        user_info = await self.get_user_from_request(request)
        if not user_info:
            return self._create_401_response(request, "Authentication required to access MCP tools")
            
        try:
            # Get tools from FastMCP proxy
            tools = await self.mcp_proxy.list_tools()
            tools_data = [tool.model_dump() if hasattr(tool, 'model_dump') else {"name": str(tool)} for tool in tools]
            
            return web.json_response({
                "tools": tools_data,
                "user": user_info.get("email"),
                "count": len(tools_data)
            })
            
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_call(self, request: web.Request) -> web.Response:
        """Call MCP tool (OAuth protected)"""
        user_info = await self.get_user_from_request(request)
        if not user_info:
            return self._create_401_response(request, "Authentication required to call MCP tools")
            
        try:
            data = await request.json()
            tool_name = data.get("name")
            arguments = data.get("arguments", {})
            
            if not tool_name:
                return web.json_response({"error": "Tool name required"}, status=400)
                
            # Add user context to arguments
            arguments["_oauth_user"] = user_info
            
            # Call tool via FastMCP proxy
            result = await self.mcp_proxy.call_tool(tool_name, arguments)
            
            logger.info(f"Tool '{tool_name}' called by {user_info.get('email', 'unknown')}")
            
            return web.json_response({
                "result": result,
                "user": user_info.get("email"),
                "tool": tool_name
            })
            
        except Exception as e:
            logger.error(f"Failed to call tool: {e}")
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_resources(self, request: web.Request) -> web.Response:
        """List MCP resources (OAuth protected)"""
        user_info = await self.get_user_from_request(request)
        if not user_info:
            return self._create_401_response(request, "Authentication required to access MCP resources")
            
        try:
            # Get resources from FastMCP proxy
            resources = await self.mcp_proxy.list_resources()
            resources_data = [res.model_dump() if hasattr(res, 'model_dump') else {"uri": str(res)} for res in resources]
            
            return web.json_response({
                "resources": resources_data,
                "user": user_info.get("email"),
                "count": len(resources_data)
            })
            
        except Exception as e:
            logger.error(f"Failed to list resources: {e}")
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_read_resource(self, request: web.Request) -> web.Response:
        """Read MCP resource (OAuth protected)"""
        user_info = await self.get_user_from_request(request)
        if not user_info:
            return self._create_401_response(request, "Authentication required to read MCP resources")
            
        try:
            data = await request.json()
            uri = data.get("uri")
            
            if not uri:
                return web.json_response({"error": "Resource URI required"}, status=400)
                
            # Read resource via FastMCP proxy
            resource_content = await self.mcp_proxy.read_resource(uri)
            
            return web.json_response({
                "content": resource_content,
                "user": user_info.get("email"),
                "uri": uri
            })
            
        except Exception as e:
            logger.error(f"Failed to read resource: {e}")
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_prompts(self, request: web.Request) -> web.Response:
        """List MCP prompts (OAuth protected)"""
        user_info = await self.get_user_from_request(request)
        if not user_info:
            return self._create_401_response(request, "Authentication required to access MCP prompts")
            
        try:
            # Get prompts from FastMCP proxy
            prompts = await self.mcp_proxy.list_prompts()
            prompts_data = [prompt.model_dump() if hasattr(prompt, 'model_dump') else {"name": str(prompt)} for prompt in prompts]
            
            return web.json_response({
                "prompts": prompts_data,  
                "user": user_info.get("email"),
                "count": len(prompts_data)
            })
            
        except Exception as e:
            logger.error(f"Failed to list prompts: {e}")
            return web.json_response({"error": str(e)}, status=500)
            
    async def permissions_info(self, request: web.Request) -> web.Response:
        """Display information about permissions requested"""
        scopes = self.config.default_scopes
        
        scope_descriptions = {
            'openid': 'Verify your identity',
            'profile': 'Access your basic profile information (name, etc.)',
            'email': 'Access your email address',
            'okta.users.read': 'Read user information from your Okta organization',
            'okta.groups.read': 'Read group information from your Okta organization', 
            'okta.apps.read': 'Read application information from your Okta organization',
            'okta.events.read': 'Read event information from your Okta organization',
            'okta.logs.read': 'Read log information from your Okta organization',
            'okta.policies.read': 'Read policy information from your Okta organization',
            'okta.devices.read': 'Read device information from your Okta organization',
            'okta.factors.read': 'Read authentication factor information from your Okta organization'
        }
        
        scope_list = ""
        for scope in scopes:
            description = scope_descriptions.get(scope, f"Access {scope}")
            scope_list += f"<li><strong>{scope}</strong>: {description}</li>"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Permissions - Okta MCP Server</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .permissions {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .note {{ background: #e7f3ff; padding: 15px; border-left: 4px solid #2196F3; margin: 20px 0; }}
                .actions {{ text-align: center; margin: 30px 0; }}
                .btn {{ padding: 12px 24px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
                .btn-primary {{ background: #007bff; color: white; }}
                .btn-secondary {{ background: #6c757d; color: white; }}
                ul {{ line-height: 1.6; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 OAuth Permissions</h1>
                <p>The Okta MCP Server is requesting the following permissions:</p>
            </div>
            
            <div class="permissions">
                <h3>Requested Permissions:</h3>
                <ul>
                    {scope_list}
                </ul>
            </div>
            
            <div class="note">
                <strong>Note:</strong> This application uses Okta's organization authorization server to access API resources. 
                You will be prompted to explicitly grant consent for each virtual client that requests access to your Okta data.
            </div>
            
            <div class="actions">
                <a href="/oauth/login" class="btn btn-primary">Continue to Login</a>
                <a href="/" class="btn btn-secondary">Cancel</a>
            </div>
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
                <small>For more information about OAuth security, see our <a href="/docs">documentation</a>.</small>
            </div>
        </body>
        </html>
        """
        
        return web.Response(text=html, content_type='text/html')

    # OAuth Discovery Endpoints (RFC 8414)
    
    async def oauth_protected_resource_metadata(self, request: web.Request) -> web.Response:
        """OAuth 2.0 Protected Resource Metadata (RFC 9728)"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version"
                }
            )
        
        try:
            base_url = f"{request.scheme}://{request.host}"
            
            metadata = {
                "resource": base_url,
                "authorization_servers": [base_url],  # Point to our proxy, not Okta directly
                "scopes_supported": self.config.get_all_scopes(),
                "bearer_methods_supported": ["header"],
                "resource_documentation": f"{base_url}/docs",
                "mcp_protocol_version": "2025-06-18",
                "resource_type": "mcp-server"
            }
            
            logger.info("Serving OAuth protected resource metadata")
            response = web.json_response(metadata)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
            
        except Exception as e:
            logger.error(f"Error serving protected resource metadata: {e}")
            response = web.json_response(
                {"error": "Failed to retrieve protected resource metadata"}, 
                status=503
            )
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    
    async def oauth_authorization_server_metadata(self, request: web.Request) -> web.Response:
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version"
                }
            )
        
        try:
            # Try Okta's OpenID Connect discovery endpoint first (most common)
            metadata_urls = [
                f"{self.config.org_url}/.well-known/openid-configuration"
            ]
            
            okta_metadata = None
            for metadata_url in metadata_urls:
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.get(metadata_url, timeout=10.0)
                        if response.status_code == 200:
                            okta_metadata = response.json()
                            logger.info(f"Successfully fetched Okta metadata from {metadata_url}")
                            break
                        else:
                            logger.debug(f"Failed to fetch from {metadata_url}: HTTP {response.status_code}")
                except Exception as e:
                    logger.debug(f"Failed to fetch from {metadata_url}: {e}")
                    continue
            
            if okta_metadata:
                # Replace key endpoints with our proxy endpoints where we have proxies
                base_url = f"{request.scheme}://{request.host}"
                okta_metadata["authorization_endpoint"] = f"{base_url}/oauth2/v1/authorize"
                okta_metadata["token_endpoint"] = f"{base_url}/oauth2/v1/token"
                okta_metadata["registration_endpoint"] = f"{base_url}/oauth2/v1/clients"
                
                # Return Okta's metadata with our proxy endpoints
                response = web.json_response(okta_metadata)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return response
            else:
                raise Exception("All metadata URLs failed")
            
        except Exception as e:
            logger.error(f"Error fetching Okta metadata: {e}")
            # Fallback metadata with our proxy endpoints where available
            base_url = f"{request.scheme}://{request.host}"
            fallback_metadata = {
                "issuer": self.config.org_url,
                "authorization_endpoint": f"{base_url}/oauth2/v1/authorize",
                "token_endpoint": f"{base_url}/oauth2/v1/token", 
                "userinfo_endpoint": f"{self.config.org_url}/oauth2/v1/userinfo",
                "registration_endpoint": f"{base_url}/oauth2/v1/clients",
                "jwks_uri": f"{self.config.org_url}/oauth2/v1/keys",
                "scopes_supported": self.config.get_all_scopes() + ["openid", "profile", "email"],
                "response_types_supported": ["code", "token"],
                "grant_types_supported": ["authorization_code", "client_credentials"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                "code_challenge_methods_supported": ["S256"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            }
            
            logger.warning("Using fallback authorization server metadata")
            response = web.json_response(fallback_metadata)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    
    async def oauth_jwks_proxy(self, request: web.Request) -> web.Response:
        """Proxy to Okta's JWKS endpoint with caching"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                }
            )
        
        try:
            # Simple in-memory cache (in production, use Redis or similar)
            cache_key = "okta_jwks"
            cache_ttl = 300  # 5 minutes
            now = datetime.now(timezone.utc)
            
            # Check if we have cached JWKS
            if hasattr(self, '_jwks_cache'):
                cached_time, cached_data = self._jwks_cache.get(cache_key, (None, None))
                if cached_time and (now - cached_time).total_seconds() < cache_ttl:
                    logger.debug("Serving cached JWKS")
                    response = web.json_response(cached_data)
                    response.headers["Access-Control-Allow-Origin"] = "*"
                    return response
            
            # Fetch fresh JWKS from Okta
            jwks_url = f"{self.config.org_url}/oauth2/v1/keys"
            
            async with httpx.AsyncClient() as client:
                jwks_response = await client.get(jwks_url, timeout=10.0)
                jwks_response.raise_for_status()
                jwks_data = jwks_response.json()
            
            # Cache the result
            if not hasattr(self, '_jwks_cache'):
                self._jwks_cache = {}
            self._jwks_cache[cache_key] = (now, jwks_data)
            
            logger.info(f"Serving fresh JWKS with {len(jwks_data.get('keys', []))} keys")
            response = web.json_response(jwks_data)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
            
        except Exception as e:
            logger.error(f"Error fetching JWKS from Okta: {e}")
            response = web.json_response(
                {"error": "Failed to retrieve JWKS"}, 
                status=503
            )
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    
    async def run(self, host: str = "localhost", port: int = 3001):
        """Run the OAuth FastMCP proxy server"""
        try:
            logger.info(f"Starting OAuth FastMCP proxy server on {host}:{port}")
            
            # SECURITY: Start periodic cleanup task for expired entries
            async def periodic_cleanup():
                while True:
                    try:
                        await asyncio.sleep(300)  # Run every 5 minutes
                        await self._cleanup_expired_entries()
                    except Exception as e:
                        logger.error(f"Cleanup task error: {e}")
            
            # Start the cleanup task in the background
            asyncio.create_task(periodic_cleanup())
            
            # Start HTTP server
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(runner, host, port)
            await site.start()
            
            logger.info("OAuth FastMCP proxy server started successfully!")
            logger.info("Available endpoints:")
            logger.info(f"  - GET  http://{host}:{port}/          - Home page")
            logger.info(f"  - GET  http://{host}:{port}/oauth/permissions - View OAuth permissions")
            logger.info(f"  - GET  http://{host}:{port}/oauth/login - OAuth login")
            logger.info(f"  - GET  http://{host}:{port}/mcp/tools  - List MCP tools (protected)")
            logger.info(f"  - POST http://{host}:{port}/mcp/tools/call - Call MCP tool (protected)")
            
            return runner
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise

    @web.middleware
    async def security_middleware(self, request: web.Request, handler):
        """Security middleware to add security headers and logging"""
        try:
            # Log request for audit
            self._audit_log("http_request", details={
                "method": request.method,
                "path": request.path,
                "remote": request.remote,
                "user_agent": request.headers.get("User-Agent", "")
            })
            
            response = await handler(request)
            
            # Add security headers
            for header, value in self.security_headers.items():
                response.headers[header] = value
                
            return response
            
        except Exception as e:
            self._audit_log("request_error", details={"error": str(e), "path": request.path})
            raise

    async def oauth_register_client(self, request: web.Request) -> web.Response:
        """Handle Dynamic Client Registration (DCR) - RFC 7591"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                }
            )
        
        try:
            # Get registration request
            registration_data = await request.json()
            logger.info(f"Client registration request: {registration_data}")
            
            # For MCP Inspector and similar tools, we can use our static client
            # but return a "virtual" registration that points to our proxy endpoints
            
            client_name = registration_data.get("client_name", "Unknown MCP Client")
            redirect_uris = registration_data.get("redirect_uris", [])
            scopes = registration_data.get("scope", "")
            token_endpoint_auth_method = registration_data.get("token_endpoint_auth_method", "none")
            
            # Validate redirect URIs (basic security check)
            valid_redirect_uris = []
            for uri in redirect_uris:
                if uri.startswith(("http://localhost", "http://127.0.0.1", "https://localhost", "https://127.0.0.1")):
                    valid_redirect_uris.append(uri)
                else:
                    logger.warning(f"Rejecting non-localhost redirect URI: {uri}")
            
            if not valid_redirect_uris:
                return web.json_response(
                    {"error": "invalid_redirect_uri", "error_description": "Only localhost redirect URIs are allowed"},
                    status=400,
                    headers={"Access-Control-Allow-Origin": "*"}
                )
            
            # Create a virtual client ID (for mapping to real client)
            client_id = f"virtual-{hashlib.sha256(client_name.encode()).hexdigest()[:16]}"
            
            # Store the virtual client registration
            self.virtual_clients[client_id] = {
                "client_name": client_name,
                "redirect_uris": valid_redirect_uris,
                "scopes": scopes.split(),
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "registered_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Also maintain backward compatibility with sessions storage
            self.sessions[client_id] = {
                "client_name": client_name,
                "redirect_uris": valid_redirect_uris,
                "scopes": scopes.split(),
                "registered_at": datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Registered virtual client: {client_id} - {client_name}")
            
            # Respond with registered client information
            response_data = {
                "client_id": client_id,
                "client_name": client_name,
                "redirect_uris": valid_redirect_uris,
                "scopes": scopes.split(),
                "grant_types": registration_data.get("grant_types", ["authorization_code"]),
                "response_types": registration_data.get("response_types", ["code"]),
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "client_id_issued_at": int(datetime.now(timezone.utc).timestamp()),
                "registration_access_token": "dummy-access-token",
                "registration_client_uri": f"{request.scheme}://{request.host}/oauth2/v1/clients/{client_id}"
            }
            
            return web.json_response(
                response_data, 
                status=201,
                headers={"Access-Control-Allow-Origin": "*"}
            )
            
        except Exception as e:
            logger.error(f"Client registration failed: {e}")
            return web.json_response(
                {"error": str(e)}, 
                status=500,
                headers={"Access-Control-Allow-Origin": "*"}
            )

    async def oauth_authorize_virtual(self, request: web.Request) -> web.Response:
        """Handle OAuth authorization for virtual clients"""
        try:
            # Get client_id from request
            client_id = request.query.get('client_id')
            redirect_uri = request.query.get('redirect_uri')
            state = request.query.get('state')
            scope = request.query.get('scope')
            
            # Check if this is a virtual client
            if hasattr(self, '_virtual_clients') and client_id in self._virtual_clients:
                virtual_client = self._virtual_clients[client_id]
                
                # Validate redirect URI
                if redirect_uri not in virtual_client['redirect_uris']:
                    return web.Response(
                        text=f"Invalid redirect URI: {redirect_uri}",
                        status=400
                    )
                
                logger.info(f"Virtual client {client_id} authorization request")
                
                # Redirect to our normal OAuth login flow, but store virtual client info
                from aiohttp_session import get_session
                session = await get_session(request)
                session['virtual_client_id'] = client_id
                session['virtual_redirect_uri'] = redirect_uri
                session['virtual_state'] = state
                session['virtual_scope'] = scope
                
                # Redirect to our OAuth login
                return web.Response(
                    status=302,
                    headers={'Location': '/oauth/login'}
                )
            else:
                return web.Response(
                    text=f"Unknown client_id: {client_id}",
                    status=400
                )
                
        except Exception as e:
            logger.error(f"Virtual OAuth authorize error: {e}")
            return web.Response(text="Authorization failed", status=500)
    
    async def oauth_token_virtual(self, request: web.Request) -> web.Response:
        """Handle OAuth token exchange for virtual clients"""
        try:
            # Handle CORS
            if request.method == "OPTIONS":
                return web.Response(
                    status=200,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization"
                    }
                )
            
            # For now, return an error since this requires more complex implementation
            # The client should use the main OAuth flow through /oauth/login
            return web.json_response(
                {
                    "error": "unsupported_grant_type",
                    "error_description": "Please use the web-based OAuth flow at /oauth/login"
                },
                status=400,
                headers={"Access-Control-Allow-Origin": "*"}
            )
            
        except Exception as e:
            logger.error(f"Virtual OAuth token error: {e}")
            return web.json_response(
                {"error": "server_error", "error_description": str(e)},
                status=500,
                headers={"Access-Control-Allow-Origin": "*"}
            )
    
    async def oauth_userinfo_virtual(self, request: web.Request) -> web.Response:
        """Handle OAuth userinfo for virtual clients"""
        try:
            # Handle CORS
            if request.method == "OPTIONS":
                return web.Response(
                    status=200,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization"
                    }
                )
            
            # For now, return an error since this requires authentication
            return self._create_401_response(request, "Please use the web-based OAuth flow at /oauth/login")
            
        except Exception as e:
            logger.error(f"Virtual OAuth userinfo error: {e}")
            return web.json_response(
                {"error": "server_error", "error_description": str(e)},
                status=500,
                headers={"Access-Control-Allow-Origin": "*"}
            )
    
    async def oauth_authorize_proxy(self, request: web.Request) -> web.Response:
        """Proxy OAuth authorization requests, with mandatory consent for virtual clients"""
        from aiohttp_session import get_session
        
        try:
            client_id = request.query.get('client_id')
            if not client_id:
                return web.Response(text="Missing client_id parameter", status=400)
            
            if client_id.startswith('virtual-'):
                # Check if virtual client exists, if not, auto-register it
                if client_id not in self.virtual_clients:
                    # Auto-register virtual client for VS Code and similar MCP clients
                    redirect_uri = request.query.get('redirect_uri', '')
                    scope = request.query.get('scope', 'openid profile email')
                    
                    logger.info(f"Auto-registering virtual client {client_id} with redirect_uri: {redirect_uri}")
                    
                    # Create virtual client entry
                    self.virtual_clients[client_id] = {
                        "client_name": f"Auto-registered MCP Client ({client_id})",
                        "redirect_uris": [redirect_uri] if redirect_uri else [],
                        "scopes": scope.split() if scope else ['openid', 'profile', 'email'],
                        "token_endpoint_auth_method": "none",
                        "registered_at": datetime.now(timezone.utc).isoformat(),
                        "auto_registered": True
                    }
                    
                    # Also maintain backward compatibility with sessions storage
                    self.sessions[client_id] = {
                        "client_name": f"Auto-registered MCP Client ({client_id})",
                        "redirect_uris": [redirect_uri] if redirect_uri else [],
                        "scopes": scope.split() if scope else ['openid', 'profile', 'email'],
                        "registered_at": datetime.now(timezone.utc).isoformat(),
                        "auto_registered": True
                    }
                    
                    logger.info(f"Successfully auto-registered virtual client: {client_id}")
                else:
                    logger.info(f"Virtual client {client_id} already registered")
                
                logger.info(f"Processing authorization request for virtual client {client_id}")
                
                # Get session to check for pending consent
                session = await get_session(request)
                pending_consent = session.get('pending_consent')
                
                # Check if this request has valid pending consent
                if not pending_consent or pending_consent.get('virtual_client_id') != client_id:
                    # No valid consent - redirect to consent page
                    logger.info(f"No valid consent for virtual client {client_id}, redirecting to consent page")
                    consent_params = {
                        'client_id': client_id,
                        'redirect_uri': request.query.get('redirect_uri', ''),
                        'state': request.query.get('state', ''),
                        'scope': request.query.get('scope', '')
                    }
                    consent_query = urlencode({k: v for k, v in consent_params.items() if v})
                    consent_url = f"/oauth/consent?{consent_query}"
                    return web.Response(status=302, headers={'Location': consent_url})
                
                # Valid consent exists - proceed with OAuth flow
                logger.info(f"Valid consent found for virtual client {client_id}, proceeding with OAuth")
                
                # Get original parameters
                original_redirect_uri = request.query.get('redirect_uri')
                original_state = request.query.get('state')
                
                logger.info(f"Original redirect_uri: {original_redirect_uri}")
                logger.info(f"Original state: {original_state}")
                
                # Generate a state parameter if none provided (required for Okta)
                if not original_state:
                    proxy_state = secrets.token_urlsafe(32)
                    logger.info(f"Generated proxy state: {proxy_state}")
                else:
                    proxy_state = original_state
                
                # Store mapping for callback (use proxy state as key)
                self.state_store[proxy_state] = {
                    'virtual_client_id': client_id,
                    'original_redirect_uri': original_redirect_uri,
                    'original_state': original_state,  # Store original state (could be None)
                    'pending_consent': pending_consent,  # Store consent info for finalization
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                logger.info(f"Stored state mapping: {proxy_state} -> virtual_client: {client_id}")
                
                # Clear the pending consent from session (it will be finalized after OAuth callback)
                session.pop('pending_consent', None)
                
                # Generate PKCE parameters for Okta
                code_verifier = secrets.token_urlsafe(64)
                hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
                encoded = base64.urlsafe_b64encode(hashed)
                code_challenge = encoded.decode('ascii').strip('=')
                
                # Store the code verifier for token exchange
                self.state_store[proxy_state].update({
                    'code_verifier': code_verifier,
                    'code_challenge': code_challenge
                })
                
                # Build new query parameters with PKCE
                new_query_params = dict(request.query)
                new_query_params['client_id'] = self.config.client_id
                new_query_params['state'] = proxy_state  # Use proxy state
                new_query_params['code_challenge'] = code_challenge
                new_query_params['code_challenge_method'] = 'S256'
                
                # Add audience parameter if configured (CRITICAL for JWT audience validation)
                if self.config.audience:
                    new_query_params['audience'] = self.config.audience
                    logger.info(f"Including audience in virtual client authorization: {self.config.audience}")
                
                # Use our configured redirect URI instead
                proxy_redirect_uri = self.config.redirect_uri or f"{request.scheme}://{request.host}/oauth/callback"
                new_query_params['redirect_uri'] = proxy_redirect_uri
                
                query_string = urlencode(new_query_params)
                okta_auth_url = f"https://{self.config.okta_domain}/oauth2/v1/authorize?{query_string}"
                
                logger.info(f"Redirecting to Okta: {okta_auth_url}")
                return web.Response(status=302, headers={'Location': okta_auth_url})
            else:
                # Non-virtual client - use standard flow with PKCE support
                # Generate PKCE parameters for any OAuth request
                code_verifier = secrets.token_urlsafe(64)
                hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
                encoded = base64.urlsafe_b64encode(hashed)
                code_challenge = encoded.decode('ascii').strip('=')
                
                # Get the state parameter
                original_state = request.query.get('state')
                if not original_state:
                    # Generate state if not provided
                    original_state = secrets.token_urlsafe(32)
                
                # Store code verifier for this state
                self.state_store[original_state] = {
                    'code_verifier': code_verifier,
                    'code_challenge': code_challenge,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                # Build query parameters with PKCE
                query_params = dict(request.query)
                query_params['code_challenge'] = code_challenge
                query_params['code_challenge_method'] = 'S256'
                if not query_params.get('state'):
                    query_params['state'] = original_state
                
                # Add audience parameter if configured (CRITICAL for JWT audience validation)
                if self.config.audience:
                    query_params['audience'] = self.config.audience
                    logger.info(f"Including audience in non-virtual client authorization: {self.config.audience}")
                
                query_string = urlencode(query_params)
                okta_auth_url = f"https://{self.config.okta_domain}/oauth2/v1/authorize?{query_string}"
                logger.info(f"Redirecting to Okta with PKCE: {okta_auth_url}")
                return web.Response(status=302, headers={'Location': okta_auth_url})
                
        except Exception as e:
            logger.error(f"Authorization proxy error: {e}")
            return web.Response(text=f"Authorization failed: {str(e)}", status=500)
    
    async def oauth_token_proxy(self, request: web.Request) -> web.Response:
        """Proxy OAuth token requests, handling virtual client authentication"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version"
                }
            )
        
        try:
            # Get the request body
            if request.content_type == 'application/json':
                token_data = await request.json()
            else:
                # Form data
                token_data = dict(await request.post())
            
            client_id = token_data.get('client_id')
            logger.info(f"Token request for client_id: {client_id}")
            
            if not client_id:
                return web.json_response(
                    {"error": "invalid_request", "error_description": "Missing client_id"},
                    status=400,
                    headers={"Access-Control-Allow-Origin": "*"}
                )
            
            # Check if this is a virtual client
            if client_id.startswith('virtual-'):
                if client_id not in self.virtual_clients:
                    return web.json_response(
                        {"error": "invalid_client", "error_description": "Unknown virtual client"},
                        status=400,
                        headers={"Access-Control-Allow-Origin": "*"}
                    )
                
                logger.info(f"Token request for virtual client {client_id}")
                
                # Check if this is using an authorization code we generated
                auth_code = token_data.get('code')
                if auth_code and auth_code in self.state_store:
                    # This is an authorization code from our proxy flow
                    stored_data = self.state_store[auth_code]
                    
                    # Verify the authorization code belongs to this virtual client
                    if stored_data.get('virtual_client_id') != client_id:
                        return web.json_response(
                            {"error": "invalid_grant", "error_description": "Authorization code does not match client"},
                            status=400,
                            headers={"Access-Control-Allow-Origin": "*"}
                        )
                    
                    # SECURITY FIX: Check if authorization code has expired
                    expires_at_str = stored_data.get('expires_at')
                    if expires_at_str:
                        try:
                            expires_at = datetime.fromisoformat(expires_at_str)
                            if datetime.now(timezone.utc) > expires_at:
                                del self.state_store[auth_code]
                                return web.json_response(
                                    {"error": "invalid_grant", "error_description": "Authorization code has expired"},
                                    status=400,
                                    headers={"Access-Control-Allow-Origin": "*"}
                                )
                        except (ValueError, TypeError) as e:
                            logger.warning(f"Invalid expires_at format for auth code {auth_code}: {e}")
                            # Delete suspicious entry
                            del self.state_store[auth_code]
                            return web.json_response(
                                {"error": "invalid_grant", "error_description": "Invalid authorization code"},
                                status=400,
                                headers={"Access-Control-Allow-Origin": "*"}
                            )
                    
                    # SECURITY FIX: Check if authorization code has already been used
                    if stored_data.get('used'):
                        logger.error(f"Attempted reuse of authorization code {auth_code} for client {client_id}")
                        del self.state_store[auth_code]
                        self._audit_log("auth_code_reuse_attempt", details={
                            "auth_code": auth_code[:20] + "...",
                            "virtual_client_id": client_id
                        })
                        return web.json_response(
                            {"error": "invalid_grant", "error_description": "Authorization code has already been used"},
                            status=400,
                            headers={"Access-Control-Allow-Origin": "*"}
                        )
                    
                    # Mark authorization code as used
                    stored_data['used'] = True
                    self.state_store[auth_code] = stored_data
                    
                    logger.info(f"Processing token exchange for virtual client {client_id} using stored PKCE verifier")
                    
                    # Use our stored PKCE verifier to exchange with Okta
                    stored_code_verifier = stored_data.get('code_verifier')
                    if not stored_code_verifier:
                        logger.error(f"No stored code_verifier found for auth code {auth_code}")
                        return web.json_response(
                            {"error": "server_error", "error_description": "Missing PKCE verifier"},
                            status=500,
                            headers={"Access-Control-Allow-Origin": "*"}
                        )
                    
                    # Exchange the authorization code with Okta using our PKCE verifier
                    redirect_uri = self.config.redirect_uri or f"{request.scheme}://{request.host}/oauth/callback"
                    okta_token_data = {
                        "grant_type": "authorization_code",
                        "client_id": self.config.client_id,
                        "client_secret": self.config.client_secret,
                        "code": auth_code,
                        "redirect_uri": redirect_uri,
                        "code_verifier": stored_code_verifier
                    }
                    
                    # Add audience parameter if configured (CRITICAL for JWT audience validation)
                    if self.config.audience:
                        okta_token_data["audience"] = self.config.audience
                        logger.info(f"Including audience in virtual client token request: {self.config.audience}")
                    
                    logger.info(f"Exchanging auth code with Okta using stored PKCE verifier: {stored_code_verifier[:20]}...")
                    
                    # Make token request to Okta
                    async with httpx.AsyncClient() as okta_client:
                        okta_token_url = f"https://{self.config.okta_domain}/oauth2/v1/token"
                        okta_response = await okta_client.post(
                            okta_token_url,
                            data=okta_token_data,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'}
                        )
                        
                        if okta_response.status_code != 200:
                            logger.error(f"Okta token exchange failed: {okta_response.status_code} - {okta_response.text}")
                            # Clean up the auth code
                            del self.state_store[auth_code]
                            return web.json_response(
                                {"error": "invalid_grant", "error_description": f"Token exchange failed: {okta_response.text}"},
                                status=400,
                                headers={"Access-Control-Allow-Origin": "*"}
                            )
                        
                        okta_token = okta_response.json()
                        logger.info("Successfully exchanged authorization code with Okta")
                    
                    # SECURITY FIX: Extract user information from the real Okta token
                    real_access_token = okta_token.get('access_token')
                    user_info = await self._get_user_info_comprehensive(real_access_token)
                    
                    # Generate a virtual access token for this virtual client
                    virtual_access_token = self._generate_secure_state()
                    
                    # SECURITY FIX: Store the virtual token mapping with proper user context
                    self.tokens[virtual_access_token] = {
                        'virtual_client_id': client_id,
                        'real_access_token': real_access_token,
                        'user_id': user_info.get('user_id'),
                        'email': user_info.get('email'),
                        'name': user_info.get('name'),
                        'scopes': user_info.get('scopes', []),
                        'created_at': datetime.now(timezone.utc).isoformat(),
                        'expires_in': okta_token.get('expires_in', 3600)
                    }
                    
                    # Clean up the authorization code
                    del self.state_store[auth_code]
                    
                    logger.info(f"Generated virtual access token for {client_id}")
                    
                    # Return virtual token response
                    return web.json_response({
                        "access_token": virtual_access_token,
                        "token_type": "Bearer",
                        "expires_in": okta_token.get('expires_in', 3600),
                        "scope": okta_token.get('scope', '')
                    }, headers={"Access-Control-Allow-Origin": "*"}
                )
                
                # Fall back to legacy virtual client handling for backward compatibility
                if client_id not in self.sessions:
                    return web.json_response(
                        {"error": "invalid_client", "error_description": "Unknown virtual client"},
                        status=400,
                        headers={"Access-Control-Allow-Origin": "*"}
                    )
                
                logger.info(f"Legacy token request for virtual client {client_id}, mapping to real client {self.config.client_id}")
                
                # Log original request data for debugging
                logger.info(f"Original token request data: {token_data}")
                
                # Replace virtual client ID with real client ID
                token_data['client_id'] = self.config.client_id
                
                # Replace redirect_uri with our proxy URI (must match authorization request)
                if 'redirect_uri' in token_data:
                    original_redirect_uri = token_data['redirect_uri']
                    proxy_redirect_uri = self.config.redirect_uri or f"{request.scheme}://{request.host}/oauth/callback"
                    token_data['redirect_uri'] = proxy_redirect_uri
                    logger.info(f"Mapped redirect_uri: {original_redirect_uri} -> {proxy_redirect_uri}")
                
                # Replace code_verifier with the one we stored during authorization
                auth_code = token_data.get('code')
                if auth_code and 'code_verifier' in token_data:
                    # Look for the stored code verifier using the authorization code from Okta
                    if auth_code in self.state_store:
                        stored_data = self.state_store[auth_code]
                        stored_code_verifier = stored_data.get('code_verifier')
                        
                        # Verify this auth code belongs to the correct virtual client
                        if stored_data.get('virtual_client_id') == client_id:
                            if stored_code_verifier:
                                original_code_verifier = token_data['code_verifier']
                                token_data['code_verifier'] = stored_code_verifier
                                logger.info(f"Replaced code_verifier using auth_code {auth_code}: {original_code_verifier[:20]}... -> {stored_code_verifier[:20]}...")
                                
                                # Clean up the auth code mapping
                                del self.state_store[auth_code]
                            else:
                                logger.warning(f"No code_verifier found in stored data for auth_code {auth_code}")
                        else:
                            logger.error(f"Authorization code {auth_code} belongs to client {stored_data.get('virtual_client_id')}, not {client_id}")
                    else:
                        logger.warning(f"Authorization code {auth_code} not found in state store")
                        logger.info(f"Current state store entries: {list(self.state_store.keys())}")
                        # Log state store contents for debugging
                        for key, data in self.state_store.items():
                            logger.info(f"State {key}: virtual_client={data.get('virtual_client_id')}, has_verifier={bool(data.get('code_verifier'))}")
                
                # Add client secret if required (for confidential clients)
                if hasattr(self.config, 'client_secret') and self.config.client_secret:
                    token_data['client_secret'] = self.config.client_secret
                
                # Add audience parameter if configured (CRITICAL for JWT audience validation)
                if self.config.audience:
                    token_data["audience"] = self.config.audience
                    logger.info(f"Including audience in oauth_token_proxy request: {self.config.audience}")
                
                logger.info(f"Final token request data to Okta: {token_data}")
            
            # Forward to Okta token endpoint
            async with httpx.AsyncClient() as client:
                okta_token_url = f"https://{self.config.okta_domain}/oauth2/v1/token"
                
                if request.content_type == 'application/json':
                    response = await client.post(
                        okta_token_url,
                        json=token_data,
                        headers={'Content-Type': 'application/json'}
                    )
                else:
                    response = await client.post(
                        okta_token_url,
                        data=token_data,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'}
                    )
                
                logger.info(f"Okta token response status: {response.status_code}")
                
                if response.status_code >= 400:
                    logger.error(f"Okta token error response: {response.text}")
                
                # Return Okta's response with CORS headers
                try:
                    response_data = response.json()
                except:
                    response_data = {"error": "invalid_response", "error_description": response.text}
                
                return web.json_response(
                    response_data,
                    status=response.status_code,
                    headers={"Access-Control-Allow-Origin": "*"}
                )
                
        except Exception as e:
            logger.error(f"Token proxy error: {e}")
            import traceback
            traceback.print_exc()
            return web.json_response(
                {"error": "server_error", "error_description": str(e)},
                status=500,
                headers={"Access-Control-Allow-Origin": "*"}
            )

    async def consent_page(self, request: web.Request) -> web.Response:
        """Display consent page for virtual client authorization"""
        from aiohttp_session import get_session
        
        try:
            # Get parameters from query string
            virtual_client_id = request.query.get('client_id')
            redirect_uri = request.query.get('redirect_uri')
            state = request.query.get('state')
            scope = request.query.get('scope', '').split()
            
            if not virtual_client_id or not virtual_client_id.startswith('virtual-'):
                return web.Response(text="Invalid or missing virtual client ID", status=400)
            
            # Check if virtual client is registered
            if virtual_client_id not in self.virtual_clients:
                return web.Response(text=f"Unknown virtual client: {virtual_client_id}", status=400)
            
            virtual_client = self.virtual_clients[virtual_client_id]
            
            # Validate redirect URI
            if redirect_uri and redirect_uri not in virtual_client['redirect_uris']:
                return web.Response(text="Invalid redirect URI", status=400)
            
            scope_descriptions = {
                'openid': 'Verify your identity',
                'profile': 'Access your basic profile information (name, etc.)',
                'email': 'Access your email address',
                'okta.users.read': 'Read user information from your Okta organization',
                'okta.groups.read': 'Read group information from your Okta organization', 
                'okta.apps.read': 'Read application information from your Okta organization',
                'okta.events.read': 'Read event information from your Okta organization',
                'okta.logs.read': 'Read log information from your Okta organization',
                'okta.policies.read': 'Read policy information from your Okta organization',
                'okta.devices.read': 'Read device information from your Okta organization',
                'okta.factors.read': 'Read authentication factor information from your Okta organization'
            }
            
            # Use requested scopes or fall back to client's registered scopes
            requested_scopes = scope if scope else virtual_client.get('scopes', [])
            
            scope_list = ""
            for scope_name in requested_scopes:
                description = scope_descriptions.get(scope_name, f"Access {scope_name}")
                scope_list += f"<li><strong>{scope_name}</strong>: {description}</li>"
            
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authorization Required - {virtual_client['client_name']}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .client-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #007bff; }}
                    .permissions {{ background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107; }}
                    .warning {{ background: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0; }}
                    .actions {{ text-align: center; margin: 30px 0; }}
                    .btn {{ padding: 12px 24px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
                    .btn-success {{ background: #28a745; color: white; }}
                    .btn-danger {{ background: #dc3545; color: white; }}
                    ul {{ line-height: 1.6; }}
                    form {{ display: inline; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🔐 Authorization Required</h1>
                    <p>The application <strong>"{virtual_client['client_name']}"</strong> is requesting access to your account.</p>
                </div>
                
                <div class="client-info">
                    <h3>Application Details:</h3>
                    <ul>
                        <li><strong>Name:</strong> {virtual_client['client_name']}</li>
                        <li><strong>Client ID:</strong> {virtual_client_id}</li>
                        <li><strong>Registered:</strong> {virtual_client['registered_at']}</li>
                    </ul>
                </div>
                
                <div class="permissions">
                    <h3>Requested Permissions:</h3>
                    <ul>
                        {scope_list}
                    </ul>
                </div>
                
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong> Only authorize applications you trust. 
                    This application will have access to the specified information in your Okta organization.
                </div>
                
                <div class="actions">
                    <form method="post" action="/oauth/consent">
                        <input type="hidden" name="client_id" value="{virtual_client_id}">
                        <input type="hidden" name="redirect_uri" value="{redirect_uri or ''}">
                        <input type="hidden" name="state" value="{state or ''}">
                        <input type="hidden" name="scope" value="{' '.join(requested_scopes)}">
                        <input type="hidden" name="action" value="allow">
                        <button type="submit" class="btn btn-success">Allow Access</button>
                    </form>
                    
                    <form method="post" action="/oauth/consent">
                        <input type="hidden" name="client_id" value="{virtual_client_id}">
                        <input type="hidden" name="redirect_uri" value="{redirect_uri or ''}">
                        <input type="hidden" name="state" value="{state or ''}">
                        <input type="hidden" name="action" value="deny">
                        <button type="submit" class="btn btn-danger">Deny Access</button>
                    </form>
                </div>
                
                <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
                    <small>This consent applies only to this specific application. You can revoke access at any time.</small>
                </div>
            </body>
            </html>
            """
            
            return web.Response(text=html, content_type='text/html')
            
        except Exception as e:
            logger.error(f"Consent page error: {e}")
            return web.Response(text=f"Error displaying consent page: {str(e)}", status=500)

    async def handle_consent(self, request: web.Request) -> web.Response:
        """Handle user consent response"""
        from aiohttp_session import get_session
        
        try:
            # Get form data
            data = await request.post()
            virtual_client_id = data.get('client_id')
            redirect_uri = data.get('redirect_uri')
            state = data.get('state')
            scope = data.get('scope', '').split()
            action = data.get('action')
            
            if not virtual_client_id or not virtual_client_id.startswith('virtual-'):
                return web.Response(text="Invalid virtual client ID", status=400)
            
            # For now, we'll use a placeholder user ID since we haven't authenticated yet
            # In a real implementation, this would come from the authenticated session
            user_id = "pending_auth"  # Will be updated after OAuth callback
            
            if action == "deny":
                # User denied consent - redirect back with error
                if redirect_uri:
                    error_params = {
                        'error': 'access_denied',
                        'error_description': 'User denied the request',
                        'state': state
                    }
                    error_query = urlencode({k: v for k, v in error_params.items() if v})
                    redirect_url = f"{redirect_uri}?{error_query}"
                    return web.Response(status=302, headers={'Location': redirect_url})
                else:
                    return web.Response(text="Access denied by user", status=403)
            
            elif action == "allow":
                # Store pending consent (will be finalized after OAuth callback)
                session = await get_session(request)
                session['pending_consent'] = {
                    'virtual_client_id': virtual_client_id,
                    'redirect_uri': redirect_uri,
                    'state': state,
                    'scope': scope,
                    'granted_at': datetime.now(timezone.utc).isoformat()
                }
                
                # Now redirect to the authorization proxy to start OAuth flow
                auth_params = {
                    'client_id': virtual_client_id,
                    'redirect_uri': redirect_uri,
                    'state': state,
                    'scope': ' '.join(scope),
                    'response_type': 'code'
                }
                auth_query = urlencode({k: v for k, v in auth_params.items() if v})
                auth_url = f"/oauth2/v1/authorize?{auth_query}"
                
                return web.Response(status=302, headers={'Location': auth_url})
            
            else:
                return web.Response(text="Invalid action", status=400)
                
        except Exception as e:
            logger.error(f"Consent handling error: {e}")
            return web.Response(text=f"Error processing consent: {str(e)}", status=500)

    async def _cleanup_expired_entries(self):
        """SECURITY: Clean up expired authorization codes and tokens to prevent memory leaks"""
        now = datetime.now(timezone.utc)
        
        # Clean up expired authorization codes in state store
        expired_codes = []
        for code, data in self.state_store.items():
            expires_at_str = data.get('expires_at')
            if expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(expires_at_str)
                    if now > expires_at:
                        expired_codes.append(code)
                except (ValueError, TypeError):
                    # Invalid timestamp format, remove it
                    expired_codes.append(code)
            else:
                # No expiration set, check timestamp (cleanup after 1 hour)
                timestamp_str = data.get('timestamp')
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str)
                        if now > timestamp + timedelta(hours=1):
                            expired_codes.append(code)
                    except (ValueError, TypeError):
                        expired_codes.append(code)
        
        for code in expired_codes:
            logger.info(f"Cleaning up expired authorization code: {code[:20]}...")
            del self.state_store[code]
        
        # Clean up expired virtual tokens
        expired_tokens = []
        for token, data in self.tokens.items():
            created_at_str = data.get('created_at')
            expires_in = data.get('expires_in', 3600)
            if created_at_str:
                try:
                    created_at = datetime.fromisoformat(created_at_str)
                    if now > created_at + timedelta(seconds=expires_in):
                        expired_tokens.append(token)
                except (ValueError, TypeError):
                    expired_tokens.append(token)
        
        for token in expired_tokens:
            logger.info(f"Cleaning up expired virtual token: {token[:20]}...")
            del self.tokens[token]
        
        # Clean up expired user consents
        for user_id, consents in list(self.user_consents.items()):
            expired_clients = []
            for client_id, consent_data in consents.items():
                expires_at_str = consent_data.get('expires_at')
                if expires_at_str:
                    try:
                        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                        if now > expires_at:
                            expired_clients.append(client_id)
                    except (ValueError, TypeError):
                        expired_clients.append(client_id)
            
            for client_id in expired_clients:
                logger.info(f"Cleaning up expired consent for user {user_id}, client {client_id}")
                del self.user_consents[user_id][client_id]
            
            # Remove user entry if no consents left
            if not self.user_consents[user_id]:
                del self.user_consents[user_id]
        
        if expired_codes or expired_tokens:
            logger.info(f"Cleanup completed: {len(expired_codes)} expired codes, {len(expired_tokens)} expired tokens")

    def _verify_and_decode_jwt(self, access_token: str) -> Optional[Dict[str, Any]]:
        """SECURITY: Properly verify JWT signature, expiration, and audience"""
        try:
            # First, decode header to get key ID
            unverified_header = jwt.get_unverified_header(access_token)
            kid = unverified_header.get('kid')
            
            if not kid:
                logger.error("JWT token missing key ID (kid) in header")
                return None
            
            # DEBUG: Decode token without verification to see its contents
            try:
                unverified_payload = jwt.decode(access_token, options={"verify_signature": False})
                logger.info(f"JWT token payload (unverified): {unverified_payload}")
                logger.info(f"JWT audience in token: {unverified_payload.get('aud')}")
                logger.info(f"Expected audience: {self.config.audience}")
            except Exception as e:
                logger.warning(f"Could not decode JWT for debugging: {e}")
            
            # Get JWKS from Okta (with caching)
            jwks_data = self._get_cached_jwks()
            if not jwks_data:
                logger.error("Failed to retrieve JWKS for token verification")
                return None
            
            # Find the matching key
            signing_key = None
            for key in jwks_data.get('keys', []):
                if key.get('kid') == kid:
                    try:
                        # Convert JWK to PEM format for PyJWT
                        from jwt.algorithms import RSAAlgorithm
                        signing_key = RSAAlgorithm.from_jwk(key)
                        break
                    except Exception as e:
                        logger.error(f"Failed to convert JWK to signing key: {e}")
                        continue
            
            if not signing_key:
                logger.error(f"No matching signing key found for kid: {kid}")
                return None
            
            # SECURITY: Verify JWT with proper validation
            # For Okta org authorization server, we need to be flexible with audience validation
            # as Okta uses the org URL as the default audience even when custom audience is requested
            valid_audiences = [
                self.config.audience,           # Custom audience (if configured)
                self.config.org_url,           # Okta org URL (default for org auth server)
                f"https://{self.config.okta_domain}"  # Alternative format
            ]
            
            # Remove None values and duplicates
            valid_audiences = list(set([aud for aud in valid_audiences if aud]))
            
            decoded = jwt.decode(
                access_token,
                signing_key,
                algorithms=['RS256'],  # Okta uses RS256
                audience=valid_audiences,  # Accept any of the valid audiences
                issuer=self.config.org_url,   # Validate issuer (always Okta's org URL)
                options={
                    "verify_signature": True,   # CRITICAL: Verify signature
                    "verify_exp": True,         # CRITICAL: Check expiration
                    "verify_aud": True,         # CRITICAL: Check audience
                    "verify_iss": True,         # CRITICAL: Check issuer
                    "require_exp": True,        # CRITICAL: Require expiration
                    "require_aud": True,        # CRITICAL: Require audience
                    "require_iss": True         # CRITICAL: Require issuer
                }
            )
            
            logger.info(f"JWT verification successful for user: {decoded.get('sub')}")
            return decoded
            
        except jwt.ExpiredSignatureError:
            logger.error("JWT token has expired")
            self._audit_log("jwt_expired", details={"token_prefix": access_token[:20]})
            return None
        except jwt.InvalidAudienceError:
            logger.error(f"JWT audience validation failed. Expected: {self.config.audience}")
            self._audit_log("jwt_invalid_audience", details={"token_prefix": access_token[:20]})
            return None
        except jwt.InvalidIssuerError:
            logger.error(f"JWT issuer validation failed. Expected: {self.config.org_url}")
            self._audit_log("jwt_invalid_issuer", details={"token_prefix": access_token[:20]})
            return None
        except jwt.InvalidSignatureError:
            logger.error("JWT signature verification failed")
            self._audit_log("jwt_invalid_signature", details={"token_prefix": access_token[:20]})
            return None
        except jwt.InvalidTokenError as e:
            logger.error(f"JWT token validation failed: {e}")
            self._audit_log("jwt_validation_failed", details={"error": str(e), "token_prefix": access_token[:20]})
            return None
        except Exception as e:
            logger.error(f"Unexpected error during JWT verification: {e}")
            return None
    
    def _get_cached_jwks(self) -> Optional[Dict[str, Any]]:
        """Get JWKS with caching for JWT verification"""
        try:
            cache_key = "okta_jwks"
            cache_ttl = 300  # 5 minutes
            now = datetime.now(timezone.utc)
            
            # Check if we have cached JWKS
            if hasattr(self, '_jwks_cache'):
                cached_time, cached_data = self._jwks_cache.get(cache_key, (None, None))
                if cached_time and (now - cached_time).total_seconds() < cache_ttl:
                    return cached_data
            
            # Fetch fresh JWKS from Okta
            import httpx
            jwks_url = f"{self.config.org_url}/oauth2/v1/keys"
            
            with httpx.Client() as client:
                jwks_response = client.get(jwks_url, timeout=10.0)
                jwks_response.raise_for_status()
                jwks_data = jwks_response.json()
            
            # Cache the result
            if not hasattr(self, '_jwks_cache'):
                self._jwks_cache = {}
            self._jwks_cache[cache_key] = (now, jwks_data)
            
            logger.info(f"Fetched fresh JWKS with {len(jwks_data.get('keys', []))} keys")
            return jwks_data
            
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            return None
    
    def _get_fallback_user_info(self) -> Dict[str, Any]:
        """Fallback user info for failed JWT verification"""
        return {
            "user_id": "unknown",
            "email": "unknown@example.com",
            "name": "Unknown User",
            "roles": [],
            "scopes": [],
            "audience": None,
            "issuer": None
        }

if __name__ == "__main__":
    import argparse
    import asyncio
    
    async def main():
        """Main entry point for the OAuth FastMCP proxy server"""
        parser = argparse.ArgumentParser(
            description="OAuth-protected FastMCP proxy server for Okta integration"
        )
        parser.add_argument(
            "--backend", 
            default="./main.py",
            help="Path to the backend MCP server script (default: ./main.py)"
        )
        parser.add_argument(
            "--host",
            default="localhost", 
            help="Host to bind the server to (default: localhost)"
        )
        parser.add_argument(
            "--port",
            type=int,
            default=3001,
            help="Port to bind the server to (default: 3001)"
        )
        parser.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR"],
            default="INFO",
            help="Logging level (default: INFO)"
        )
        
        args = parser.parse_args()
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, args.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        try:
            # Create and start the OAuth proxy server
            proxy = OAuthFastMCPProxy(backend_server_path=args.backend)
            
            logger.info("Starting OAuth FastMCP proxy server...")
            logger.info(f"Backend MCP server: {args.backend}")
            logger.info(f"Listening on: {args.host}:{args.port}")
            logger.info(f"OAuth configuration: {proxy.config.org_url}")
            
            # Start the server
            runner = await proxy.run(host=args.host, port=args.port)
            
            logger.info("Server is running. Press Ctrl+C to stop.")
            
            # Keep the server running
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                logger.info("Received shutdown signal, stopping server...")
                await runner.cleanup()
                logger.info("Server stopped.")
                
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            import traceback
            traceback.print_exc()
            exit(1)
    
    # Run the main function
    asyncio.run(main())
