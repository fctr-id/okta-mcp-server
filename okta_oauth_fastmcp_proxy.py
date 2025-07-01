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

logger = logging.getLogger("okta_oauth_fastmcp_proxy")

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
    
    def _validate_token_audience(self, token: Dict[str, Any]) -> bool:
        """Validate that token was issued for this MCP server"""
        expected_audience = self.config.org_url
        token_audience = token.get('aud')
        
        if token_audience != expected_audience:
            logger.error(f"Token audience mismatch. Expected: {expected_audience}, Got: {token_audience}")
            return False
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
    
    def _setup_oauth_routes(self):
        """Setup OAuth authentication routes"""
        self.app.router.add_get("/", self.home)
        self.app.router.add_get("/health", self.health_check)
        
        # OAuth routes
        self.app.router.add_get('/oauth/permissions', self.permissions_info)
        self.app.router.add_get('/oauth/login', self.oauth_login)
        self.app.router.add_get('/oauth/callback', self.oauth_callback)
        self.app.router.add_get('/oauth/status', self.oauth_status)
        self.app.router.add_get('/oauth/logout', self.oauth_logout)
        
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
        
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "oauth_configured": bool(self.config.client_id),
            "mcp_backend": self.backend_server_path,
            "timestamp": datetime.utcnow().isoformat()
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
            
            # Get redirect URI
            redirect_uri = str(request.url.with_path("/oauth/callback"))
            
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
            
            # First validate token audience (MCP security requirement)
            try:
                decoded_token = jwt.decode(access_token, options={"verify_signature": False})
                if not self._validate_token_audience(decoded_token):
                    self._audit_log("token_validation_failed", details={"reason": "invalid_audience"})
                    return web.json_response({"error": "Invalid token audience"}, status=403)
            except Exception as e:
                logger.error(f"Token validation failed: {e}")
                self._audit_log("token_validation_failed", details={"reason": str(e)})
                return web.json_response({"error": "Token validation failed"}, status=403)
            
            user_info = await self._get_user_info_comprehensive(access_token)
            
            # Store user info in session
            session['authenticated'] = True
            session['user_info'] = user_info
            session['access_token'] = access_token
            session['token_expires_at'] = (datetime.now(timezone.utc) + timedelta(seconds=token.get("expires_in", 3600))).isoformat()
            
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
        """Extract user information from JWT access token"""
        try:
            # Decode JWT without verification (in production, verify signature)
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            
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
        """Get authenticated user from session with enhanced security validation"""
        try:
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
            return web.json_response({"error": "Authentication required"}, status=401)
            
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
            return web.json_response({"error": "Authentication required"}, status=401)
            
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
            return web.json_response({"error": "Authentication required"}, status=401)
            
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
            return web.json_response({"error": "Authentication required"}, status=401)
            
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
            return web.json_response({"error": "Authentication required"}, status=401)
            
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
                Consent is granted automatically upon successful authentication as this is a trusted first-party application.
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

    async def run(self, host: str = "localhost", port: int = 3001):
        """Run the OAuth FastMCP proxy server"""
        try:
            logger.info(f"Starting OAuth FastMCP proxy server on {host}:{port}")
            
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

def main():
    """Main entry point"""
    import argparse
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description="OAuth FastMCP Proxy Server")
    parser.add_argument("--backend", default="./main.py", help="Backend MCP server path")
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    parser.add_argument("--port", type=int, default=3001, help="Port to bind to")
    
    args = parser.parse_args()
    
    async def run_server():
        proxy = OAuthFastMCPProxy(args.backend)
        runner = await proxy.run(args.host, args.port)
        
        try:
            # Keep server running
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
        finally:
            await runner.cleanup()
    
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
