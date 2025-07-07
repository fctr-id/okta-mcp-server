"""
Unified FastMCP OAuth Server

This replaces the aiohttp OAuth proxy with a pure FastMCP implementation that provides:
- OAuth 2.0 authentication flows via @custom_route decorators
- MCP protocol support with OAuth protection via middleware  
- RBAC tool filtering based on Okta group membership
- All OAuth endpoints for MCP Inspector compatibility

This server runs on port 3001 and eliminates the need for proxying to port 3000.
"""

import os
import sys
import asyncio
import logging
import secrets
import json
import httpx
import hashlib
import base64
import contextvars
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, urlparse
from pathlib import Path

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import Response, JSONResponse, HTMLResponse, RedirectResponse
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

# Add parent directory to path for imports
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from okta_mcp.auth.oauth_provider import OAuthConfig
from okta_mcp.auth.role_mapper import OktaGroupRoleMapper
from okta_mcp.auth.jwt_validator import JWTValidator
from okta_mcp.oauth_proxy.models import VirtualClient, AuthorizationCode, UserConsent
from okta_mcp.oauth_proxy.utils import generate_secure_session_key, audit_log

logger = logging.getLogger("fastmcp_oauth_server")


class OAuthSessionManager:
    """Manages OAuth sessions, tokens, and user state"""
    
    def __init__(self, oauth_config: OAuthConfig):
        self.config = oauth_config
        self.role_mapper = OktaGroupRoleMapper()
        self.jwt_validator = JWTValidator(oauth_config)
        
        # Session storage
        self.virtual_clients: Dict[str, VirtualClient] = {}
        self.client_secrets: Dict[str, str] = {}  # client_id -> client_secret
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.user_consents: Dict[str, UserConsent] = {}
        self.tokens: Dict[str, Dict[str, Any]] = {}  # Virtual tokens for clients
        self.state_store: Dict[str, Any] = {}
        self.refresh_token_mappings: Dict[str, Dict[str, Any]] = {}  # Virtual refresh token mappings
        self.real_token_store: Dict[str, Dict[str, Any]] = {}  # Real Okta tokens (secure storage)
        
        # Thread-safe current user storage for FastMCP middleware access
        self.current_user_context: contextvars.ContextVar = contextvars.ContextVar('current_user', default=None)
        
        # Load persisted tokens from file
        self._load_persisted_tokens()
        
        logger.info("OAuth session manager initialized with JWT validation")
    
    def _load_persisted_tokens(self):
        """Load persisted tokens from file (stub for future implementation)
        
        This is a placeholder for future file-based persistence to survive server restarts.
        Currently tokens are only stored in memory.
        """
        # TODO: Implement file-based token persistence
        # For now, tokens are only stored in memory and lost on restart
        pass
    
    def set_current_user(self, user_info: Optional[Dict[str, Any]]):
        """Set current user in context for FastMCP middleware access"""
        self.current_user_context.set(user_info)
    
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current user from context for FastMCP middleware access"""
        return self.current_user_context.get(None)
    
    async def get_user_from_session(self, request: Request) -> Optional[Dict[str, Any]]:
        """Extract user info from session or Bearer token with full JWT validation
        
        Note: FastMCP custom routes may not have session access, so we use memory fallback
        """
        try:
            # Try Bearer token first (for API calls) with JWT validation
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                access_token = auth_header[7:]  # Remove "Bearer "
                
                # First check if it's a virtual token (for MCP Inspector compatibility)
                if access_token in self.tokens:
                    session_data = self.tokens[access_token]
                    logger.debug(f"Using virtual token for user: {session_data.get('user_id')}")
                    return {
                        'user_id': session_data.get('user_id'),
                        'email': session_data.get('email'),
                        'name': session_data.get('name'),
                        'role': session_data.get('rbac_role'),
                        'groups': session_data.get('groups', []),
                        'scopes': session_data.get('scopes', [])
                    }
                
                # If not a virtual token, validate as real JWT from Okta
                logger.debug("Validating Bearer token as JWT")
                validation_result = await self.jwt_validator.validate_token(access_token)
                
                if validation_result.is_valid:
                    user_info = self.jwt_validator.get_user_info_from_claims(validation_result.user_claims)
                    
                    # Map role if not already done
                    if "role" not in user_info or not user_info["role"]:
                        groups = user_info.get("groups", [])
                        user_info["role"] = self.role_mapper.get_user_role(groups)
                    
                    logger.info(f"JWT validation successful for user: {user_info.get('email')}")
                    audit_log("jwt_validation_success", 
                             user_id=user_info.get('user_id'),
                             details={"validation_type": "bearer_token"})
                    
                    return user_info
                else:
                    logger.warning(f"JWT validation failed: {validation_result.error}")
                    audit_log("jwt_validation_failed", 
                             details={
                                 "error": validation_result.error,
                                 "error_type": validation_result.error_type,
                                 "token_prefix": access_token[:20] if access_token else "none"
                             })
                    return None
            
            # Try session-based auth (for web UI) with safe access
            try:
                if hasattr(request, 'session') and hasattr(request.session, 'get'):
                    if request.session.get("authenticated"):
                        user_info = request.session.get("user_info", {})
                        
                        # Map role if not already done
                        if "rbac_role" not in user_info:
                            groups = user_info.get("groups", [])
                            user_info["rbac_role"] = self.role_mapper.get_user_role(groups)
                            
                        return {
                            'user_id': user_info.get('user_id'),
                            'email': user_info.get('email'),
                            'name': user_info.get('name'),
                            'role': user_info.get('rbac_role'),
                            'groups': user_info.get('groups', []),
                            'scopes': user_info.get('scopes', [])
                        }
            except Exception as session_error:
                logger.debug(f"Session access failed (this is normal for FastMCP custom routes): {session_error}")
                
        except Exception as e:
            logger.error(f"Failed to get user from session: {e}")
            audit_log("authentication_error", details={"error": str(e)})
            
        return None
    
    def create_401_response(self, request: Request, error_description: str = "Authentication required") -> JSONResponse:
        """Create RFC 6750 compliant 401 response with proper WWW-Authenticate header"""
        base_url = f"{request.url.scheme}://{request.url.netloc}"
        resource_metadata_url = f"{base_url}/.well-known/oauth-protected-resource"
        www_authenticate = f'Bearer realm="Okta MCP Server", resource_metadata="{resource_metadata_url}"'
        
        return JSONResponse(
            {
                "error": "invalid_token", 
                "error_description": error_description
            },
            status_code=401,
            headers={
                "WWW-Authenticate": www_authenticate,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
            }
        )
    
    def add_security_headers(self, response: Response) -> Response:
        """Add comprehensive security headers to response"""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY", 
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache"
        }
        
        # Add HSTS for HTTPS in production
        if self.config.require_https:
            security_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response
    
    async def cleanup_expired_tokens(self):
        """Cleanup expired tokens and authorization codes"""
        current_time = datetime.now(timezone.utc)
        
        # Clean up expired authorization codes
        expired_codes = []
        for code, auth_code_obj in self.authorization_codes.items():
            if current_time > auth_code_obj["expires_at"]:
                expired_codes.append(code)
        
        for code in expired_codes:
            del self.authorization_codes[code]
            
        # Clean up expired virtual tokens  
        expired_tokens = []
        for token, token_data in self.tokens.items():
            expires_at = token_data.get("expires_at")
            if expires_at and current_time > expires_at:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self.tokens[token]
            
        if expired_codes or expired_tokens:
            logger.info(f"Cleaned up {len(expired_codes)} expired codes and {len(expired_tokens)} expired tokens")
            audit_log("token_cleanup", details={
                "expired_codes": len(expired_codes),
                "expired_tokens": len(expired_tokens)
            })
    
    def check_user_consent(self, user_id: str, client_id: str, requested_scopes: List[str]) -> bool:
        """Check if user has valid consent for the client and scopes"""
        consent_key = f"{user_id}:{client_id}"
        
        if consent_key not in self.user_consents:
            logger.debug(f"No consent found for user {user_id} and client {client_id}")
            return False
        
        consent = self.user_consents[consent_key]
        
        # Check if consent has expired (24 hours default)
        if datetime.now(timezone.utc) > consent["expires_at"]:
            logger.debug(f"Consent expired for user {user_id} and client {client_id}")
            del self.user_consents[consent_key]
            return False
        
        # Check if all requested scopes are covered by consent
        granted_scopes = consent.get("scopes", [])
        for scope in requested_scopes:
            if scope not in granted_scopes:
                logger.debug(f"Scope '{scope}' not in granted consent for user {user_id} and client {client_id}")
                return False
        
        logger.debug(f"Valid consent found for user {user_id} and client {client_id}")
        return True
    
    def store_user_consent(self, user_id: str, client_id: str, scopes: List[str], duration_hours: int = 24):
        """Store user consent for a client with expiration"""
        consent_key = f"{user_id}:{client_id}"
        
        self.user_consents[consent_key] = {
            "user_id": user_id,
            "client_id": client_id,
            "scopes": scopes,
            "granted_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        }
        
        logger.info(f"Stored consent for user {user_id} and client {client_id}, expires in {duration_hours} hours")
        audit_log("user_consent_granted", 
                 user_id=user_id,
                 details={
                     "client_id": client_id,
                     "scopes": scopes,
                     "expires_in_hours": duration_hours
                 })
    
    def create_rfc6750_error_response(self, request: Request, error: str, error_description: str, status_code: int = 401) -> JSONResponse:
        """Create RFC 6750 compliant error response with WWW-Authenticate header"""
        resource_metadata_url = f"{request.url.scheme}://{request.url.netloc}/.well-known/oauth-protected-resource"
        www_authenticate = f'Bearer realm="Okta MCP Server", resource_metadata="{resource_metadata_url}"'
        
        response = JSONResponse(
            {"error": error, "error_description": error_description},
            status_code=status_code,
            headers={"WWW-Authenticate": www_authenticate}
        )
        
        return self.add_security_headers(response)


class FastMCPOAuthServer:
    """Unified FastMCP server with OAuth authentication and RBAC"""
    
    def __init__(self):
        # Load OAuth configuration
        self.oauth_config = OAuthConfig.from_environment()
        
        # Initialize session manager
        self.session_manager = OAuthSessionManager(self.oauth_config)
        
        # Note: RBAC middleware is implemented directly in _register_fastmcp_middleware()
        # This external middleware class is not actually used
        
        # Create FastMCP server
        self.mcp = FastMCP(
            name="Okta MCP OAuth Server",
            instructions="""
            OAuth-protected MCP server for Okta Identity Cloud management.
            Supports RBAC-based tool filtering and complete OAuth 2.0 flows.
            """
        )
        
        # Register tools
        self._register_tools()
        
        # Register OAuth routes
        self._register_oauth_routes()
        
        # Register FastMCP middleware hooks
        self._register_fastmcp_middleware()
        
        logger.info("FastMCP OAuth server initialized")
    
    def _register_tools(self):
        """Register all Okta MCP tools with RBAC filtering"""
        logger.info("Registering Okta tools with RBAC filtering")
        
        try:
            # Initialize Okta client
            from okta_mcp.utils.okta_client import OktaMcpClient, create_okta_client
            
            org_url = os.getenv('OKTA_CLIENT_ORGURL')
            api_token = os.getenv('OKTA_API_TOKEN')
            okta_sdk_client = create_okta_client(org_url, api_token)
            okta_client = OktaMcpClient(client=okta_sdk_client)
            
            # Register tools directly
            from okta_mcp.tools.user_tools import register_user_tools
            from okta_mcp.tools.apps_tools import register_apps_tools
            from okta_mcp.tools.log_events_tools import register_log_events_tools
            from okta_mcp.tools.group_tools import register_group_tools
            from okta_mcp.tools.policy_network_tools import register_policy_tools 
            from okta_mcp.tools.datetime_tools import register_datetime_tools
            
            register_user_tools(self.mcp, okta_client)
            register_apps_tools(self.mcp, okta_client)
            register_log_events_tools(self.mcp, okta_client)
            register_group_tools(self.mcp, okta_client)
            register_policy_tools(self.mcp, okta_client) 
            register_datetime_tools(self.mcp, okta_client)
            
            logger.info("All Okta tools registered successfully")
            
        except Exception as e:
            logger.error(f"Failed to register tools: {e}")
            raise
    
    def _register_oauth_routes(self):
        """Register OAuth endpoints as FastMCP custom routes"""
        
        @self.mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
        async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
            """OAuth 2.0 Resource Server Metadata (RFC 8414 extension)"""
            if request.method == "OPTIONS":
                return JSONResponse(
                    {},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization, User-Agent, Accept, Accept-Language, Accept-Encoding, Cache-Control, Connection, Host, Origin, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site"
                    }
                )
            
            # Force HTTPS for cloud deployments (avoid HTTP->HTTPS redirects that break CORS preflight)
            base_url = f"{request.url.scheme}://{request.url.netloc}"
            if "ondigitalocean.app" in request.url.netloc or "herokuapp.com" in request.url.netloc:
                base_url = f"https://{request.url.netloc}"
            
            metadata = {
                "resource": f"{base_url}/mcp",
                "authorization_servers": [base_url],
                "resource_documentation": "https://github.com/fctrid/okta-mcp-server",
                "scopes_supported": self.oauth_config.get_all_scopes(),
                "bearer_methods_supported": ["header"],
                "resource_signing_alg_values_supported": ["RS256"]
            }
            
            response = JSONResponse(metadata)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
        
        @self.mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
        async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
            """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
            if request.method == "OPTIONS":
                return JSONResponse(
                    {},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization, User-Agent, Accept, Accept-Language, Accept-Encoding, Cache-Control, Connection, Host, Origin, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site"
                    }
                )
            
            # Force HTTPS for cloud deployments (avoid HTTP->HTTPS redirects that break CORS preflight)
            base_url = f"{request.url.scheme}://{request.url.netloc}"
            if "ondigitalocean.app" in request.url.netloc or "herokuapp.com" in request.url.netloc:
                base_url = f"https://{request.url.netloc}"
            
            metadata = {
                "issuer": base_url,
                "authorization_endpoint": f"{base_url}/oauth/authorize",  # Our virtual endpoint
                "token_endpoint": f"{base_url}/oauth/token",  # Our virtual endpoint
                "userinfo_endpoint": f"{base_url}/oauth/userinfo",  # Our virtual endpoint
                "registration_endpoint": f"{base_url}/oauth2/v1/clients",  # Dynamic client registration
                "scopes_supported": self.oauth_config.get_all_scopes(),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "userinfo_signing_alg_values_supported": ["RS256"],
                "request_uri_parameter_supported": False,
                "require_request_uri_registration": False,
                "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "preferred_username", "groups"]
            }
            
            response = JSONResponse(metadata)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
        
        @self.mcp.custom_route("/oauth2/v1/clients", methods=["GET", "POST", "OPTIONS"])
        async def oauth_dynamic_client_registration(request: Request) -> JSONResponse:
            """OAuth 2.0 Dynamic Client Registration (RFC 7591)"""
            if request.method == "OPTIONS":
                return JSONResponse(
                    {},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization, User-Agent, Accept, Accept-Language, Accept-Encoding, Cache-Control, Connection, Host, Origin, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site"
                    }
                )
            
            if request.method == "GET":
                # Return RFC 7591 compliant dynamic client registration metadata
                # Force HTTPS for cloud deployments
                base_url = f"{request.url.scheme}://{request.url.netloc}"
                if "ondigitalocean.app" in request.url.netloc or "herokuapp.com" in request.url.netloc:
                    base_url = f"https://{request.url.netloc}"
                
                response_data = {
                    "client_registration_endpoint": f"{base_url}/oauth2/v1/clients",
                    "client_registration_authn_methods_supported": ["none"],
                    "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "scopes_supported": self.oauth_config.get_all_scopes(),
                    "code_challenge_methods_supported": ["S256"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "registration_endpoint": f"{base_url}/oauth2/v1/clients"
                }
                response = JSONResponse(response_data)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
            
            try:
                data = await request.json()
                redirect_uris = data.get("redirect_uris", [])
                
                if not redirect_uris:
                    return JSONResponse({"error": "invalid_request", "error_description": "redirect_uris required"}, status_code=400)
                
                # Generate virtual client
                virtual_client_id = f"virtual_{secrets.token_urlsafe(20)}"
                client_secret = secrets.token_urlsafe(32)
                
                virtual_client = VirtualClient(
                    client_id=virtual_client_id,
                    name=data.get("client_name", f"MCP Client {virtual_client_id}"),
                    redirect_uri=redirect_uris[0],  # Use first redirect URI for compatibility
                    scopes=self.oauth_config.get_all_scopes(),
                    created_at=datetime.now(timezone.utc)
                )
                
                # Store the virtual client
                self.session_manager.virtual_clients[virtual_client_id] = virtual_client
                self.session_manager.client_secrets[virtual_client_id] = client_secret
                
                logger.info(f"Created virtual client: {virtual_client_id} with redirect URI: {', '.join(redirect_uris)}")
                
                # Return client registration response
                registration_response = {
                    "client_id": virtual_client_id,
                    "client_secret": client_secret,
                    "client_name": virtual_client.name,
                    "redirect_uris": redirect_uris,
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "client_secret_post"
                }
                
                response = JSONResponse(registration_response, status_code=201)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
                
            except Exception as e:
                logger.error(f"Client registration error: {e}")
                return JSONResponse({"error": "server_error"}, status_code=500)
        
        @self.mcp.custom_route("/oauth/authorize", methods=["GET", "POST"])
        async def oauth_authorize_virtual(request: Request) -> Response:
            """Virtual OAuth authorization endpoint for MCP Inspector"""
            try:
                # Get parameters from query params or form data
                if request.method == "GET":
                    client_id = request.query_params.get("client_id")
                    redirect_uri = request.query_params.get("redirect_uri")
                    state = request.query_params.get("state")
                    code_challenge = request.query_params.get("code_challenge")
                    scope = request.query_params.get("scope", "openid profile email")
                else:  # POST
                    form_data = await request.form()
                    client_id = form_data.get("client_id")
                    redirect_uri = form_data.get("redirect_uri")
                    state = form_data.get("state")
                    code_challenge = form_data.get("code_challenge")
                    scope = form_data.get("scope", "openid profile email")
                
                if not client_id or not redirect_uri:
                    return JSONResponse({"error": "invalid_request", "error_description": "client_id and redirect_uri required"}, status_code=400)
                
                # Auto-register virtual client if it doesn't exist (for MCP Inspector compatibility)
                if client_id not in self.session_manager.virtual_clients:
                    logger.info(f"Auto-registering virtual client - ID: {client_id}")
                    
                    # Create virtual client with requested scopes
                    requested_scopes = scope.split() if scope else ["openid", "profile", "email"]
                    virtual_client = VirtualClient(
                        client_id=client_id,
                        name="Auto-registered MCP Client",
                        redirect_uri=redirect_uri,  # Use the provided redirect_uri
                        scopes=requested_scopes,  # Include the scopes parameter
                        created_at=datetime.now(timezone.utc)
                    )
                    
                    self.session_manager.virtual_clients[client_id] = virtual_client
                    
                    logger.info(f"Virtual client {client_id} auto-registered for redirect_uri: {redirect_uri} with scopes: {requested_scopes}")
                
                virtual_client = self.session_manager.virtual_clients[client_id]
                
                # Check for pending consent (check both session and memory storage)
                consent_key = f"consent_{client_id}"
                pending_consent = None
                
                # Try session first
                if hasattr(request, 'session') and consent_key in request.session:
                    pending_consent = request.session[consent_key]
                    logger.debug(f"Found consent in session for {consent_key}")
                elif consent_key in self.session_manager.state_store:
                    pending_consent = self.session_manager.state_store.get(consent_key)
                    logger.debug(f"Found consent in memory for {consent_key}")
                
                # Check if user is already authenticated
                user_info = await self.session_manager.get_user_from_session(request)
                if not user_info:
                    # User not authenticated - check if they need to consent first
                    if not pending_consent or pending_consent.get('virtual_client_id') != client_id:
                        # No valid consent - redirect to consent page first
                        consent_params = {
                            "client_id": client_id,
                            "scope": scope,
                            "redirect_uri": redirect_uri,
                            "state": state,
                            "code_challenge": code_challenge
                        }
                        consent_url = f"/oauth/consent?{urlencode(consent_params)}"
                        logger.info(f"Consent required for client {client_id} before authentication")
                        audit_log("consent_required", details={
                            "client_id": client_id,
                            "reason": "no_pending_consent"
                        })
                        return RedirectResponse(consent_url)
                    
                    # Has pending consent - proceed to Okta auth
                    # Generate proxy state for this authorization request (like old code)
                    proxy_state = secrets.token_urlsafe(64)
                    
                    # Store virtual client info with proxy state (both in memory and session)
                    state_info = {
                        'virtual_client_id': client_id,
                        'original_redirect_uri': redirect_uri,
                        'original_state': state,
                        'original_scope': scope,
                        'code_challenge': code_challenge,
                        'pending_consent': pending_consent,  # Store consent info
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                    
                    # Store in memory (for local dev)
                    self.session_manager.state_store[proxy_state] = state_info
                    
                    # Also store in session (for cloud deployments)
                    if hasattr(request, 'session'):
                        request.session[f"oauth_state_{proxy_state}"] = state_info
                        logger.debug(f"Stored state {proxy_state} in session")
                    else:
                        logger.warning("No session available, using only in-memory state storage")
                    
                    # Generate PKCE parameters for Okta
                    code_verifier = secrets.token_urlsafe(64)
                    okta_code_challenge = base64.urlsafe_b64encode(
                        hashlib.sha256(code_verifier.encode('ascii')).digest()
                    ).decode('ascii').strip('=')
                    
                    # Store PKCE verifier in both memory and session
                    if proxy_state in self.session_manager.state_store:
                        self.session_manager.state_store[proxy_state]['code_verifier'] = code_verifier
                    
                    if hasattr(request, 'session') and f"oauth_state_{proxy_state}" in request.session:
                        request.session[f"oauth_state_{proxy_state}"]['code_verifier'] = code_verifier
                        logger.debug(f"Updated state {proxy_state} with code_verifier in session")
                    
                    # Clear pending consent from both session and memory storage
                    consent_key = f"consent_{client_id}"
                    self.session_manager.state_store.pop(consent_key, None)
                    
                    try:
                        if hasattr(request, 'session') and hasattr(request.session, 'pop'):
                            request.session.pop(consent_key, None)
                            logger.debug(f"Cleared consent {consent_key} from session")
                    except Exception as e:
                        logger.debug(f"Could not clear session consent (normal for FastMCP routes): {e}")
                    
                    # Build Okta authorization URL directly
                    okta_params = {
                        'response_type': 'code',
                        'client_id': self.oauth_config.client_id,
                        'redirect_uri': self.oauth_config.redirect_uri,  # Our callback
                        'scope': ' '.join(self.oauth_config.get_all_scopes()),
                        'state': proxy_state,  # Use proxy state
                        'code_challenge': okta_code_challenge,
                        'code_challenge_method': 'S256'
                    }
                    
                    okta_auth_url = f"{self.oauth_config.authorization_url}?{urlencode(okta_params)}"
                    
                    audit_log("oauth_login_initiated", details={"redirect_uri": redirect_uri})
                    return RedirectResponse(okta_auth_url, status_code=302)
        
                # Already authenticated - generate virtual authorization code directly
                virtual_client = self.session_manager.virtual_clients[client_id]
                requested_scopes = scope.split() if scope else ["openid", "profile", "email"]
                
                # Generate virtual authorization code
                auth_code = secrets.token_urlsafe(32)
                code_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
                
                # Get the role for the authenticated user
                user_role = user_info.get('role', 'viewer')  # From session/token data
                
                auth_code_obj = AuthorizationCode(
                    code=auth_code,
                    client_id=client_id,
                    user_id=user_info['user_id'],
                    scopes=requested_scopes,
                    code_challenge=code_challenge,
                    code_challenge_method="S256",
                    redirect_uri=redirect_uri,
                    created_at=datetime.now(timezone.utc),
                    expires_at=code_expires_at,
                    rbac_role=user_role
                )
                
                self.session_manager.authorization_codes[auth_code] = auth_code_obj.__dict__
                
                # Redirect back with auth code
                params = {"code": auth_code}
                if state:
                    params["state"] = state
                    
                redirect_url = f"{redirect_uri}?{urlencode(params)}"
                
                logger.info(f"Authorization code issued for client {client_id}, scopes: {requested_scopes}")
                audit_log("authorization_code_issued", 
                         user_id=user_info['user_id'],
                         details={
                             "client_id": client_id,
                             "requested_scopes": requested_scopes,
                             "offline_access_requested": "offline_access" in requested_scopes
                         })
                
                return RedirectResponse(redirect_url)
                
            except Exception as e:
                logger.error(f"Virtual authorize error: {e}")
                return JSONResponse({"error": "server_error"}, status_code=500)

        @self.mcp.custom_route("/oauth/consent", methods=["GET", "POST", "OPTIONS"])
        async def oauth_consent(request: Request) -> Response:
            """Enhanced OAuth consent page and handler"""
            if request.method == "OPTIONS":
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type"
                    }
                )
            
            if request.method == "GET":
                # Display enhanced consent page
                client_id = request.query_params.get('client_id')
                redirect_uri = request.query_params.get('redirect_uri')
                state = request.query_params.get('state')
                scope = request.query_params.get('scope', '')
                code_challenge = request.query_params.get('code_challenge')
                user_agent = request.headers.get('User-Agent', '')
                
                if not client_id or client_id not in self.session_manager.virtual_clients:
                    return Response("Invalid client", status_code=400)
                
                virtual_client = self.session_manager.virtual_clients[client_id]
                client_name = virtual_client.name or client_id
                
                # Generate enhanced consent page
                consent_html = self._get_consent_template(
                    client_id, client_name, redirect_uri, state, scope, code_challenge, user_agent
                )
                
                logger.info(f"🔐 Enhanced consent page displayed for client: {client_id}")
                audit_log("consent_page_displayed", details={
                    "client_id": client_id,
                    "client_name": client_name,
                    "user_agent_type": self._identify_client_type(user_agent)
                })
                
                response = Response(consent_html, media_type="text/html")
                return self.session_manager.add_security_headers(response)
                
            elif request.method == "POST":
                # Handle consent response with FastMCP-compatible storage
                form_data = await request.form()
                client_id = form_data.get('client_id')
                redirect_uri = form_data.get('redirect_uri')
                state = form_data.get('state')
                scope = form_data.get('scope')
                code_challenge = form_data.get('code_challenge')
                action = form_data.get('action')
                
                if action == "deny":
                    # User denied consent
                    logger.info(f"❌ Consent denied for client: {client_id}")
                    audit_log("consent_denied", details={
                        "client_id": client_id,
                        "reason": "user_denied"
                    })
                    
                    if redirect_uri:
                        error_params = {
                            'error': 'access_denied',
                            'error_description': 'User denied the request'
                        }
                        if state:
                            error_params['state'] = state
                        error_url = f"{redirect_uri}?{urlencode(error_params)}"
                        return RedirectResponse(error_url)
                    else:
                        return Response("Access denied", status_code=403)
                
                elif action == "allow":
                    # Store pending consent using FastMCP-compatible approach (primary: memory, fallback: session)
                    consent_key = f"consent_{client_id}"
                    consent_data = {
                        'virtual_client_id': client_id,
                        'redirect_uri': redirect_uri,
                        'state': state,
                        'scope': scope.split() if scope else [],
                        'code_challenge': code_challenge,
                        'granted_at': datetime.now(timezone.utc).isoformat()
                    }
                    
                    # Store in memory (reliable for FastMCP custom routes)
                    self.session_manager.state_store[consent_key] = consent_data
                    
                    # Also store in session using consistent key pattern
                    try:
                        if hasattr(request, 'session') and hasattr(request.session, '__setitem__'):
                            request.session[consent_key] = consent_data
                            logger.debug(f"Stored consent {consent_key} in session")
                    except Exception as e:
                        logger.debug(f"Could not store consent in session (normal for FastMCP routes): {e}")
                    
                    logger.info(f"✅ Consent granted for client: {client_id}")
                    audit_log("consent_granted", details={
                        "client_id": client_id,
                        "granted_scopes": scope.split() if scope else []
                    })
                    
                    # Redirect back to authorize endpoint with GET to continue OAuth flow
                    auth_params = {
                        'client_id': client_id,
                        'redirect_uri': redirect_uri,
                        'response_type': 'code',
                        'scope': scope,
                        'code_challenge': code_challenge,
                        'code_challenge_method': 'S256'
                    }
                    if state:
                        auth_params['state'] = state
                        
                    auth_url = f"/oauth/authorize?{urlencode(auth_params)}"
                    return RedirectResponse(auth_url)
                
                return Response("Invalid action", status_code=400)
        
        @self.mcp.custom_route("/oauth/token", methods=["POST", "OPTIONS"])
        async def oauth_token_virtual(request: Request) -> JSONResponse:
            """Virtual OAuth token endpoint - handles authorization_code and refresh_token grants"""
            if request.method == "OPTIONS":
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization, User-Agent, Accept, Accept-Language, Accept-Encoding, Cache-Control, Connection, Host, Origin, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site"
                    }
                )
                
            try:
                # Parse form data
                form_data = await request.form()
                grant_type = form_data.get("grant_type")
                
                if grant_type == "authorization_code":
                    return await self._handle_authorization_code_grant(request, form_data)
                elif grant_type == "refresh_token":
                    return await self._handle_refresh_token_grant(request, form_data)
                else:
                    response = JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
                    response.headers["Access-Control-Allow-Origin"] = "*"
                    return self.session_manager.add_security_headers(response)
                    
            except Exception as e:
                logger.error(f"Virtual token error: {e}")
                response = JSONResponse({"error": "server_error"}, status_code=500)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
        
        @self.mcp.custom_route("/oauth/userinfo", methods=["GET", "POST", "OPTIONS"])
        async def oauth_userinfo_virtual(request: Request) -> JSONResponse:
            """Virtual OAuth userinfo endpoint"""
            if request.method == "OPTIONS":
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization"
                    }
                )
                
            try:
                # Get access token from Authorization header
                auth_header = request.headers.get("authorization", "")
                if not auth_header.startswith("Bearer "):
                    return JSONResponse({"error": "invalid_token"}, status_code=401)
                
                access_token = auth_header[7:]  # Remove "Bearer "
                
                if access_token not in self.session_manager.tokens:
                    return JSONResponse({"error": "invalid_token"}, status_code=401)
                
                token_data = self.session_manager.tokens[access_token]
                
                # Check token expiration
                if datetime.now(timezone.utc) > token_data["expires_at"]:
                    return JSONResponse({"error": "invalid_token", "error_description": "Token expired"}, status_code=401)
                
                # Get user info from session (groups not stored in session)
                user_info = await self.session_manager.get_user_from_session(request)
                if not user_info:
                    return JSONResponse({"error": "invalid_token"}, status_code=401)
                
                # For userinfo endpoint, we need to get fresh groups if 'groups' scope was requested
                # This is required by OAuth spec when groups scope is present
                user_id = user_info.get('user_id')
                userinfo_claims = {
                    "sub": user_info.get('user_id'),
                    "name": user_info.get('name'),
                    "email": user_info.get('email'),
                    "preferred_username": user_info.get('email')
                }
                
                # Only include groups if the token has 'groups' scope
                token_data = self.session_manager.tokens.get(access_token, {})
                token_scopes = token_data.get('scopes', [])
                
                if 'groups' in token_scopes:
                    # Get fresh groups from real token store (don't store in session)
                    if user_id in self.session_manager.real_token_store:
                        real_tokens = self.session_manager.real_token_store[user_id]
                        real_access_token = real_tokens.get('access_token')
                        
                        # Fetch fresh userinfo from Okta to get current groups
                        try:
                            async with httpx.AsyncClient() as client:
                                userinfo_url = f"{self.oauth_config.org_url}/oauth2/v1/userinfo"
                                userinfo_response = await client.get(
                                    userinfo_url,
                                    headers={'Authorization': f'Bearer {real_access_token}'}
                                )
                                if userinfo_response.status_code == 200:
                                    okta_userinfo = userinfo_response.json()
                                    userinfo_claims["groups"] = okta_userinfo.get('groups', [])
                        except Exception as e:
                            logger.warning(f"Failed to fetch fresh groups for userinfo: {e}")
                            userinfo_claims["groups"] = []  # Fallback to empty groups
                
                # Return userinfo claims
                userinfo = userinfo_claims
                
                response = JSONResponse(userinfo)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
                
            except Exception as e:
                logger.error(f"Virtual userinfo error: {e}")
                return JSONResponse({"error": "server_error"}, status_code=500)
        
        @self.mcp.custom_route("/oauth/callback", methods=["GET"])
        async def oauth_callback(request: Request) -> Response:
            """OAuth callback handler for Okta authentication"""
            try:
                code = request.query_params.get("code")
                state = request.query_params.get("state")
                error = request.query_params.get("error")
                
                if error:
                    logger.error(f"OAuth callback error: {error}")
                    return Response(f"OAuth error: {error}", status_code=400)
                
                if not code or not state:
                    return Response("Missing code or state parameter", status_code=400)
                
                # Retrieve stored state information (try session first, fallback to in-memory)
                state_data = None
                
                # First try to get from session (more reliable for cloud deployments)
                if hasattr(request, 'session') and f"oauth_state_{state}" in request.session:
                    state_data = request.session[f"oauth_state_{state}"]
                    logger.info(f"Found state in session for {state}")
                    # Clean up from session
                    del request.session[f"oauth_state_{state}"]
                elif state in self.session_manager.state_store:
                    state_data = self.session_manager.state_store[state]
                    logger.info(f"Found state in memory store for {state}")
                    # Clean up from memory store
                    del self.session_manager.state_store[state]
                else:
                    logger.error(f"Invalid or expired state: {state} (not found in session or memory)")
                    # Debug: list available states
                    logger.debug(f"Available in-memory states: {list(self.session_manager.state_store.keys())}")
                    if hasattr(request, 'session'):
                        session_states = [k for k in request.session.keys() if k.startswith("oauth_state_")]
                        logger.debug(f"Available session states: {session_states}")
                    return Response("Invalid or expired state", status_code=400)
                
                if not state_data:
                    logger.error(f"State data is None for state: {state}")
                    return Response("Invalid state data", status_code=400)
                virtual_client_id = state_data.get('virtual_client_id')
                original_redirect_uri = state_data.get('original_redirect_uri')
                original_state = state_data.get('original_state')
                original_scope = state_data.get('original_scope')
                code_challenge = state_data.get('code_challenge')
                code_verifier = state_data.get('code_verifier')
                pending_consent = state_data.get('pending_consent')
                
                # Clean up the state
                del self.session_manager.state_store[state]
                
                # Exchange code for tokens with Okta
                token_data = {
                    'grant_type': 'authorization_code',
                    'client_id': self.oauth_config.client_id,
                    'client_secret': self.oauth_config.client_secret,
                    'code': code,
                    'redirect_uri': self.oauth_config.redirect_uri,
                    'code_verifier': code_verifier
                }
                
                async with httpx.AsyncClient() as client:
                    token_response = await client.post(
                        self.oauth_config.token_url,
                        data=token_data,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'}
                    )
                    
                    if token_response.status_code != 200:
                        logger.error(f"Token exchange failed: {token_response.text}")
                        return Response("Token exchange failed", status_code=500)
                    
                    tokens = token_response.json()
                    access_token = tokens.get('access_token')
                    id_token = tokens.get('id_token')
                    refresh_token = tokens.get('refresh_token')
                    
                    # SECURITY: Validate ID token with proper JWT validation
                    if id_token:
                        id_token_result = await self.session_manager.jwt_validator.validate_id_token(id_token)
                        if not id_token_result.is_valid:
                            logger.error(f"ID token validation failed: {id_token_result.error}")
                            return Response(f"ID token validation failed: {id_token_result.error}", status_code=400)
                        
                        # Extract user info from validated ID token (more secure than userinfo endpoint)
                        user_info = self.session_manager.jwt_validator.get_user_info_from_claims(id_token_result.user_claims)
                        logger.info(f"ID token validation successful for user: {user_info.get('email')}")
                    else:
                        # Fallback to userinfo endpoint if no ID token
                        userinfo_url = f"{self.oauth_config.org_url}/oauth2/v1/userinfo"
                        userinfo_response = await client.get(
                            userinfo_url,
                            headers={'Authorization': f'Bearer {access_token}'}
                        )
                        
                        if userinfo_response.status_code != 200:
                            logger.error(f"Userinfo request failed: {userinfo_response.text}")
                            return Response("Failed to get user info", status_code=500)
                        
                        user_info = userinfo_response.json()
                    
                    # SECURITY: Validate refresh token if present
                    if refresh_token:
                        refresh_token_result = await self.session_manager.jwt_validator.validate_refresh_token(refresh_token)
                        if not refresh_token_result.is_valid:
                            logger.error(f"Refresh token validation failed: {refresh_token_result.error}")
                            # Don't fail the flow, but log the issue
                            refresh_token = None
                
                # Store user info in session (NO real Okta tokens stored in session)
                # IMPORTANT: JWT validator already maps 'sub' to 'user_id' for consistency
                session_user_info = {
                    'user_id': user_info.get('user_id'),  # JWT validator maps 'sub' -> 'user_id'
                    'email': user_info.get('email'),
                    'name': user_info.get('name'),
                    'scopes': tokens.get('scope', '').split(),
                    'authenticated': True
                    # NOTE: Real Okta tokens stored separately for security
                    # NOTE: Groups not stored - only the mapped role is kept
                }
                
                # Map user role from groups (but don't store the groups)
                groups = user_info.get('groups', [])
                session_user_info['rbac_role'] = self.session_manager.role_mapper.get_user_role(groups)
                
                # SECURITY: Store real Okta tokens securely (separate from user session)
                # This allows us to refresh tokens and validate user state with Okta
                user_id = user_info.get('user_id')  # JWT validator already mapped 'sub' -> 'user_id'
                self.session_manager.real_token_store[user_id] = {
                    'access_token': access_token,
                    'refresh_token': refresh_token,  # Store real refresh token securely
                    'id_token': id_token,
                    'expires_at': datetime.now(timezone.utc) + timedelta(seconds=tokens.get('expires_in', 3600)),
                    'updated_at': datetime.now(timezone.utc)
                }
                
                # Store in session (if available) and memory
                try:
                    if hasattr(request, 'session'):
                        request.session['authenticated'] = True
                        request.session['user_info'] = session_user_info
                except Exception as e:
                    logger.debug(f"Could not store in session (normal for FastMCP): {e}")
                
                # Also store in memory for token-based access
                session_token = secrets.token_urlsafe(32)
                self.session_manager.tokens[session_token] = {
                    **session_user_info,
                    'expires_at': datetime.now(timezone.utc) + timedelta(hours=8)
                }
                
                # Finalize consent if it was pending
                if pending_consent:
                    user_consent = UserConsent(
                        user_id=user_info.get('user_id'),  # JWT validator mapped 'sub' -> 'user_id'
                        virtual_client_id=virtual_client_id,
                        scopes=original_scope.split() if original_scope else [],
                        granted_at=datetime.now(timezone.utc),
                        expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
                    )
                    
                    consent_key = f"{user_info.get('user_id')}_{virtual_client_id}"
                    self.session_manager.user_consents[consent_key] = user_consent
                
                # Generate virtual authorization code for the original client
                auth_code = secrets.token_urlsafe(32)
                code_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
                
                # Get the role that was determined earlier in the OAuth callback
                user_id_from_okta = user_info.get('user_id')  # JWT validator already mapped 'sub' -> 'user_id'
                user_role = session_user_info.get('rbac_role', 'viewer')
                
                auth_code_obj = AuthorizationCode(
                    code=auth_code,
                    client_id=virtual_client_id,
                    user_id=user_id_from_okta,
                    scopes=original_scope.split() if original_scope else ["openid", "profile", "email"],
                    code_challenge=code_challenge,
                    code_challenge_method="S256",
                    redirect_uri=original_redirect_uri,
                    created_at=datetime.now(timezone.utc),
                    expires_at=code_expires_at,
                    rbac_role=user_role
                )
                
                # Convert to dict explicitly for consistent storage
                auth_code_dict = {
                    'code': auth_code_obj.code,
                    'client_id': auth_code_obj.client_id,
                    'user_id': auth_code_obj.user_id,
                    'scopes': auth_code_obj.scopes,
                    'code_challenge': auth_code_obj.code_challenge,
                    'code_challenge_method': auth_code_obj.code_challenge_method,
                    'redirect_uri': auth_code_obj.redirect_uri,
                    'created_at': auth_code_obj.created_at,
                    'expires_at': auth_code_obj.expires_at,
                    'rbac_role': auth_code_obj.rbac_role,  # Include role in stored data
                    'used': getattr(auth_code_obj, 'used', False)
                }
                
                self.session_manager.authorization_codes[auth_code] = auth_code_dict
                
                # Redirect back to the original client
                params = {"code": auth_code}
                if original_state:
                    params["state"] = original_state
                
                redirect_url = f"{original_redirect_uri}?{urlencode(params)}"
                
                logger.info(f"OAuth callback completed, redirecting to: {original_redirect_uri}")
                audit_log("oauth_callback_completed", 
                         user_id=user_info.get('user_id'),  # JWT validator mapped 'sub' -> 'user_id'
                         details={
                             "virtual_client_id": virtual_client_id,
                             "user_email": user_info.get('email'),
                             "scopes": original_scope.split() if original_scope else []
                         })
                
                return RedirectResponse(redirect_url)
                
            except Exception as e:
                logger.error(f"OAuth callback error: {e}")
                return Response(f"OAuth callback failed: {str(e)}", status_code=500)
        
        logger.info("OAuth routes registered successfully")
    
    async def _handle_authorization_code_grant(self, request: Request, form_data) -> JSONResponse:
        """Handle authorization_code grant type"""
        code = form_data.get("code")
        client_id = form_data.get("client_id")
        code_verifier = form_data.get("code_verifier")
        
        # Validate authorization code
        if code not in self.session_manager.authorization_codes:
            response = JSONResponse({"error": "invalid_grant"}, status_code=400)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
            
        auth_code_obj = self.session_manager.authorization_codes[code]
        
        # Verify client and expiration
        if auth_code_obj["client_id"] != client_id:
            response = JSONResponse({"error": "invalid_client"}, status_code=400)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
            
        if datetime.now(timezone.utc) > auth_code_obj["expires_at"]:
            response = JSONResponse({"error": "invalid_grant"}, status_code=400)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
        
        # Verify PKCE if provided
        if code_verifier and auth_code_obj.get("code_challenge"):
            computed_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('ascii')).digest()
            ).decode('ascii').strip('=')
            
            if computed_challenge != auth_code_obj["code_challenge"]:
                response = JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
        
        # Generate virtual access token (client gets virtual token, we keep real Okta token)
        virtual_access_token = secrets.token_urlsafe(32)
        virtual_refresh_token = secrets.token_urlsafe(32) if "offline_access" in auth_code_obj["scopes"] else None
        
        expires_in = 3600  # 1 hour
        token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        
        # Store virtual token mapping (NO real Okta tokens stored here)
        user_id = auth_code_obj["user_id"]
        
        virtual_token_data = {
            "access_token": virtual_access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "expires_at": token_expires_at,
            "scopes": auth_code_obj["scopes"],
            "client_id": client_id,
            "user_id": user_id,
            "rbac_role": auth_code_obj.get("rbac_role", "viewer"),  # Include role for RBAC
            "grant_type": "authorization_code"
        }
        
        # Store virtual refresh token mapping if offline_access was requested
        if virtual_refresh_token:
            virtual_token_data["virtual_refresh_token"] = virtual_refresh_token
            # Store refresh token mapping separately for lookup during refresh grant
            self.session_manager.refresh_token_mappings[virtual_refresh_token] = {
                "user_id": user_id,
                "client_id": client_id,
                "scopes": auth_code_obj["scopes"],
                "created_at": datetime.now(timezone.utc)
            }
        
        self.session_manager.tokens[virtual_access_token] = virtual_token_data
        
        # Clean up used authorization code
        del self.session_manager.authorization_codes[code]
        
        # Prepare response with virtual tokens - only include refresh token if offline_access scope was requested
        response_data = {
            "access_token": virtual_access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": " ".join(auth_code_obj["scopes"])
        }
        
        # Only include refresh token if client originally requested offline_access scope (RFC 6749 Section 6 compliance)
        if virtual_refresh_token:
            response_data["refresh_token"] = virtual_refresh_token
            logger.info(f"Refresh token included in response for client {client_id}")
        else:
            logger.info("Refresh token omitted from response (offline_access scope not requested)")
        
        logger.info(f"Virtual access token issued for client {client_id}, user {user_id}")
        audit_log("access_token_issued", 
                 user_id=user_id,
                 details={
                     "client_id": client_id,
                     "scopes": auth_code_obj["scopes"],
                     "has_refresh_token": bool(virtual_refresh_token),
                     "grant_type": "authorization_code"
                 })
        
        response = JSONResponse(response_data)
        response.headers["Access-Control-Allow-Origin"] = "*"
        return self.session_manager.add_security_headers(response)
    
    async def _handle_refresh_token_grant(self, request: Request, form_data) -> JSONResponse:
        """Handle refresh_token grant type - exchanges virtual refresh token for new virtual access token"""
        refresh_token = form_data.get("refresh_token")
        client_id = form_data.get("client_id")
        
        if not refresh_token or not client_id:
            response = JSONResponse({"error": "invalid_request", "error_description": "refresh_token and client_id required"}, status_code=400)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
        
        # Validate virtual refresh token
        if refresh_token not in self.session_manager.refresh_token_mappings:
            response = JSONResponse({"error": "invalid_grant", "error_description": "Invalid refresh token"}, status_code=400)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
        
        refresh_data = self.session_manager.refresh_token_mappings[refresh_token]
        
        # Verify client matches
        if refresh_data["client_id"] != client_id:
            response = JSONResponse({"error": "invalid_client"}, status_code=400)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)
        
        user_id = refresh_data["user_id"]
        original_scopes = refresh_data["scopes"]
        
        try:
            # SECURITY: Use real Okta refresh token to get fresh tokens and user info
            if user_id not in self.session_manager.real_token_store:
                response = JSONResponse({"error": "invalid_grant", "error_description": "User session expired - no stored tokens"}, status_code=400)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
            
            real_tokens = self.session_manager.real_token_store[user_id]
            real_refresh_token = real_tokens.get('refresh_token')
            
            if not real_refresh_token:
                response = JSONResponse({"error": "invalid_grant", "error_description": "No refresh token available"}, status_code=400)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
            
            async with httpx.AsyncClient() as client:
                # SECURITY: Use real Okta refresh token to get fresh access token
                refresh_data = {
                    'grant_type': 'refresh_token',
                    'client_id': self.oauth_config.client_id,
                    'client_secret': self.oauth_config.client_secret,
                    'refresh_token': real_refresh_token,
                    'scope': ' '.join(original_scopes)
                }
                
                # Exchange refresh token with Okta
                token_response = await client.post(
                    self.oauth_config.token_url,
                    data=refresh_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                if token_response.status_code != 200:
                    logger.error(f"Okta refresh token exchange failed: {token_response.text}")
                    response = JSONResponse({"error": "invalid_grant", "error_description": "Refresh token expired or invalid"}, status_code=400)
                    response.headers["Access-Control-Allow-Origin"] = "*"
                    return self.session_manager.add_security_headers(response)
                
                new_tokens = token_response.json()
                new_access_token = new_tokens.get('access_token')
                new_id_token = new_tokens.get('id_token')
                new_refresh_token = new_tokens.get('refresh_token', real_refresh_token)  # Use new or keep existing
                
                # SECURITY: Validate new ID token to get updated user info and groups
                if new_id_token:
                    id_token_result = await self.session_manager.jwt_validator.validate_id_token(new_id_token)
                    if not id_token_result.is_valid:
                        logger.error(f"Refresh: ID token validation failed: {id_token_result.error}")
                        response = JSONResponse({"error": "server_error", "error_description": "Token validation failed"}, status_code=500)
                        response.headers["Access-Control-Allow-Origin"] = "*"
                        return self.session_manager.add_security_headers(response)
                    
                    # Extract fresh user info from validated ID token
                    fresh_user_info = self.session_manager.jwt_validator.get_user_info_from_claims(id_token_result.user_claims)
                    logger.info(f"Refresh: ID token validation successful, updated user info for: {fresh_user_info.get('email')}")
                else:
                    # Fallback to userinfo endpoint if no ID token
                    userinfo_url = f"{self.oauth_config.org_url}/oauth2/v1/userinfo"
                    userinfo_response = await client.get(
                        userinfo_url,
                        headers={'Authorization': f'Bearer {new_access_token}'}
                    )
                    
                    if userinfo_response.status_code != 200:
                        logger.error(f"Refresh: Userinfo request failed: {userinfo_response.text}")
                        response = JSONResponse({"error": "server_error", "error_description": "Failed to get user info"}, status_code=500)
                        response.headers["Access-Control-Allow-Origin"] = "*"
                        return self.session_manager.add_security_headers(response)
                    
                    fresh_user_info = userinfo_response.json()
                
                # SECURITY: Update stored real tokens
                self.session_manager.real_token_store[user_id] = {
                    'access_token': new_access_token,
                    'refresh_token': new_refresh_token,
                    'id_token': new_id_token,
                    'expires_at': datetime.now(timezone.utc) + timedelta(seconds=new_tokens.get('expires_in', 3600)),
                    'updated_at': datetime.now(timezone.utc)
                }
                
                # SECURITY: Re-evaluate user role based on fresh groups from Okta
                current_groups = fresh_user_info.get('groups', [])
                current_role = self.session_manager.role_mapper.get_user_role(current_groups)
                
                # Generate new virtual tokens for the client
                new_virtual_access_token = secrets.token_urlsafe(32)
                new_virtual_refresh_token = secrets.token_urlsafe(32)  # Always issue new virtual refresh token
                
                expires_in = 3600  # 1 hour
                token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                
                # Store new virtual token mapping with updated role and fresh user info
                new_virtual_token_data = {
                    "access_token": new_virtual_access_token,
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                    "expires_at": token_expires_at,
                    "scopes": original_scopes,
                    "client_id": client_id,
                    "user_id": user_id,
                    "grant_type": "refresh_token",
                    "virtual_refresh_token": new_virtual_refresh_token,
                    "rbac_role": current_role,  # Updated role (groups not stored)
                    "email": fresh_user_info.get('email'),
                    "name": fresh_user_info.get('name')
                    # NOTE: Groups not stored in token data - only the mapped role
                }
                
                self.session_manager.tokens[new_virtual_access_token] = new_virtual_token_data
                
                # Update refresh token mapping (invalidate old, create new)
                del self.session_manager.refresh_token_mappings[refresh_token]  # Invalidate old refresh token
                self.session_manager.refresh_token_mappings[new_virtual_refresh_token] = {
                    "user_id": user_id,
                    "client_id": client_id,
                    "scopes": original_scopes,
                    "created_at": datetime.now(timezone.utc)
                }
                
                # Prepare response - only include refresh token if client originally requested offline_access scope  
                response_data = {
                    "access_token": new_virtual_access_token,
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                    "scope": " ".join(original_scopes)
                }
                
                # Only include refresh token if client originally requested offline_access scope (RFC 6749 Section 6 compliance)
                if "offline_access" in original_scopes:
                    response_data["refresh_token"] = new_virtual_refresh_token
                    logger.info("Refresh token included in response (offline_access scope requested)")
                else:
                    logger.info("Refresh token omitted from response (offline_access scope not requested)")
                
                logger.info(f"Virtual tokens refreshed for client {client_id}, user {user_id}, role updated to: {current_role}")
                audit_log("access_token_refreshed", 
                         user_id=user_id,
                         details={
                             "client_id": client_id,
                             "scopes": original_scopes,
                             "updated_role": current_role,
                             "grant_type": "refresh_token"
                             # NOTE: Groups not logged for privacy/performance
                         })
                
                response = JSONResponse(response_data)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return self.session_manager.add_security_headers(response)
                
        except Exception as e:
            logger.error(f"Refresh token error: {e}")
            response = JSONResponse({"error": "server_error"}, status_code=500)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return self.session_manager.add_security_headers(response)

    def _get_consent_template(self, client_id: str, client_name: str, redirect_uri: str, state: str, scope: str, code_challenge: str, user_agent: str) -> str:
        """Generate business-appropriate consent page HTML (ported from old proxy)"""
        scopes = scope.split() if scope else []
        
        # Enhanced scope descriptions with better categorization  
        scope_descriptions = {
            # Identity & Profile Scopes
            'openid': 'Verify your identity',
            'profile': 'Access your basic profile information (name, username)',
            'email': 'Access your email address',
            'address': 'Access your address information',
            'phone': 'Access your phone number',
            'groups': 'Access your group memberships',
            'offline_access': 'Maintain access when you\'re offline',

            # Okta API Scopes (what the server actually uses)
            'okta.users.read': 'View users in your Okta tenant',
            'okta.groups.read': 'View groups in your Okta tenant',
            'okta.apps.read': 'View applications in your Okta tenant',
            'okta.events.read': 'View system events in your Okta tenant',
            'okta.logs.read': 'View audit logs in your Okta tenant',
            'okta.policies.read': 'View security policies in your Okta tenant',
            'okta.devices.read': 'View registered devices in your Okta tenant',
            'okta.factors.read': 'View authentication factors in your Okta tenant'
        }
        
        client_type = self._identify_client_type(user_agent)
        client_domain = self._get_redirect_domain(redirect_uri) if redirect_uri else "Unknown Domain"
        okta_domain = self.oauth_config.org_url.replace("https://", "") if self.oauth_config.org_url else "your-tenant.okta.com"
        
        # Get client type for display (optional, only show if meaningful)
        client_type_display = ""
        if user_agent and client_type and not client_type.startswith("Unknown"):
            client_type_display = client_type
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Request</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(180deg, #e5eaf5, #f0f4fb);
            min-height: 100vh;
            position: relative;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
            font-feature-settings: 'cv02', 'cv03', 'cv04', 'cv11';
            font-optical-sizing: auto;
            text-rendering: optimizeLegibility;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }}

        .consent-card {{
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.08), 0 8px 30px rgba(0,0,0,0.06);
            max-width: 520px;
            width: 100%;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.8);
            backdrop-filter: blur(10px);
            position: relative;
        }}

        .consent-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.6), transparent);
            pointer-events: none;
        }}

        .header {{
            background: white;
            padding: 40px 32px 40px;
            text-align: center;
            border-bottom: 1px solid #f0f0f0;
        }}

        .logo-container {{
            width: 60px;
            height: 60px;
            border-radius: 50%;
            margin: 0 auto 20px;
            position: relative;
            background: white;
            padding: 8px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            border: 2px solid #e5eaf5;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        .logo-container img {{
            width: 80%;
            height: 80%;
            object-fit: contain;
            border-radius: 50%;
        }}

        .header h1 {{
            color: #1a1a1a;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 8px;
            text-align: center;
        }}

        .header p {{
            color: #666;
            font-size: 14px;
            text-align: center;
        }}

        .header .tenant-info {{
            color: #666;
            font-size: 12px;
            font-weight: 500;
            margin-top: 12px;
            text-align: center;
        }}

        .content {{
            padding: 40px 32px 40px;
        }}

        .client-info {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
        }}

        .client-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}

        .client-row:last-child {{
            margin-bottom: 0;
        }}

        .client-label {{
            color: #666;
            font-size: 13px;
            font-weight: 500;
        }}

        .client-value {{
            color: #1a1a1a;
            font-size: 13px;
            font-weight: 600;
            text-align: right;
            max-width: 60%;
            word-break: break-word;
        }}

        .permissions-summary {{
            margin-bottom: 24px;
        }}

        .permissions-summary h3 {{
            color: #1a1a1a;
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 12px;
        }}

        .permission-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 0;
            border-bottom: 1px solid #f0f0f0;
        }}

        .permission-item:last-child {{
            border-bottom: none;
        }}

        .permission-icon {{
            color: #0066cc;
            font-size: 14px;
            width: 16px;
        }}

        .permission-text {{
            color: #333;
            font-size: 14px;
        }}

        .notice {{
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 14px;
            line-height: 1.5;
            color: #334155;
            text-align: left;
        }}

        .notice p {{
            margin-bottom: 12px;
        }}

        .notice p:last-child {{
            margin-bottom: 0;
        }}

        .notice strong {{
            color: #1e293b;
            font-weight: 600;
        }}

        .actions {{
            display: flex;
            gap: 12px;
            margin-top: 8px;
        }}

        .action-form {{
            flex: 1;
            margin: 0;
        }}

        .btn {{
            flex: 1;
            padding: 16px 28px;
            border: none;
            border-radius: 12px;
            font-size: 15px;
            font-weight: 600;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            letter-spacing: -0.01em;
            position: relative;
            outline: none;
            text-decoration: none;
            user-select: none;
            min-height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
        }}

        .btn:focus {{
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
        }}

        .btn:hover {{
            transform: translateY(-1px);
        }}

        .btn:active {{
            transform: translateY(0);
            transition: transform 0.1s;
        }}

        .btn-primary {{
            background: linear-gradient(135deg, #8b9dc3 0%, #6b7a99 100%);
            color: white;
            border: 1px solid #6b7a99;
        }}

        .btn-primary:hover {{
            background: linear-gradient(135deg, #6b7a99 0%, #5a6580 100%);
            border-color: #5a6580;
        }}

        .btn-primary:active {{
            background: linear-gradient(135deg, #5a6580 0%, #4a5366 100%);
        }}

        .btn-secondary {{
            background: #f8f9fa;
            color: #495057;
            border: 2px solid #dee2e6;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}

        .btn-secondary:hover {{
            background: #e9ecef;
            border-color: #adb5bd;
            color: #343a40;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }}

        .btn-secondary:active {{
            background: #dee2e6;
            border-color: #6c757d;
        }}

        @media (max-width: 480px) {{
            .consent-card {{
                margin: 0 10px;
            }}

            .header, .content {{
                padding: 24px 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="consent-card">
        <div class="header">
            <div class="logo-container">
                <img src="/images/fctr-logo.png" alt="Fctr Identity Logo" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                <div style="display: none; width: 100%; height: 100%; align-items: center; justify-content: center; background: linear-gradient(135deg, #0066cc 0%, #004499 100%); color: white; font-weight: 700; font-size: 20px; border-radius: 50%;">F</div>
            </div>
            <h1>AI Agent Authorization</h1>
            <div class="tenant-info">Connecting to Okta Tenant: {okta_domain}</div>
        </div>

        <div class="content">
            <div class="client-info">
                <div class="client-row">
                    <span class="client-label">Application:</span>
                    <span class="client-value">{client_name}</span>
                </div>
                <div class="client-row">
                    <span class="client-label">Domain:</span>
                    <span class="client-value">{client_domain}</span>
                </div>
                <div class="client-row">
                    <span class="client-label">Platform:</span>
                    <span class="client-value">MCP Client Application</span>
                </div>
                {f'''
                <div class="client-row">
                    <span class="client-label">Client Type:</span>
                    <span class="client-value">{client_type_display}</span>
                </div>
                ''' if client_type_display else ''}
            </div>

            <div class="permissions-summary">
                <h3>Requested Access</h3>
                <div class="permission-item">
                    <span class="permission-icon">🏢</span>
                    <span class="permission-text">Interact with your Okta tenant</span>
                </div>
                <div class="permission-item">
                    <span class="permission-icon">👤</span>
                    <span class="permission-text">Access your profile information</span>
                </div>
                <div class="permission-item">
                    <span class="permission-icon">🛠️</span>
                    <span class="permission-text">Use MCP tools filtered for your access level</span>
                </div>
            </div>

            <div class="notice">
                <p><strong>You have an AI client requesting access to the MCP Server for Okta by Fctr Identity.</strong></p>
                <p><strong>Important:</strong> If you are not actively trying to connect an AI client or authorize access, please reject this request.</p>
            </div>

            <div class="actions">
                <form method="post" class="action-form">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="hidden" name="state" value="{state}">
                    <input type="hidden" name="scope" value="{scope}">
                    <input type="hidden" name="code_challenge" value="{code_challenge}">
                    <input type="hidden" name="action" value="allow">
                    <button type="submit" class="btn btn-primary">Authorize</button>
                </form>

                <form method="post" class="action-form">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="hidden" name="state" value="{state}">
                    <input type="hidden" name="action" value="deny">
                    <button type="submit" class="btn btn-secondary">Cancel</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"""

    def _identify_client_type(self, user_agent: str) -> str:
        """Identify client type from User-Agent header"""
        user_agent_lower = user_agent.lower()
        
        if 'claude' in user_agent_lower or 'anthropic' in user_agent_lower:
            return "Claude Desktop (AI Assistant)"
        elif 'cursor' in user_agent_lower:
            return "Cursor IDE"
        elif 'vscode' in user_agent_lower or 'code' in user_agent_lower:
            return "VS Code Extension"
        elif 'postman' in user_agent_lower:
            return "Postman API Client"
        elif 'curl' in user_agent_lower:
            return "cURL Command Line"
        elif 'python' in user_agent_lower:
            return "Python Application"
        elif 'chrome' in user_agent_lower or 'firefox' in user_agent_lower or 'safari' in user_agent_lower:
            return "Web Browser"
        else:
            return "Desktop Application"

    def _get_redirect_domain(self, redirect_uri: str) -> str:
        """Extract domain from redirect URI for display"""
        if not redirect_uri:
            return "Unknown"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(redirect_uri)
            if parsed.hostname:
                if 'localhost' in parsed.hostname or '127.0.0.1' in parsed.hostname:
                    return f"localhost:{parsed.port or 80}"
                else:
                    return parsed.hostname
            return "Invalid URI"
        except Exception:
            return "Parse Error"

    def _register_fastmcp_middleware(self):
        """Register FastMCP middleware for authentication and RBAC using proper middleware system"""
        
        from fastmcp.server.middleware import Middleware, MiddlewareContext
        from mcp.types import ErrorData
        from mcp import McpError
        
        class OAuthRBACMiddleware(Middleware):
            """FastMCP middleware for OAuth authentication and RBAC"""
            
            def __init__(self, session_manager):
                self.session_manager = session_manager
                # Load RBAC config directly instead of using external middleware
                import json
                import os
                config_path = os.path.join(os.path.dirname(__file__), 'auth', 'rbac_config.json')
                try:
                    with open(config_path, 'r') as f:
                        self.role_config = json.load(f)
                except (FileNotFoundError, json.JSONDecodeError) as e:
                    logger.error(f"Failed to load RBAC config: {e}")
                    self.role_config = {"roles": {"viewer": {"level": 1}}, "tools": {}}
                super().__init__()
            
            async def on_list_tools(self, context: MiddlewareContext, call_next):
                """Filter tools based on user authentication and RBAC"""
                try:
                    # Get user from context (set by HTTP middleware)
                    user_info = self.session_manager.get_current_user()
                    
                    if not user_info:
                        logger.warning("list_tools called without authentication")
                        audit_log("list_tools_unauthorized", details={"endpoint": "/mcp"})
                        
                        # Return empty list for unauthenticated requests
                        return []
                    
                    user_role = user_info.get('role')
                    logger.info(f"list_tools called by user {user_info.get('email') or user_info.get('user_id', 'unknown')} with role {user_role}")
                    
                    # Get all available tools from the original handler
                    result = await call_next(context)
                    
                    # Handle both list and dict formats
                    if isinstance(result, list):
                        # FastMCP returns a list of tools
                        all_tools = result
                        filtered_tools = []
                        
                        for tool in all_tools:
                            tool_name = tool.name if hasattr(tool, 'name') else str(tool)
                            
                            # Check RBAC permission directly
                            user_level = self.role_config.get('roles', {}).get(user_role, {}).get('level', 0)
                            tool_permissions = self.role_config.get('tools', {})
                            required_level = tool_permissions.get(tool_name, {}).get('min_level', 1)
                            
                            if user_level >= required_level:
                                filtered_tools.append(tool)
                    else:
                        # Handle dict/object format if needed
                        filtered_tools = result
                    
                    audit_log("list_tools_filtered", 
                             user_id=user_info.get('user_id'),
                             details={
                                 "user_role": user_role,
                                 "total_tools": len(all_tools) if isinstance(result, list) else 0,
                                 "filtered_tools": len(filtered_tools) if isinstance(filtered_tools, list) else 0
                             })
                    
                    logger.info(f"Filtered {len(all_tools) if isinstance(result, list) else 'unknown'} tools to {len(filtered_tools) if isinstance(filtered_tools, list) else 'unknown'} for role {user_role}")
                    
                    return filtered_tools
                    
                except Exception as e:
                    logger.error(f"Error in list_tools middleware: {e}")
                    audit_log("list_tools_error", details={"error": str(e)})
                    return []
            
            async def on_call_tool(self, context: MiddlewareContext, call_next):
                """Authenticate and authorize tool execution"""
                tool_name = "unknown"  # Initialize early to avoid unbound variable errors
                try:
                    # FastMCP v2.10 format - tool name and arguments are directly on the message
                    tool_name = getattr(context.message, 'name', "unknown")
                    arguments = getattr(context.message, 'arguments', {})
                    
                    # Get user from context (set by HTTP middleware)
                    user_info = self.session_manager.get_current_user()
                    
                    if not user_info:
                        logger.warning(f"Tool '{tool_name}' called without authentication")
                        audit_log("call_tool_unauthorized", 
                                 details={"tool_name": tool_name, "endpoint": "/mcp"})
                        raise McpError(ErrorData(code=-32000, message="Authentication required to execute tools"))
                    
                    user_role = user_info.get('role')
                    logger.info(f"Tool '{tool_name}' called by user {user_info.get('email') or user_info.get('user_id', 'unknown')} with role {user_role}")
                    
                    # Check RBAC permissions directly
                    user_level = self.role_config.get('roles', {}).get(user_role, {}).get('level', 0)
                    tool_permissions = self.role_config.get('tools', {})
                    required_level = tool_permissions.get(tool_name, {}).get('min_level', 1)
                    
                    if user_level < required_level:
                        logger.warning(f"Tool '{tool_name}' execution denied for role {user_role}")
                        audit_log("call_tool_forbidden", 
                                 user_id=user_info.get('user_id'),
                                 details={
                                     "tool_name": tool_name,
                                     "user_role": user_role,
                                     "arguments": arguments
                                 })
                        raise McpError(ErrorData(code=-32000, message=f"Insufficient permissions to execute tool '{tool_name}'"))
                    
                    # Log successful authorization
                    audit_log("call_tool_authorized", 
                             user_id=user_info.get('user_id'),
                             details={
                                 "tool_name": tool_name,
                                 "user_role": user_role,
                                 "arguments": arguments
                             })
                    
                    # Execute the tool via the original handler
                    logger.info(f"Executing tool '{tool_name}' for user {user_info.get('email') or user_info.get('user_id', 'unknown')}")
                    result = await call_next(context)
                    
                    audit_log("call_tool_success", 
                             user_id=user_info.get('user_id'),
                             details={
                                 "tool_name": tool_name,
                                 "user_role": user_role
                             })
                    
                    return result
                    
                except McpError:
                    # Re-raise MCP errors
                    raise
                except Exception as e:
                    logger.error(f"Error executing tool '{tool_name}': {e}")
                    # Get user info safely for audit logging
                    try:
                        current_user = self.session_manager.get_current_user()
                        user_id = current_user.get('user_id') if current_user else None
                    except:
                        user_id = None
                    
                    audit_log("call_tool_error", 
                             user_id=user_id,
                             details={
                                 "tool_name": tool_name,
                                 "error": str(e)
                             })
                    raise McpError(ErrorData(code=-32000, message=f"Tool execution error: {str(e)}"))
        
        # Add the middleware to our FastMCP server
        middleware = OAuthRBACMiddleware(self.session_manager)
        self.mcp.add_middleware(middleware)
        
        logger.info("FastMCP middleware registered successfully")
        logger.info("MCP endpoints now protected with OAuth authentication and RBAC filtering")
    
    def create_app(self, host: str = "localhost", port: int = 3001):
        """Create ASGI application with session middleware and OAuth authentication"""
        
        # Generate secure session key
        session_key = generate_secure_session_key()
        
        # Use the standard FastMCP HTTP app
        # Custom routes registered via @custom_route decorators should be included
        # Mount at /mcp (no trailing slash) to avoid redirect issues with MCP clients
        app = self.mcp.http_app(path="/mcp")
        
        # Add session middleware
        from starlette.middleware.sessions import SessionMiddleware
        app.add_middleware(
            SessionMiddleware,
            secret_key=session_key,
            max_age=7200,  # 2 hours
            https_only=self.oauth_config.require_https and "localhost" not in host,
            same_site='lax'
        )
        
        # Add authentication middleware
        from starlette.middleware.base import BaseHTTPMiddleware
        
        # Define a custom ASGI middleware that rewrites the path at the ASGI level
        class MCPPathRewriteMiddleware:
            """Pure ASGI middleware to rewrite /mcp requests to /mcp/ to avoid FastMCP redirect issues"""
            
            def __init__(self, app):
                self.app = app
            
            async def __call__(self, scope, receive, send):
                """ASGI call that rewrites /mcp path to /mcp/ before FastMCP sees the request"""
                
                # Only modify HTTP requests to /mcp (exact match)
                if (scope["type"] == "http" and 
                    scope.get("path") == "/mcp"):
                    
                    logger.info(f"Rewriting path from /mcp to /mcp/ for {scope.get('method', 'unknown')} request")
                    
                    # Create a new scope with the rewritten path
                    new_scope = dict(scope)
                    new_scope["path"] = "/mcp/"
                    new_scope["raw_path"] = b"/mcp/"
                    
                    # Continue with the rewritten scope
                    return await self.app(new_scope, receive, send)
                
                # For all other requests, continue normally
                return await self.app(scope, receive, send)
        
        class MCPAuthMiddleware(BaseHTTPMiddleware):
            def __init__(self, app, session_manager):
                super().__init__(app)
                self.session_manager = session_manager
            
            async def dispatch(self, request, call_next):
                """Middleware to handle MCP endpoint authentication at HTTP level"""
                
                # Handle CORS preflight for all requests with comprehensive headers
                if request.method == "OPTIONS":
                    response = Response(status_code=200)
                    
                    # Get any requested headers from the preflight request
                    requested_headers = request.headers.get("access-control-request-headers", "")
                    
                    # Comprehensive CORS headers for MCP Inspector compatibility
                    response.headers["Access-Control-Allow-Origin"] = "*"
                    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD"
                    
                    # Allow all commonly used headers plus any specifically requested
                    allowed_headers = [
                        "Content-Type", "Authorization", "Accept", "Origin", "User-Agent",
                        "mcp-protocol-version", "X-Requested-With", "Cache-Control",
                        "Access-Control-Request-Method", "Access-Control-Request-Headers",
                        "Accept-Language", "Accept-Encoding", "Connection", "Host", 
                        "Referer", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
                        "Pragma", "DNT", "Upgrade-Insecure-Requests", "If-Modified-Since",
                        "If-None-Match", "X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP"
                    ]
                    
                    # Add any specifically requested headers
                    if requested_headers:
                        requested_list = [h.strip() for h in requested_headers.split(",")]
                        allowed_headers.extend(requested_list)
                    
                    response.headers["Access-Control-Allow-Headers"] = ", ".join(set(allowed_headers))
                    response.headers["Access-Control-Allow-Credentials"] = "true"
                    response.headers["Access-Control-Max-Age"] = "86400"  # 24 hours
                    response.headers["Access-Control-Expose-Headers"] = (
                        "Content-Type, Authorization, mcp-protocol-version, WWW-Authenticate"
                    )
                    return self.session_manager.add_security_headers(response)
                
                # Get user authentication for all requests (not just MCP endpoints)
                user_info = await self.session_manager.get_user_from_session(request)
                
                # Set user context for FastMCP middleware access
                self.session_manager.set_current_user(user_info)
                
                # Check if this is an MCP endpoint request
                if request.url.path.startswith('/mcp'):
                    logger.debug(f"MCP endpoint request: {request.method} {request.url.path}")
                    
                    # Check authentication for MCP endpoints
                    if not user_info:
                        logger.info(f"MCP endpoint {request.url.path} accessed without authentication - returning 401")
                        audit_log("mcp_http_unauthorized", details={
                            "method": request.method,
                            "path": request.url.path,
                            "user_agent": request.headers.get("user-agent", ""),
                        })
                        
                        # Return 401 with WWW-Authenticate header for MCP Inspector
                        base_url = f"{request.url.scheme}://{request.url.netloc}"
                        resource_metadata_url = f"{base_url}/.well-known/oauth-protected-resource"
                        www_authenticate = f'Bearer resource_metadata="{resource_metadata_url}"'
                        
                        response = JSONResponse(
                            {
                                "error": "invalid_token",
                                "error_description": "Authentication required for MCP endpoint access"
                            },
                            status_code=401,
                            headers={
                                "WWW-Authenticate": www_authenticate,
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                                "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version"
                            }
                        )
                        
                        return self.session_manager.add_security_headers(response)
                    else:
                        logger.info(f"MCP endpoint {request.url.path} accessed by authenticated user: {user_info.get('email') or user_info.get('user_id', 'unknown')}")
                        audit_log("mcp_http_authenticated", 
                                 user_id=user_info.get('user_id'),
                                 details={
                                     "method": request.method,
                                     "path": request.url.path,
                                     "role": user_info.get('role')
                                 })
                
                # Continue to next middleware/handler
                response = await call_next(request)
                
                # Add CORS headers to all responses for MCP Inspector compatibility
                response.headers["Access-Control-Allow-Origin"] = "*"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD"
                response.headers["Access-Control-Allow-Headers"] = (
                    "Content-Type, Authorization, Accept, Origin, User-Agent, "
                    "mcp-protocol-version, X-Requested-With, Cache-Control, "
                    "Accept-Language, Accept-Encoding, Connection, Host, Referer"
                )
                response.headers["Access-Control-Expose-Headers"] = (
                    "Content-Type, Authorization, mcp-protocol-version, WWW-Authenticate"
                )
                
                return response
        
        # Add middleware in reverse order (last added = first executed)
        # 1. Add authentication middleware first
        app.add_middleware(MCPAuthMiddleware, session_manager=self.session_manager)
        
        # 2. Add path rewrite middleware as pure ASGI middleware (executes first)
        app = MCPPathRewriteMiddleware(app)

        logger.info("ASGI application created with session, authentication, and path rewrite middleware")
        return app
    
    async def run(self, host: str = "localhost", port: int = 3001):
        """Run the unified OAuth MCP server with SSE transport for MCP protocol"""
        try:
            logger.info(f"Starting FastMCP OAuth server on {host}:{port}")
            logger.info("Security features enabled:")
            logger.info("  ✅ JWT signature validation")
            logger.info("  ✅ PKCE protection") 
            logger.info("  ✅ RBAC enforcement")
            logger.info("  ✅ Audit logging")
            logger.info("  ✅ Session security")
            
            # Start periodic cleanup task
            async def periodic_cleanup():
                while True:
                    try:
                        await asyncio.sleep(300)  # Every 5 minutes
                        await self.session_manager.cleanup_expired_tokens()
                    except Exception as e:
                        logger.error(f"Cleanup task error: {e}")
            
            # Start cleanup task in background
            cleanup_task = asyncio.create_task(periodic_cleanup())
            
            try:
                # Use custom ASGI app with OAuth middleware instead of FastMCP's built-in transport
                # This ensures all requests go through our OAuth authentication middleware
                logger.info("🚀 Starting server with custom OAuth-protected HTTP transport")
                
                # Create the ASGI app with our OAuth middleware
                app = self.create_app(host, port)
                
                # Run with uvicorn server (ensures OAuth middleware is active)
                import uvicorn
                config = uvicorn.Config(app, host=host, port=port, log_level="info")
                server = uvicorn.Server(config)
                await server.serve()
            finally:
                cleanup_task.cancel()
                try:
                    await cleanup_task
                except asyncio.CancelledError:
                    pass
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="FastMCP OAuth server for Okta integration")
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    parser.add_argument("--port", type=int, default=3001, help="Port to bind to")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Create and run server
        server = FastMCPOAuthServer()
        await server.run(host=args.host, port=args.port)
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
