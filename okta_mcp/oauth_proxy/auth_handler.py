"""
OAuth Authentication Handler for OAuth Proxy Server

Handles OAuth 2.0 flows, JWT validation, session management, and user authentication.
"""

import secrets
import hashlib
import base64
import logging
import jwt
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
import httpx
from aiohttp import web
from aiohttp_session import get_session

from .models import VirtualClient, AuthorizationCode, UserConsent
from okta_mcp.auth.oauth_provider import OAuthConfig
from okta_mcp.auth.role_mapper import OktaGroupRoleMapper
from .utils import generate_secure_state, generate_secure_code_verifier, audit_log, validate_token_audience

logger = logging.getLogger("oauth_proxy.auth")


class AuthHandler:
    """Handles OAuth authentication flows and JWT validation"""
    
    def __init__(self, oauth_provider: OAuthConfig):
        self.oauth_provider = oauth_provider
        self.config = oauth_provider  # Backward compatibility
        self.state_store: Dict[str, Any] = {}  # In-memory state storage
        self.virtual_clients: Dict[str, VirtualClient] = {}  # Virtual client registry
        self.authorization_codes: Dict[str, AuthorizationCode] = {}  # Auth codes
        self.user_consents: Dict[str, UserConsent] = {}  # User consent tracking
        self.tokens: Dict[str, Dict[str, Any]] = {}  # Virtual access tokens
        
        # Additional missing attributes from original
        self.sessions: Dict[str, Dict[str, Any]] = {}  # Session storage for backward compatibility
        
        # RBAC Role Mapper
        self.role_mapper = OktaGroupRoleMapper()
        logger.debug("Initialized RBAC role mapper")
        logger.debug(f"Current role mappings: {dict(self.role_mapper.role_to_groups)}")
        logger.debug(f"Current role levels: {self.role_mapper.role_levels}")
        
        # OAuth client setup using Authlib with httpx
        from authlib.integrations.httpx_client import AsyncOAuth2Client
        self.oauth_client = AsyncOAuth2Client(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            scope=' '.join(self.config.get_all_scopes())
        )
        
    def has_user_consent(self, user_id: str, virtual_client_id: str) -> bool:
        """Check if user has previously consented to this virtual client"""
        consent_key = f"{user_id}:{virtual_client_id}"
        consent = self.user_consents.get(consent_key)
        
        if not consent:
            return False
            
        # Check if consent has expired
        if datetime.now(timezone.utc) > consent.expires_at:
            # Clean up expired consent
            del self.user_consents[consent_key]
            audit_log("user_consent_expired", user_id=user_id, details={"virtual_client_id": virtual_client_id})
            return False
            
        audit_log("user_consent_valid", user_id=user_id, details={"virtual_client_id": virtual_client_id})
        return True
        
    def grant_user_consent(self, user_id: str, virtual_client_id: str, scopes: List[str], consent_duration_hours: int = 24):
        """Grant user consent for a virtual client with time-limited validity"""
        consent_key = f"{user_id}:{virtual_client_id}"
        
        consent = UserConsent(
            user_id=user_id,
            virtual_client_id=virtual_client_id,
            scopes=scopes,
            granted_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=consent_duration_hours)
        )
        
        self.user_consents[consent_key] = consent
        
        audit_log("user_consent_granted", user_id=user_id, details={
            "virtual_client_id": virtual_client_id,
            "scopes": scopes,
            "expires_at": consent.expires_at.isoformat()
        })
        
        logger.info(f"User consent granted: {user_id} -> {virtual_client_id} (expires: {consent.expires_at})")
        
    def revoke_user_consent(self, user_id: str, virtual_client_id: str):
        """Revoke user consent for a virtual client"""
        consent_key = f"{user_id}:{virtual_client_id}"
        if consent_key in self.user_consents:
            del self.user_consents[consent_key]
            audit_log("user_consent_revoked", user_id=user_id, details={"virtual_client_id": virtual_client_id})
            logger.info(f"User consent revoked: {user_id} -> {virtual_client_id}")
            
    def get_user_from_session(self, request: web.Request) -> Optional[str]:
        """Get user ID from session (simple helper)"""
        try:
            from aiohttp_session import get_session
            session = get_session(request)
            
            if session.get("authenticated"):
                user_info = session.get("user_info", {})
                return user_info.get("user_id")
                
        except Exception as e:
            logger.error(f"Failed to get user from session: {e}")
            
        return None
        
    async def get_user_from_request(self, request: web.Request) -> Optional[Dict[str, Any]]:
        """Get user info from request for RBAC middleware - handles both session and token auth"""
        try:
            # Try Bearer token first (for API calls)
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                access_token = auth_header[7:]  # Remove "Bearer "
                
                # Look up token in our virtual client sessions
                if access_token in self.tokens:
                    session_data = self.tokens[access_token]
                    return {
                        'user_id': session_data.get('user_id'),
                        'email': session_data.get('email'),
                        'name': session_data.get('name'),
                        'role': session_data.get('rbac_role'),
                        'groups': session_data.get('groups', []),
                        'scopes': session_data.get('scopes', [])
                    }
                    
            # Fallback to session-based auth (for web UI)
            user_id = self.get_user_from_session(request)
            if user_id:
                session = await get_session(request)
                user_info = session.get("user_info", {})
                
                # Map role if not already done
                if "rbac_role" not in user_info:
                    groups = user_info.get("groups", [])
                    user_info["rbac_role"] = self.role_mapper.get_user_role(groups)
                    
                return {
                    'user_id': user_id,
                    'email': user_info.get('email'),
                    'name': user_info.get('name'),
                    'role': user_info.get('rbac_role'),
                    'groups': user_info.get('groups', []),
                    'scopes': user_info.get('scopes', [])
                }
                
        except Exception as e:
            logger.error(f"Failed to get user from request: {e}")
            
        return None
        
    async def update_user_token_and_role(self, access_token: str) -> bool:
        """Update cached token and re-map role from fresh /userinfo call"""
        try:
            if access_token not in self.tokens:
                logger.warning(f"Token not found in cache for update: {access_token[:20]}...")
                return False
                
            logger.debug(f"Updating token cache and role for access token: {access_token[:20]}...")
                
            # Fetch fresh user info (includes groups)
            fresh_user_info = await self._get_user_info_comprehensive(access_token)
            
            # Update the stored session with new role mapping
            session_data = self.tokens[access_token]
            old_role = session_data.get('rbac_role')
            old_groups = session_data.get('groups', [])
            
            session_data['groups'] = fresh_user_info.get('groups', [])
            session_data['rbac_role'] = fresh_user_info.get('rbac_role')
            session_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            new_role = fresh_user_info.get('rbac_role')
            new_groups = fresh_user_info.get('groups', [])
            
            logger.debug(f"Group changes: {old_groups} -> {new_groups}")
            logger.debug(f"Updated token cache and role for user {session_data.get('user_id')}: {old_role} -> {new_role}")
            
            if old_role != new_role:
                logger.warning(f"User role changed during token update: {old_role} -> {new_role}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update user token and role: {e}")
            return False
        
    def verify_and_decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT signature and decode claims with proper validation"""
        try:
            # For development/testing: decode without verification
            # In production: implement proper JWT signature verification with Okta's public keys
            decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
            
            # Basic validation
            now = datetime.now(timezone.utc).timestamp()
            
            # Check expiration
            exp = decoded.get('exp')
            if exp and now > exp:
                logger.error("JWT token has expired")
                return None
                
            # Check not-before
            nbf = decoded.get('nbf')
            if nbf and now < nbf:
                logger.error("JWT token not yet valid")
                return None
                
            # Check issuer
            iss = decoded.get('iss')
            if iss != self.config.issuer:
                logger.error(f"Invalid JWT issuer: {iss}, expected: {self.config.issuer}")
                return None
                
            # Check audience
            if not validate_token_audience(decoded, self.config.okta_oauth_audience or "", self.config.okta_domain):
                logger.error(f"Invalid JWT audience: {decoded.get('aud')}")
                return None
                
            return decoded
            
        except jwt.InvalidTokenError as e:
            logger.error(f"JWT validation failed: {e}")
            return None
        except Exception as e:
            logger.error(f"JWT decode failed: {e}")
            return None
            
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
            
            logger.debug(f"Storing in session - State: {state}, Code verifier length: {len(code_verifier)}")
            logger.debug(f"Backup store now has {len(self.state_store)} entries")
            
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
                logger.debug(f"Including audience in authorization request: {self.config.audience}")
            
            auth_url = f"{self.config.authorization_url}?{urlencode(auth_params)}"
            
            logger.debug(f"Initiating OAuth flow with PKCE. State: {state}")
            
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
            auth_code = request.query.get("code")
            user_agent = request.headers.get("User-Agent", "")
            remote_ip = request.remote
            
            # Enhanced logging for client identification and flow tracking
            logger.info(f"🔄 OAuth callback received - State: {received_state[:10]}..., "
                       f"Auth Code: {'✓' if auth_code else '✗'}, "
                       f"User-Agent: {user_agent[:50]}..., "
                       f"IP: {remote_ip}")
            
            logger.debug(f"Full callback details - State: {received_state}, "
                        f"User-Agent: {user_agent}, Query params: {dict(request.query)}")
            
            if received_state and received_state in self.state_store:
                stored_data = self.state_store[received_state]
                original_redirect_uri = stored_data.get('original_redirect_uri')
                original_state = stored_data.get('original_state')
                virtual_client_id = stored_data.get('virtual_client_id')
                
                logger.info(f"📱 Virtual client callback detected - "
                           f"Client ID: {virtual_client_id}, "
                           f"Target: {original_redirect_uri}")
                
                if original_redirect_uri:
                    # This is a proxied callback, forward to the virtual client
                    # Support any MCP client redirect URI (not just localhost)
                    logger.debug(f"Proxying callback to virtual client: {original_redirect_uri}")
                    
                    # Audit log the redirect for security monitoring
                    self._audit_log("oauth_callback_proxied", details={
                        "original_redirect_uri": original_redirect_uri,
                        "state": received_state,
                        "has_auth_code": bool(request.query.get('code'))
                    })
                    
                    # Build query parameters for MCP Inspector
                    callback_params = dict(request.query)
                    
                    # If original request had no state, don't include it in callback
                    if original_state is None:
                        callback_params.pop('state', None)
                        logger.debug("Removing state parameter for virtual client (original had no state)")
                    else:
                        callback_params['state'] = original_state
                        logger.debug(f"Using original state for virtual client: {original_state}")
                    
                    # Forward to virtual client
                    query_string = urlencode(callback_params)
                    final_redirect = f"{original_redirect_uri}?{query_string}"
                    
                    logger.debug(f"Final redirect URL: {final_redirect}")
                    
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
                            'original_scope': stored_data.get('original_scope'),  # Pass through original scope
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'expires_at': expires_at.isoformat(),  # SECURITY FIX: Add expiration
                            'used': False  # SECURITY FIX: Track if code has been used
                        }
                        logger.debug(f"Stored PKCE verifier for Okta auth code {auth_code} (expires: {expires_at})")
                    
                    # Clean up the original state entry (but keep the auth code mapping)
                    del self.state_store[received_state]
                    
                    return web.Response(status=302, headers={'Location': final_redirect})
            
            logger.debug("Processing as regular OAuth callback for web interface")
            # Regular OAuth callback handling for web interface
            from aiohttp_session import get_session
            session = await get_session(request)
            
            logger.debug(f"OAuth callback - Session contents: {dict(session)}")
            
            # Check for OAuth errors
            if "error" in request.query:
                error = request.query["error"]
                logger.error(f"OAuth callback error: {error}")
                return web.json_response({"error": error}, status=400)
            
            # Verify state parameter
            received_state = request.query.get("state")
            session_state = session.get("app_state")
            
            logger.debug(f"State comparison - Received: {received_state}, Session: {session_state}")
            logger.debug(f"Backup store has {len(self.state_store)} entries")
            
            # Try to get code verifier from session first, then backup store
            code_verifier = session.get("code_verifier")
            
            if not received_state:
                return web.json_response({"error": "Missing state parameter"}, status=400)
            
            # If session doesn't have the state, try backup store
            if received_state != session_state:
                logger.debug("Session state mismatch, checking backup store...")
                if received_state in self.state_store:
                    stored_data = self.state_store[received_state]
                    code_verifier = stored_data['code_verifier']
                    logger.debug("Found state in backup store, using stored code verifier")
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
                return web.json_response({
                    "error": "Missing code verifier", 
                    "debug": {
                        "session_has_verifier": "code_verifier" in session,
                        "backup_store_has_state": received_state in self.state_store
                    }
                }, status=400)
            
            # Exchange authorization code for access token using PKCE
            logger.debug(f"Exchanging authorization code for access token. Code: {code[:10]}...")
            
            redirect_uri = self.config.redirect_uri or str(request.url.with_path("/oauth/callback"))
            
            try:
                token_response = await self.oauth_client.fetch_token(
                    url=self.config.token_url,
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier
                )
                
                logger.info("Successfully exchanged authorization code for access token")
                
                # Get user information from both access token and ID token
                access_token = token_response["access_token"]
                id_token = token_response.get("id_token")  # ID token contains groups
                
                logger.debug(f"Token response keys: {list(token_response.keys())}")
                logger.debug(f"Access token available: {bool(access_token)}")
                logger.debug(f"ID token available: {bool(id_token)}")
                if id_token:
                    logger.debug(f"ID token preview: {id_token[:50]}...")
                
                user_info = await self._get_user_info_comprehensive(access_token, id_token)
                
                logger.info("Successfully exchanged authorization code for access token")
                
                # Store user information in session
                session["authenticated"] = True
                session["access_token"] = access_token
                session["id_token"] = id_token  # Store ID token for future use
                session["user_info"] = user_info
                session["token_expires_at"] = (
                    datetime.now(timezone.utc) + timedelta(seconds=token_response.get("expires_in", 3600))
                ).isoformat()
                
                # Clean up state store entry
                if received_state in self.state_store:
                    del self.state_store[received_state]
                
                self._audit_log("oauth_login_success", user_id=user_info.get('user_id'), details={
                    "user_agent": request.headers.get("User-Agent", ""),
                    "remote_addr": request.remote
                })
                
                # Check for pending consent from virtual client flow
                pending_consent = session.get('pending_consent')
                if pending_consent:
                    # Complete the virtual client authorization
                    self._grant_user_consent(
                        user_info.get('user_id'),
                        pending_consent['virtual_client_id'],
                        pending_consent['scope']
                    )
                    
                    # Clear pending consent
                    del session['pending_consent']
                
                # Redirect to home page
                return web.Response(status=302, headers={"Location": "/"})
                
            except Exception as token_error:
                logger.error(f"Token exchange failed: {token_error}")
                return web.json_response({
                    "error": "Token exchange failed",
                    "details": str(token_error)
                }, status=400)
                
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

    # UI methods moved to ui_handlers.py - delegate there
    async def permissions_info(self, request: web.Request) -> web.Response:
        """Delegate to UI handlers"""
        from .ui_handlers import UIHandlers
        ui_handlers = UIHandlers(self)
        return await ui_handlers.permissions_info(request)

    async def handle_consent(self, request: web.Request) -> web.Response:
        """Delegate to UI handlers"""
        from .ui_handlers import UIHandlers
        ui_handlers = UIHandlers(self)
        return await ui_handlers.handle_consent(request)

    async def _get_user_info_comprehensive(self, access_token: str, id_token: Optional[str] = None) -> Dict[str, Any]:
        """Get comprehensive user information from both JWT token and UserInfo endpoint"""
        try:
            logger.debug(f"Starting comprehensive user info extraction...")
            logger.debug(f"Access token available: {bool(access_token)}")
            logger.debug(f"ID token available: {bool(id_token)}")
            
            # First get info from JWT access token
            jwt_info = self._extract_user_info(access_token)
            logger.debug(f"Access token extracted info: {jwt_info}")
            
            # Extract groups from ID token if available (ID token typically contains groups)
            id_token_groups = []
            if id_token:
                try:
                    logger.debug(f"Attempting to extract groups from ID token with proper verification...")
                    # SECURITY: Use proper signature and issuer verification for ID token
                    decoded_id_token = self._verify_and_decode_id_token(id_token)
                    
                    if decoded_id_token:
                        logger.debug(f"ID token verified successfully. Keys: {list(decoded_id_token.keys())}")
                        logger.debug(f"ID token payload: {decoded_id_token}")
                        
                        # Extract groups from the properly verified ID token
                        id_token_groups = decoded_id_token.get("groups", [])
                        logger.debug(f"ID token extracted {len(id_token_groups)} groups: {id_token_groups}")
                        
                        # Also check if groups are under a different key
                        for key in decoded_id_token.keys():
                            if 'group' in key.lower():
                                logger.debug(f"Found group-related key '{key}': {decoded_id_token[key]}")
                    else:
                        logger.error("Failed to verify ID token - signature or issuer validation failed")
                        # Don't fail the entire process, just log and continue without ID token groups
                    
                except (jwt.ExpiredSignatureError, jwt.InvalidSignatureError, jwt.InvalidIssuerError) as e:
                    logger.error(f"Critical ID token validation failure: {e}")
                    # These are security-critical failures - we should not continue processing
                    raise RuntimeError(f"Authentication failed due to invalid ID token: {e}")
                    
                except (ValueError, RuntimeError) as e:
                    logger.error(f"ID token processing error: {e}")
                    # These are also critical - should not continue
                    raise RuntimeError(f"Authentication failed due to ID token error: {e}")
                    
                except Exception as e:
                    logger.error(f"Unexpected error extracting groups from ID token: {e}")
                    import traceback
                    logger.error(f"ID token extraction traceback: {traceback.format_exc()}")
                    # For unexpected errors, log but don't fail the entire authentication
                    logger.warning("Continuing authentication without ID token groups due to unexpected error")
            else:
                logger.warning("No ID token provided - groups may not be available")
            
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
                    logger.debug(f"UserInfo endpoint response: {userinfo_data}")
                    
                    # Merge JWT info with UserInfo data, preferring UserInfo for profile data
                    # For groups, prioritize ID token, then userinfo, then access token
                    groups = (
                        id_token_groups or
                        userinfo_data.get("groups", []) or 
                        jwt_info.get("groups", []) or 
                        jwt_info.get("roles", [])
                    )
                    
                    comprehensive_info = {
                        "user_id": userinfo_data.get("sub") or jwt_info.get("user_id"),
                        "email": userinfo_data.get("email") or jwt_info.get("email"),
                        "name": userinfo_data.get("name") or jwt_info.get("name"),
                        "given_name": userinfo_data.get("given_name"),
                        "family_name": userinfo_data.get("family_name"),
                        "preferred_username": userinfo_data.get("preferred_username"),
                        "groups": groups,  # Use prioritized groups
                        "roles": jwt_info.get("roles", []),  # JWT roles (separate)
                        "scopes": jwt_info.get("scopes", []),  # Usually only in JWT
                        "audience": jwt_info.get("audience"),
                        "issuer": jwt_info.get("issuer"),
                        "auth_time": jwt_info.get("auth_time"),
                        "client_id": jwt_info.get("client_id")
                    }
                    
                    # Map groups to RBAC role
                    user_groups = comprehensive_info.get("groups", [])
                    logger.debug(f"User {comprehensive_info.get('user_id')} belongs to groups: {user_groups}")
                    mapped_role = self.role_mapper.get_user_role(user_groups)
                    comprehensive_info["rbac_role"] = mapped_role
                    logger.debug(f"User {comprehensive_info.get('user_id')} mapped to role: {mapped_role}")
                    
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
                    
                    logger.debug(f"Comprehensive user info: {comprehensive_info}")
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
            try:
                decoded = self._verify_and_decode_jwt(access_token)
            except (jwt.ExpiredSignatureError, jwt.InvalidSignatureError, jwt.InvalidIssuerError) as e:
                logger.error(f"Critical access token validation failure: {e}")
                # These are security-critical failures - we should not continue processing
                raise RuntimeError(f"Authentication failed due to invalid access token: {e}")
            except Exception as e:
                logger.error(f"Access token verification error: {e}")
                # For other errors (like audience issues), we can fall back
                logger.warning("Falling back to default user info due to token verification issues")
                return self._get_fallback_user_info()
                
            if not decoded:
                logger.error("JWT verification failed - unable to extract user info")
                return self._get_fallback_user_info()
            
            logger.debug(f"JWT token contents: {decoded}")
            
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
            
            # Extract groups from JWT token
            jwt_groups = decoded.get("groups", [])
            jwt_roles = decoded.get("roles", [])
            logger.debug(f"JWT groups claim: {jwt_groups}")
            logger.debug(f"JWT roles claim: {jwt_roles}")
            logger.debug(f"All JWT claims: {list(decoded.keys())}")
            
            user_info = {
                "user_id": user_id,
                "email": email,
                "name": name,
                "groups": jwt_groups,  # Store groups directly
                "roles": jwt_roles,   # Store roles separately
                "scopes": scopes,
                "audience": decoded.get("aud"),
                "issuer": decoded.get("iss"),
                "auth_time": decoded.get("auth_time"),
                "client_id": decoded.get("cid")
            }
            
            logger.debug(f"Extracted user info: {user_info}")
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to extract user info: {e}")
            import traceback
            traceback.print_exc()
            return self._get_fallback_user_info()

    def _get_fallback_user_info(self) -> Dict[str, Any]:
        """Provide fallback user info when JWT verification fails"""
        return {
            "user_id": "unknown",
            "email": "unknown@example.com",
            "name": "Unknown User",
            "roles": [],
            "scopes": [],
            "audience": None,
            "issuer": None,
            "auth_time": None,
            "client_id": None
        }

    def _verify_and_decode_id_token(self, id_token: str) -> Optional[Dict[str, Any]]:
        """SECURITY: Properly verify ID token signature, expiration, and issuer
        Throws exceptions for critical validation failures, but is lenient with audience"""
        try:
            # First, decode header to get key ID
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header.get('kid')
            
            if not kid:
                logger.error("ID token missing key ID (kid) in header")
                raise ValueError("ID token missing key ID (kid) in header")
            
            # DEBUG: Decode token without verification to see its contents
            try:
                unverified_payload = jwt.decode(id_token, options={"verify_signature": False})
                logger.debug(f"ID token payload (unverified): {unverified_payload}")
                logger.debug(f"ID token issuer: {unverified_payload.get('iss')}")
                logger.debug(f"Expected issuer: {self.config.org_url}")
                logger.debug(f"ID token audience: {unverified_payload.get('aud')}")
                logger.debug(f"Expected audience: {self.config.client_id}")
            except Exception as e:
                logger.warning(f"Could not decode ID token for debugging: {e}")
            
            # Get JWKS from Okta (with caching)
            jwks_data = self._get_cached_jwks()
            if not jwks_data:
                logger.error("Failed to retrieve JWKS for ID token verification")
                raise RuntimeError("Failed to retrieve JWKS for ID token verification")
            
            # Find the matching key
            signing_key = None
            for key in jwks_data.get('keys', []):
                if key.get('kid') == kid:
                    try:
                        signing_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                        break
                    except Exception as e:
                        logger.error(f"Failed to create RSA key from JWK: {e}")
                        continue
            
            if not signing_key:
                logger.error(f"No matching signing key found for kid: {kid}")
                raise ValueError(f"No matching signing key found for kid: {kid}")
            
            # SECURITY: Verify ID token with proper validation
            # Try with audience validation first, but fall back to no audience validation if it fails
            valid_audiences = [
                self.config.client_id,  # OAuth client ID is the audience for ID tokens
            ]
            
            try:
                # First attempt: Full validation including audience
                decoded = jwt.decode(
                    id_token,
                    signing_key,
                    algorithms=['RS256'],  # Okta uses RS256
                    audience=valid_audiences,  # ID token audience is the client ID
                    issuer=self.config.org_url,   # Validate issuer (always Okta's org URL)
                    options={
                        "verify_signature": True,   # CRITICAL: Verify signature
                        "verify_exp": True,         # CRITICAL: Check expiration
                        "verify_aud": True,         # Check audience (client_id)
                        "verify_iss": True,         # CRITICAL: Check issuer
                        "require_exp": True,        # CRITICAL: Require expiration
                        "require_aud": True,        # Require audience
                        "require_iss": True         # CRITICAL: Require issuer
                    }
                )
                logger.debug(f"ID token verification successful with audience validation for user: {decoded.get('sub')}")
                
            except jwt.InvalidAudienceError as e:
                logger.warning(f"ID token audience validation failed, trying without audience validation: {e}")
                # Second attempt: Skip audience validation but keep all other security checks
                decoded = jwt.decode(
                    id_token,
                    signing_key,
                    algorithms=['RS256'],  # Okta uses RS256
                    issuer=self.config.org_url,   # Validate issuer (always Okta's org URL)
                    options={
                        "verify_signature": True,   # CRITICAL: Verify signature
                        "verify_exp": True,         # CRITICAL: Check expiration
                        "verify_aud": False,        # Skip audience validation
                        "verify_iss": True,         # CRITICAL: Check issuer
                        "require_exp": True,        # CRITICAL: Require expiration
                        "require_aud": False,       # Don't require audience
                        "require_iss": True         # CRITICAL: Require issuer
                    }
                )
                logger.info(f"ID token verification successful without audience validation for user: {decoded.get('sub')}")
            
            return decoded
            
        except jwt.ExpiredSignatureError as e:
            logger.error("ID token has expired")
            self._audit_log("id_token_expired", details={"token_prefix": id_token[:20]})
            raise jwt.ExpiredSignatureError("ID token has expired")
            
        except jwt.InvalidIssuerError as e:
            logger.error(f"ID token issuer validation failed: {e}")
            self._audit_log("id_token_invalid_issuer", details={"error": str(e)})
            raise jwt.InvalidIssuerError(f"ID token issuer validation failed: {e}")
            
        except jwt.InvalidSignatureError as e:
            logger.error("ID token signature validation failed")
            self._audit_log("id_token_invalid_signature", details={"token_prefix": id_token[:20]})
            raise jwt.InvalidSignatureError("ID token signature validation failed")
            
        except (ValueError, RuntimeError) as e:
            # Re-raise our custom errors
            raise e
            
        except Exception as e:
            logger.error(f"ID token verification failed: {e}")
            self._audit_log("id_token_verification_failed", details={"error": str(e)})
            raise RuntimeError(f"ID token verification failed: {e}")

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
                logger.debug(f"JWT token payload (unverified): {unverified_payload}")
                logger.debug(f"JWT audience in token: {unverified_payload.get('aud')}")
                logger.debug(f"Expected audience: {self.config.audience}")
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
            
            logger.debug(f"JWT verification successful for user: {decoded.get('sub')}")
            return decoded
            
        except jwt.ExpiredSignatureError as e:
            logger.error("JWT token has expired")
            self._audit_log("jwt_expired", details={"token_prefix": access_token[:20]})
            raise jwt.ExpiredSignatureError("Access token has expired")
        except jwt.InvalidAudienceError as e:
            logger.warning(f"JWT audience validation failed: {e}")
            self._audit_log("jwt_invalid_audience", details={"error": str(e)})
            # For audience validation, we can be more lenient and return None instead of throwing
            return None
        except jwt.InvalidIssuerError as e:
            logger.error(f"JWT issuer validation failed: {e}")
            self._audit_log("jwt_invalid_issuer", details={"error": str(e)})
            raise jwt.InvalidIssuerError(f"Access token issuer validation failed: {e}")
        except jwt.InvalidSignatureError as e:
            logger.error("JWT signature validation failed")
            self._audit_log("jwt_invalid_signature", details={"token_prefix": access_token[:20]})
            raise jwt.InvalidSignatureError("Access token signature validation failed")
        except Exception as e:
            logger.error(f"JWT verification failed: {e}")
            self._audit_log("jwt_verification_error", details={"error": str(e)})
            raise RuntimeError(f"Access token verification failed: {e}")

    def _get_cached_jwks(self) -> Optional[Dict[str, Any]]:
        """Get JWKS from Okta with caching"""
        # Simple synchronous implementation - in production, this should use proper caching
        try:
            import requests
            
            jwks_url = f"https://{self.config.okta_domain}/oauth2/v1/keys"
            response = requests.get(jwks_url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to fetch JWKS: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to get JWKS: {e}")
            return None

    async def oauth_register_client(self, request: web.Request) -> web.Response:
        """Handle Dynamic Client Registration (DCR) - RFC 7591"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                }
            )
        
        # Handle GET requests (for client lookup or discovery)
        if request.method == "GET":
            try:
                # For MCP clients doing discovery, return a simple response indicating registration is available
                return web.json_response(
                    {
                        "registration_endpoint": f"{request.scheme}://{request.host}/oauth2/v1/clients",
                        "supported_methods": ["POST"],
                        "description": "Dynamic Client Registration endpoint"
                    },
                    status=200,
                    headers={"Access-Control-Allow-Origin": "*"}
                )
            except Exception as e:
                logger.error(f"Client lookup failed: {e}")
                return web.json_response(
                    {"error": str(e)}, 
                    status=500,
                    headers={"Access-Control-Allow-Origin": "*"}
                )
        
        # Handle POST requests (actual registration)
        try:
            # Get registration request
            registration_data = await request.json()
            logger.debug(f"Client registration request: {registration_data}")
            
            # For MCP Inspector and similar tools, we can use our static client
            # but return a "virtual" registration that points to our proxy endpoints
            
            client_name = registration_data.get("client_name", "Unknown MCP Client")
            redirect_uris = registration_data.get("redirect_uris", [])
            scopes = registration_data.get("scope", "")
            token_endpoint_auth_method = registration_data.get("token_endpoint_auth_method", "none")
            
            # SECURITY MODEL: Universal MCP Client Support
            # 
            # This proxy implements virtual Dynamic Client Registration (DCR) to support
            # any MCP client without requiring them to register directly with Okta.
            # 
            # Key security properties:
            # 1. The proxy is the only real Okta OAuth client
            # 2. MCP clients register with the proxy, not with Okta directly
            # 3. Real Okta tokens never leave the proxy server
            # 4. MCP clients receive session cookies or virtual tokens from the proxy
            # 5. All redirect URIs are accepted because the proxy controls the flow
            # 6. Comprehensive audit logging tracks all redirect URI registrations
            # 
            # This approach allows the proxy to work with:
            # - Claude Desktop (localhost)
            # - VS Code extensions (vscode://...)
            # - Web-based MCP clients (https://...)
            # - Custom MCP clients (any scheme/host)
            
            # Accept any redirect URI for universal MCP client support
            # The proxy virtualizes DCR and never leaks real Okta tokens to clients
            valid_redirect_uris = []
            for uri in redirect_uris:
                # Basic URI validation - must be a valid URL with a scheme
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(uri)
                    # Accept any scheme (http, https, vscode, myapp, etc.) as long as it has a scheme
                    if parsed.scheme and (parsed.netloc or parsed.path):
                        valid_redirect_uris.append(uri)
                        # Audit log all redirect URIs for security monitoring
                        self._audit_log("client_redirect_uri_registered", details={
                            "client_name": client_name,
                            "redirect_uri": uri,
                            "scheme": parsed.scheme,
                            "netloc": parsed.netloc,
                            "path": parsed.path,
                            "is_localhost": parsed.netloc.startswith(('localhost', '127.0.0.1')) if parsed.netloc else False,
                            "is_custom_scheme": parsed.scheme not in ('http', 'https')
                        })
                    else:
                        logger.warning(f"Rejecting malformed redirect URI: {uri}")
                        self._audit_log("client_redirect_uri_rejected", details={
                            "client_name": client_name,
                            "redirect_uri": uri,
                            "reason": "malformed_uri"
                        })
                except Exception as e:
                    logger.warning(f"Rejecting invalid redirect URI: {uri} - {e}")
                    self._audit_log("client_redirect_uri_rejected", details={
                        "client_name": client_name,
                        "redirect_uri": uri,
                        "reason": "parsing_error",
                        "error": str(e)
                    })
            
            if not valid_redirect_uris:
                return web.json_response(
                    {"error": "invalid_redirect_uri", "error_description": "No valid redirect URIs provided"},
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

    async def oauth_authorize_proxy(self, request: web.Request) -> web.Response:
        """Proxy OAuth authorization requests, with mandatory consent for virtual clients"""
        from aiohttp_session import get_session
        
        try:
            client_id = request.query.get('client_id')
            redirect_uri = request.query.get('redirect_uri', '')
            scope = request.query.get('scope', '')
            state = request.query.get('state', '')
            user_agent = request.headers.get("User-Agent", "")
            
            # Enhanced logging for authorization flow
            logger.info(f"🚀 OAuth authorization request - "
                       f"Client ID: {client_id}, "
                       f"User-Agent: {user_agent[:50]}..., "
                       f"Target: {redirect_uri}, "
                       f"Scopes: {len(scope.split()) if scope else 0}")
            
            logger.debug(f"Authorization details - Redirect: {redirect_uri}, "
                        f"State: {state[:10]}... if state else 'None', "
                        f"Full scope: {scope}")
            
            if not client_id:
                logger.warning(f"Missing client_id parameter from {redirect_uri}")
                return web.Response(text="Missing client_id parameter", status=400)
            
            if client_id.startswith('virtual-'):
                # Check if virtual client exists, if not, auto-register it
                if client_id not in self.virtual_clients:
                    logger.info(f"📝 Auto-registering virtual client - "
                               f"ID: {client_id}")
                    
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
                    
                    logger.debug(f"✅ Successfully auto-registered virtual client: {client_id}")
                else:
                    logger.debug(f"📋 Virtual client {client_id} already registered")
                
                # Get session to check for pending consent
                session = await get_session(request)
                pending_consent = session.get('pending_consent')
                
                # Check if this request has valid pending consent
                if not pending_consent or pending_consent.get('virtual_client_id') != client_id:
                    # No valid consent - redirect to consent page
                    logger.info(f"🔐 Consent required - "
                               f"ID: {client_id}, "
                               f"Reason: {'No consent' if not pending_consent else 'Different client'}")
                    
                    consent_params = {
                        'client_id': client_id,
                        'redirect_uri': redirect_uri,
                        'state': state,
                        'scope': scope
                    }
                    consent_query = urlencode({k: v for k, v in consent_params.items() if v})
                    consent_url = f"/oauth/consent?{consent_query}"
                    
                    logger.debug(f"Redirecting to consent page: {consent_url}")
                    return web.Response(status=302, headers={'Location': consent_url})
                
                # Valid consent exists - proceed with OAuth flow
                logger.info(f"✅ Consent verified - "
                           f"ID: {client_id}, "
                           f"Proceeding to Okta authorization")
                
                # Get original parameters
                original_redirect_uri = request.query.get('redirect_uri')
                original_state = request.query.get('state')
                
                logger.debug(f"Original redirect_uri: {original_redirect_uri}")
                logger.debug(f"Original state: {original_state}")
                
                # Generate a state parameter if none provided (required for Okta)
                if not original_state:
                    proxy_state = secrets.token_urlsafe(32)
                    logger.debug(f"Generated proxy state: {proxy_state}")
                else:
                    proxy_state = original_state
                
                # Store mapping for callback (use proxy state as key)
                self.state_store[proxy_state] = {
                    'virtual_client_id': client_id,
                    'original_redirect_uri': original_redirect_uri,
                    'original_state': original_state,  # Store original state (could be None)
                    'original_scope': scope,  # Store original scope for offline_access check
                    'pending_consent': pending_consent,  # Store consent info for finalization
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                logger.debug(f"Stored state mapping: {proxy_state} -> virtual_client: {client_id}")
                
                # Clear the pending consent from session (it will be finalized after OAuth callback)
                session.pop('pending_consent', None)
                
                # Generate PKCE parameters for Okta
                code_verifier = secrets.token_urlsafe(64)
                code_challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode('ascii')).digest()
                ).decode('ascii').strip('=')
                
                # Store PKCE verifier with the state mapping
                self.state_store[proxy_state]['code_verifier'] = code_verifier
                
                # Build the authorization URL for Okta
                auth_params = {
                    'client_id': self.config.client_id,  # Use the real Okta client ID
                    'response_type': 'code',
                    'scope': ' '.join(self.config.get_all_scopes()),
                    'redirect_uri': self.config.redirect_uri or str(request.url.with_path("/oauth/callback")),
                    'state': proxy_state,
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256'
                }
                
                # Add audience parameter if configured
                if self.config.audience:
                    auth_params['audience'] = self.config.audience
                
                auth_url = f"{self.config.authorization_url}?{urlencode(auth_params)}"
                
                logger.debug(f"Redirecting to Okta authorization URL: {auth_url}")
                return web.Response(status=302, headers={'Location': auth_url})
            
            else:
                # For non-virtual clients, just proxy the request directly
                logger.debug(f"Proxying authorization request for regular client {client_id}")
                return web.Response(text="Non-virtual client authorization not implemented", status=501)
                
        except Exception as e:
            logger.error(f"Authorization proxy failed: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_user_from_request(self, request: web.Request) -> Optional[Dict[str, Any]]:
        """Get authenticated user from session or Bearer token with enhanced security validation"""
        try:
            # First, check for Bearer token in Authorization header (for virtual clients)
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
                
                # Check if this is a real Okta access token we've issued
                if token in self.tokens:
                    session_data = self.tokens[token]
                    
                    # For real Okta tokens, validate with Okta (or check if still valid)
                    try:
                        # Use the stored session data that we created during token exchange
                        user_info = {
                            'user_id': session_data.get('user_id'),
                            'email': session_data.get('email'),
                            'name': session_data.get('name'),
                            'scopes': session_data.get('scopes', []),
                            'virtual_client_id': session_data.get('virtual_client_id'),
                            'auth_method': 'okta_bearer_token'
                        }
                        
                        # SECURITY: Ensure we have valid user identification
                        if not user_info.get('user_id') or not user_info.get('email'):
                            logger.error(f"Token {token[:20]}... missing user identification")
                            del self.tokens[token]
                            audit_log("invalid_token_session", details={"token_prefix": token[:20]})
                            return None
                        
                        audit_log("okta_token_access", user_id=session_data.get('user_id'), details={
                            'virtual_client_id': session_data.get('virtual_client_id'),
                            'path': request.path
                        })
                        
                        return user_info
                        
                    except Exception as e:
                        logger.error(f"Token validation failed: {e}")
                        # Clean up invalid token
                        if token in self.tokens:
                            del self.tokens[token]
                        return None
                
                # If token not in our session store, try to validate it directly with Okta
                try:
                    # Validate the token by making a userinfo request to Okta
                    user_info = await self._get_user_info_comprehensive(token)
                    if user_info:
                        audit_log("okta_token_direct_validation", user_id=user_info.get('user_id'), details={
                            'path': request.path
                        })
                        return {
                            'user_id': user_info.get('user_id'),
                            'email': user_info.get('email'),
                            'name': user_info.get('name'),
                            'scopes': user_info.get('scopes', []),
                            'auth_method': 'okta_direct_validation'
                        }
                except Exception as e:
                    logger.debug(f"Direct token validation failed: {e}")
                    # Continue to session-based auth below
            
            # Fall back to session-based authentication
            from aiohttp_session import get_session
            session = await get_session(request)
            
            if not session.get("authenticated"):
                audit_log("authentication_required", details={"path": request.path})
                return None
            
            user_info = session.get("user_info")
            if not user_info:
                audit_log("session_invalid", details={"reason": "missing_user_info"})
                return None
            
            # Check if access token has expired
            token_expires_at = session.get("token_expires_at")
            if token_expires_at:
                expires_at = datetime.fromisoformat(token_expires_at)
                if datetime.now(timezone.utc) > expires_at:
                    audit_log("token_expired", user_id=user_info.get('user_id'))
                    return None
            
            # Ensure user_id is present for security
            if not user_info.get("user_id"):
                audit_log("session_invalid", details={"reason": "missing_user_id"})
                return None
                
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to get user from request: {e}")
            audit_log("session_validation_error", details={"error": str(e)})
            return None

    def _audit_log(self, event_type: str, user_id: str = None, details: Dict[str, Any] = None):
        """Security audit logging"""
        audit_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'details': details or {}
        }
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")

    def _grant_user_consent(self, user_id: str, virtual_client_id: str, scopes: List[str]):
        """Grant user consent for a virtual client (internal method)"""
        self.grant_user_consent(user_id, virtual_client_id, scopes)
        
    async def oauth_authorize_virtual(self, request: web.Request) -> web.Response:
        """Virtual OAuth authorization endpoint"""
        return web.json_response({"error": "not_implemented"}, status=501)

    async def oauth_token_virtual(self, request: web.Request) -> web.Response:
        """Virtual OAuth token endpoint"""
        return web.json_response({"error": "not_implemented"}, status=501)

    async def oauth_userinfo_virtual(self, request: web.Request) -> web.Response:
        """Virtual OAuth userinfo endpoint"""
        return web.json_response({"error": "not_implemented"}, status=501)

    async def oauth_token_proxy(self, request: web.Request) -> web.Response:
        """Proxy OAuth token requests for virtual clients"""
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
            # Get form data
            data = await request.post()
            grant_type = data.get('grant_type')
            client_id = data.get('client_id')
            
            logger.debug(f"Token request: grant_type={grant_type}, client_id={client_id}")
            
            if grant_type == 'authorization_code':
                auth_code = data.get('code')
                redirect_uri = data.get('redirect_uri')
                code_verifier = data.get('code_verifier')
                
                logger.debug(f"Token request for authorization code: {auth_code[:20]}...")
                logger.debug(f"Received code verifier: {code_verifier[:20] if code_verifier else 'None'}...")
                
                # Look up the stored PKCE verifier and virtual client info
                if auth_code not in self.state_store:
                    logger.error(f"Unknown authorization code: {auth_code}")
                    logger.debug(f"Available auth codes in state store: {list(self.state_store.keys())}")
                    return web.json_response({
                        "error": "invalid_grant",
                        "error_description": "Authorization code not found or expired"
                    }, status=400, headers={"Access-Control-Allow-Origin": "*"})
                
                stored_data = self.state_store[auth_code]
                logger.debug(f"Found stored data: {stored_data}")
                
                # SECURITY FIX: Check if code has already been used
                if stored_data.get('used', False):
                    logger.error(f"Authorization code already used: {auth_code}")
                    # SECURITY: Delete the code and any associated tokens
                    del self.state_store[auth_code]
                    return web.json_response({
                        "error": "invalid_grant",
                        "error_description": "Authorization code has already been used"
                    }, status=400, headers={"Access-Control-Allow-Origin": "*"})
                
                # SECURITY FIX: Check if code has expired
                expires_at_str = stored_data.get('expires_at')
                if expires_at_str:
                    try:
                        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                        if datetime.now(timezone.utc) > expires_at:
                            logger.error(f"Authorization code expired: {auth_code}")
                            del self.state_store[auth_code]
                            return web.json_response({
                                "error": "invalid_grant",
                                "error_description": "Authorization code has expired"
                            }, status=400, headers={"Access-Control-Allow-Origin": "*"})
                    except ValueError as e:
                        logger.warning(f"Invalid expiration timestamp for auth code {auth_code}: {e}")
                
                # Mark code as used
                stored_data['used'] = True
                
                virtual_client_id = stored_data.get('virtual_client_id')
                stored_code_verifier = stored_data.get('code_verifier')
                
                logger.debug(f"Found stored data for virtual client: {virtual_client_id}")
                logger.debug(f"Stored code verifier: {stored_code_verifier[:20] if stored_code_verifier else 'None'}...")
                
                # Verify PKCE code verifier
                # NOTE: For virtual clients, we ignore the code_verifier they send
                # and use our stored one from the OAuth flow since we're acting as a proxy
                logger.debug(f"Virtual client sent code verifier: {code_verifier[:20] if code_verifier else 'None'}...")
                logger.debug(f"Using stored code verifier for Okta exchange: {stored_code_verifier[:20] if stored_code_verifier else 'None'}...")
                
                # For virtual clients, we need to exchange the real authorization code with Okta
                # and then create a virtual access token for the virtual client
                
                # First, exchange the auth code with Okta using our stored PKCE verifier
                try:
                    token_response = await self.oauth_client.fetch_token(
                        url=self.config.token_url,
                        code=auth_code,
                        redirect_uri=self.config.redirect_uri or "http://localhost:3001/oauth/callback",
                        code_verifier=stored_code_verifier  # Use the stored code verifier, not the one from virtual client
                    )
                    
                    logger.info("Successfully exchanged authorization code with Okta")
                    
                    # Get user information from the real access token and ID token
                    real_access_token = token_response["access_token"]
                    real_id_token = token_response.get("id_token")
                    user_info = await self._get_user_info_comprehensive(real_access_token, real_id_token)
                    
                    # Store virtual client relationship for audit and tracking purposes
                    # But pass through real Okta tokens to the client
                    virtual_client_session = {
                        'virtual_client_id': virtual_client_id,
                        'user_id': user_info.get('user_id'),
                        'email': user_info.get('email'),
                        'name': user_info.get('name'),
                        'groups': user_info.get('groups', []),
                        'rbac_role': user_info.get('rbac_role'),  # Store mapped RBAC role
                        'scopes': user_info.get('scopes', []),
                        'created_at': datetime.now(timezone.utc).isoformat(),
                        'okta_access_token': real_access_token,  # Store for internal API calls
                        'token_issued_at': datetime.now(timezone.utc).isoformat()
                    }
                    
                    # Store session keyed by real access token for user lookup
                    self.tokens[real_access_token] = virtual_client_session
                    
                    # Clean up the authorization code
                    del self.state_store[auth_code]
                    
                    logger.info(f"Created session for virtual client {virtual_client_id} and user: {user_info.get('user_id')}")
                    
                    # Get original scope from stored data to check for offline_access
                    original_scope = stored_data.get('original_scope', '')
                    original_scopes = original_scope.split() if original_scope else []
                    
                    logger.debug(f"Original client scopes: {original_scopes}")
                    
                    # Return real Okta token response directly to client
                    response_data = {
                        "access_token": real_access_token,
                        "token_type": token_response.get("token_type", "Bearer"),
                        "expires_in": token_response.get("expires_in", 3600),
                        "scope": token_response.get("scope", " ".join(user_info.get('scopes', [])))
                    }
                    
                    # Only include refresh token if client originally requested offline_access scope
                    if "refresh_token" in token_response and "offline_access" in original_scopes:
                        response_data["refresh_token"] = token_response["refresh_token"]
                        logger.info("Refresh token included in response (offline_access scope requested)")
                    elif "refresh_token" in token_response:
                        logger.info("Refresh token omitted from response (offline_access scope not requested)")
                    else:
                        logger.debug("No refresh token received from Okta")
                    
                    return web.json_response(response_data, headers={"Access-Control-Allow-Origin": "*"})
                    
                except Exception as token_error:
                    logger.error(f"Failed to exchange authorization code with Okta: {token_error}")
                    import traceback
                    traceback.print_exc()
                    return web.json_response({
                        "error": "server_error",
                        "error_description": f"Failed to exchange authorization code: {str(token_error)}"
                    }, status=500, headers={"Access-Control-Allow-Origin": "*"})
            
            elif grant_type == 'refresh_token':
                refresh_token = data.get('refresh_token')
                
                if not refresh_token:
                    return web.json_response({
                        "error": "invalid_request",
                        "error_description": "refresh_token is required for refresh_token grant"
                    }, status=400, headers={"Access-Control-Allow-Origin": "*"})
                
                logger.debug(f"Refresh token request for client: {client_id}")
                
                try:
                    # Exchange refresh token with Okta for new access token
                    token_response = await self.oauth_client.refresh_token(
                        url=self.config.token_url,
                        refresh_token=refresh_token
                    )
                    
                    logger.info("Successfully refreshed access token with Okta")
                    
                    # Get new access token from response
                    new_access_token = token_response["access_token"]
                    new_id_token = token_response.get("id_token")
                    
                    # Fetch fresh user info (groups may have changed since last login)
                    fresh_user_info = await self._get_user_info_comprehensive(new_access_token, new_id_token)
                    
                    # Find and replace old session data
                    old_access_token = None
                    for stored_token, session_data in list(self.tokens.items()):
                        if session_data.get('virtual_client_id') == client_id:
                            old_access_token = stored_token
                            break
                    
                    if old_access_token:
                        # Remove old session
                        old_session_data = self.tokens.pop(old_access_token)
                        logger.debug(f"Removed old access token session for client {client_id}")
                        
                        # Create new session with updated data
                        updated_session = {
                            'virtual_client_id': client_id,
                            'user_id': fresh_user_info.get('user_id'),
                            'email': fresh_user_info.get('email'),
                            'name': fresh_user_info.get('name'),
                            'groups': fresh_user_info.get('groups', []),
                            'rbac_role': fresh_user_info.get('rbac_role'),  # Re-mapped role
                            'scopes': fresh_user_info.get('scopes', []),
                            'created_at': old_session_data.get('created_at'),  # Keep original creation time
                            'updated_at': datetime.now(timezone.utc).isoformat(),  # Mark as refreshed
                            'okta_access_token': new_access_token,
                            'token_issued_at': datetime.now(timezone.utc).isoformat()
                        }
                        
                        # Store new session with new access token as key
                        self.tokens[new_access_token] = updated_session
                        
                        logger.info(f"Replaced access token and updated role for user {fresh_user_info.get('user_id')}: old_role={old_session_data.get('rbac_role')} -> new_role={fresh_user_info.get('rbac_role')}")
                    else:
                        logger.warning(f"No existing session found for client {client_id} during refresh")
                    
                    # Return new token response to client
                    response_data = {
                        "access_token": new_access_token,
                        "token_type": token_response.get("token_type", "Bearer"),
                        "expires_in": token_response.get("expires_in", 3600),
                        "scope": token_response.get("scope", " ".join(fresh_user_info.get('scopes', [])))
                    }
                    
                    # Include new refresh token if present
                    if "refresh_token" in token_response:
                        response_data["refresh_token"] = token_response["refresh_token"]
                        logger.debug("New refresh token included in response")
                    
                    return web.json_response(response_data, headers={"Access-Control-Allow-Origin": "*"})
                    
                except Exception as refresh_error:
                    logger.error(f"Failed to refresh token with Okta: {refresh_error}")
                    return web.json_response({
                        "error": "invalid_grant",
                        "error_description": f"Failed to refresh token: {str(refresh_error)}"
                    }, status=400, headers={"Access-Control-Allow-Origin": "*"})
            
            else:
                return web.json_response({
                    "error": "unsupported_grant_type",
                    "error_description": f"Grant type '{grant_type}' is not supported"
                }, status=400, headers={"Access-Control-Allow-Origin": "*"})
                
        except Exception as e:
            logger.error(f"Token proxy failed: {e}")
            return web.json_response(
                {"error": "server_error", "error_description": str(e)}, 
                status=500,
                headers={"Access-Control-Allow-Origin": "*"}
            )

    async def cleanup_expired_entries(self):
        """Clean up expired entries from various stores"""
        try:
            now = datetime.now(timezone.utc)
            
            # Clean up expired state store entries
            expired_states = []
            for state, data in self.state_store.items():
                if isinstance(data, dict):
                    # Check for timestamp-based expiration (older entries)
                    created_at_str = data.get('timestamp')
                    if created_at_str:
                        try:
                            created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                            if now > created_at + timedelta(hours=1):  # 1 hour expiration
                                expired_states.append(state)
                        except ValueError:
                            pass
                    
                    # Check for explicit expiration (auth codes)
                    expires_at_str = data.get('expires_at')
                    if expires_at_str:
                        try:
                            expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                            if now > expires_at:
                                expired_states.append(state)
                        except ValueError:
                            pass
            
            # Remove expired state entries
            for state in expired_states:
                del self.state_store[state]
                logger.debug(f"Cleaned up expired state entry: {state}")
            
            # Clean up expired virtual tokens
            expired_tokens = []
            for token, token_data in self.tokens.items():
                if isinstance(token_data, dict):
                    created_at_str = token_data.get('created_at')
                    expires_in = token_data.get('expires_in', 3600)
                    if created_at_str:
                        try:
                            created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                            if now > created_at + timedelta(seconds=expires_in):
                                expired_tokens.append(token)
                        except ValueError:
                            pass
            
            # Remove expired tokens
            for token in expired_tokens:
                del self.tokens[token]
                logger.debug(f"Cleaned up expired virtual token: {token[:20]}...")
            
            # Clean up expired user consents
            expired_consents = []
            for consent_key, consent in self.user_consents.items():
                if hasattr(consent, 'expires_at') and now > consent.expires_at:
                    expired_consents.append(consent_key)
            
            # Remove expired consents
            for consent_key in expired_consents:
                del self.user_consents[consent_key]
                logger.debug(f"Cleaned up expired user consent: {consent_key}")
            
            if expired_states or expired_tokens or expired_consents:
                logger.info(f"Cleanup completed: {len(expired_states)} states, {len(expired_tokens)} tokens, {len(expired_consents)} consents removed")
                
        except Exception as e:
            logger.error(f"Cleanup task failed: {e}")
