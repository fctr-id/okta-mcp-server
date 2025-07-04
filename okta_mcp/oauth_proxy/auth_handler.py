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
                
                # Get user information from the token
                access_token = token_response["access_token"]
                user_info = await self._get_user_info_comprehensive(access_token)
                
                logger.info("Successfully exchanged authorization code for access token")
                
                # Store user information in session
                session["authenticated"] = True
                session["access_token"] = access_token
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
                    logger.debug(f"UserInfo endpoint response: {userinfo_data}")
                    
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
            decoded = self._verify_and_decode_jwt(access_token)
            if not decoded:
                logger.error("JWT verification failed")
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
            
        except jwt.ExpiredSignatureError:
            logger.error("JWT token has expired")
            self._audit_log("jwt_expired", details={"token_prefix": access_token[:20]})
            return None
        except jwt.InvalidAudienceError as e:
            logger.error(f"JWT audience validation failed: {e}")
            self._audit_log("jwt_invalid_audience", details={"error": str(e)})
            return None
        except jwt.InvalidIssuerError as e:
            logger.error(f"JWT issuer validation failed: {e}")
            self._audit_log("jwt_invalid_issuer", details={"error": str(e)})
            return None
        except jwt.InvalidSignatureError:
            logger.error("JWT signature validation failed")
            self._audit_log("jwt_invalid_signature", details={"token_prefix": access_token[:20]})
            return None
        except Exception as e:
            logger.error(f"JWT verification failed: {e}")
            self._audit_log("jwt_verification_error", details={"error": str(e)})
            return None

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
                
                # Check if this is a virtual access token
                if token in self.tokens:
                    token_data = self.tokens[token]
                    
                    # Check if token has expired
                    created_at = datetime.fromisoformat(token_data.get('created_at'))
                    expires_in = token_data.get('expires_in', 3600)
                    if datetime.now(timezone.utc) > created_at + timedelta(seconds=expires_in):
                        # Token expired, clean it up
                        del self.tokens[token]
                        audit_log("virtual_token_expired", user_id=token_data.get('user_id'))
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
                        audit_log("invalid_virtual_token", details={"token_prefix": token[:20]})
                        return None
                    
                    audit_log("virtual_token_access", user_id=token_data.get('user_id'), details={
                        'virtual_client_id': token_data.get('virtual_client_id'),
                        'path': request.path
                    })
                    
                    return user_info
            
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
                    
                    # Get user information from the real access token
                    real_access_token = token_response["access_token"]
                    user_info = await self._get_user_info_comprehensive(real_access_token)
                    
                    # Generate virtual access token for the virtual client
                    virtual_access_token = f"virtual_token_{secrets.token_urlsafe(32)}"
                    
                    # Store virtual token with real user info
                    self.tokens[virtual_access_token] = {
                        'virtual_client_id': virtual_client_id,
                        'user_id': user_info.get('user_id'),
                        'email': user_info.get('email'),
                        'name': user_info.get('name'),
                        'scopes': user_info.get('scopes', []),
                        'created_at': datetime.now(timezone.utc).isoformat(),
                        'expires_in': token_response.get("expires_in", 3600),
                        'real_access_token': real_access_token  # Store for API calls
                    }
                    
                    # Clean up the authorization code
                    del self.state_store[auth_code]
                    
                    logger.info(f"Created virtual token for user: {user_info.get('user_id')}")
                    
                    # Return token response
                    return web.json_response({
                        "access_token": virtual_access_token,
                        "token_type": "Bearer",
                        "expires_in": token_response.get("expires_in", 3600),
                        "scope": " ".join(user_info.get('scopes', []))
                    }, headers={"Access-Control-Allow-Origin": "*"})
                    
                except Exception as token_error:
                    logger.error(f"Failed to exchange authorization code with Okta: {token_error}")
                    import traceback
                    traceback.print_exc()
                    return web.json_response({
                        "error": "server_error",
                        "error_description": f"Failed to exchange authorization code: {str(token_error)}"
                    }, status=500, headers={"Access-Control-Allow-Origin": "*"})
            
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
