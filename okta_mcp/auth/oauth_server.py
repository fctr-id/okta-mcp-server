"""
OAuth 2.0 Server implementation for Okta MCP Server
Uses Authlib for standard OAuth 2.0 flows with Okta as IdP
"""

import os
import asyncio
import logging
import secrets
import base64
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import aiohttp
from aiohttp import web, ClientSession
import jwt
from urllib.parse import urlencode, parse_qs
from authlib.integrations.base_client import OAuthError
from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from .oauth_provider import OAuthConfig

logger = logging.getLogger(__name__)

class OktaOAuthServer:
    """
    OAuth 2.0 Server implementation for Okta integration
    Handles the full OAuth flow as a confidential client
    """
    
    def __init__(self, config: Optional[OAuthConfig] = None):
        self.config = config or OAuthConfig.from_environment()
        self.app = web.Application()
        self.tokens: Dict[str, Dict[str, Any]] = {}  # In-memory token storage
        self.sessions: Dict[str, Dict[str, Any]] = {}  # Session storage
        self.redirect_uri = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:3001/oauth/callback")
        
        # Setup routes
        self._setup_routes()
        
        logger.info(f"OAuth server initialized for {self.config.org_url}")
    
    def _setup_routes(self):
        """Setup OAuth-related HTTP routes"""
        self.app.router.add_get("/health", self.health_check)
        self.app.router.add_get("/oauth/authorize", self.oauth_authorize)
        self.app.router.add_get("/oauth/callback", self.oauth_callback)
        self.app.router.add_get("/oauth/status", self.oauth_status)
        self.app.router.add_post("/oauth/logout", self.oauth_logout)
        
        # MCP proxy routes (will be added by the proxy wrapper)
        self.app.router.add_route("*", "/mcp/{path:.*}", self.mcp_proxy_handler)
    
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "oauth_configured": bool(self.config.client_id),
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def oauth_authorize(self, request: web.Request) -> web.Response:
        """Initiate OAuth authorization flow"""
        try:
            # Generate state for CSRF protection
            state = secrets.token_urlsafe(32)
            
            # Store state in session
            session_id = secrets.token_urlsafe(16)
            self.sessions[session_id] = {
                "state": state,
                "created_at": datetime.utcnow(),
                "user_agent": request.headers.get("User-Agent", "")
            }
            
            # Build authorization URL
            auth_params = {
                "client_id": self.config.client_id,
                "response_type": "code",
                "scope": " ".join(self.config.get_all_scopes()),
                "redirect_uri": self.redirect_uri,
                "state": state
            }
            
            auth_url = f"{self.config.authorization_url}?{urlencode(auth_params)}"
            
            logger.info(f"Initiating OAuth flow with state: {state}")
            
            # Return redirect or JSON based on Accept header
            if "application/json" in request.headers.get("Accept", ""):
                response = web.json_response({
                    "authorization_url": auth_url,
                    "state": state,
                    "session_id": session_id
                })
            else:
                response = web.Response(status=302, headers={"Location": auth_url})
            
            # Set session cookie
            response.set_cookie("oauth_session", session_id, httponly=True, secure=False)  # Set secure=True in production
            
            return response
            
        except Exception as e:
            logger.error(f"OAuth authorization failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def oauth_callback(self, request: web.Request) -> web.Response:
        """Handle OAuth callback from Okta"""
        try:
            # Get authorization code and state
            code = request.query.get("code")
            state = request.query.get("state")
            error = request.query.get("error")
            
            if error:
                logger.error(f"OAuth callback error: {error}")
                return web.json_response({"error": error}, status=400)
            
            if not code or not state:
                return web.json_response({"error": "Missing code or state"}, status=400)
            
            # Verify state
            session_id = request.cookies.get("oauth_session")
            if not session_id or session_id not in self.sessions:
                return web.json_response({"error": "Invalid session"}, status=400)
            
            session = self.sessions[session_id]
            if session["state"] != state:
                return web.json_response({"error": "Invalid state"}, status=400)
            
            # Exchange code for token
            token_data = await self._exchange_code_for_token(code)
            
            if not token_data:
                return web.json_response({"error": "Token exchange failed"}, status=500)
            
            # Store token
            access_token = token_data.get("access_token")
            user_info = await self._get_user_info(access_token)
            
            # Store in token storage
            token_id = secrets.token_urlsafe(16)
            self.tokens[token_id] = {
                "access_token": access_token,
                "refresh_token": token_data.get("refresh_token"),
                "expires_at": datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600)),
                "user_info": user_info,
                "created_at": datetime.utcnow()
            }
            
            # Update session
            session["token_id"] = token_id
            session["authenticated"] = True
            
            logger.info(f"OAuth flow completed for user: {user_info.get('email', 'unknown')}")
            
            # Return success page
            html_response = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>OAuth Success</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 50px; }}
                    .success {{ color: green; }}
                    .info {{ background: #f0f0f0; padding: 20px; margin: 20px 0; }}
                </style>
            </head>
            <body>
                <h1 class="success">✅ OAuth Authentication Successful!</h1>
                <div class="info">
                    <p><strong>User:</strong> {user_info.get('email', 'Unknown')}</p>
                    <p><strong>Name:</strong> {user_info.get('name', 'Unknown')}</p>
                    <p><strong>Scopes:</strong> {', '.join(user_info.get('scopes', []))}</p>
                </div>
                <p>You can now close this window and return to your MCP client.</p>
                <script>
                    // Auto-close after 5 seconds
                    setTimeout(function() {{
                        window.close();
                    }}, 5000);
                </script>
            </body>
            </html>
            """
            
            return web.Response(text=html_response, content_type="text/html")
            
        except Exception as e:
            logger.error(f"OAuth callback failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def oauth_status(self, request: web.Request) -> web.Response:
        """Get current OAuth authentication status"""
        try:
            session_id = request.cookies.get("oauth_session")
            
            if not session_id or session_id not in self.sessions:
                return web.json_response({
                    "authenticated": False,
                    "error": "No session found"
                })
            
            session = self.sessions[session_id]
            
            if not session.get("authenticated"):
                return web.json_response({
                    "authenticated": False,
                    "session_active": True
                })
            
            token_id = session.get("token_id")
            if not token_id or token_id not in self.tokens:
                return web.json_response({
                    "authenticated": False,
                    "error": "Token not found"
                })
            
            token_info = self.tokens[token_id]
            user_info = token_info.get("user_info", {})
            
            # Check token expiration
            expires_at = token_info.get("expires_at")
            is_expired = expires_at and datetime.utcnow() > expires_at
            
            return web.json_response({
                "authenticated": not is_expired,
                "user_info": {
                    "email": user_info.get("email"),
                    "name": user_info.get("name"),
                    "user_id": user_info.get("user_id"),
                    "scopes": user_info.get("scopes", [])
                },
                "token_expires_at": expires_at.isoformat() if expires_at else None,
                "is_expired": is_expired
            })
            
        except Exception as e:
            logger.error(f"OAuth status check failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def oauth_logout(self, request: web.Request) -> web.Response:
        """Logout and clear OAuth session"""
        try:
            session_id = request.cookies.get("oauth_session")
            
            if session_id and session_id in self.sessions:
                session = self.sessions[session_id]
                token_id = session.get("token_id")
                
                # Remove token
                if token_id and token_id in self.tokens:
                    del self.tokens[token_id]
                
                # Remove session
                del self.sessions[session_id]
            
            response = web.json_response({"message": "Logged out successfully"})
            response.del_cookie("oauth_session")
            
            return response
            
        except Exception as e:
            logger.error(f"OAuth logout failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def mcp_proxy_handler(self, request: web.Request) -> web.Response:
        """Handle MCP requests - will be implemented by proxy wrapper"""
        return web.json_response({"error": "MCP proxy not configured"}, status=501)
    
    async def _exchange_code_for_token(self, code: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token"""
        try:
            token_data = {
                "grant_type": "authorization_code",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri
            }
            
            async with ClientSession() as session:
                async with session.post(self.config.token_url, data=token_data) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info("Token exchange successful")
                        return result
                    else:
                        error_text = await response.text()
                        logger.error(f"Token exchange failed: {response.status} - {error_text}")
                        return None
                        
        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            return None
    
    async def _get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Extract user information from access token"""
        try:
            # Decode JWT token (in production, verify signature)
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            
            return {
                "user_id": decoded.get("sub"),
                "email": decoded.get("email"),
                "name": decoded.get("name"),
                "roles": decoded.get("roles", []),
                "scopes": decoded.get("scope", "").split(),
                "audience": decoded.get("aud"),
                "issuer": decoded.get("iss")
            }
            
        except Exception as e:
            logger.error(f"Failed to extract user info: {e}")
            return {}
    
    def get_user_from_request(self, request: web.Request) -> Optional[Dict[str, Any]]:
        """Get authenticated user from request"""
        try:
            session_id = request.cookies.get("oauth_session")
            
            if not session_id or session_id not in self.sessions:
                return None
            
            session = self.sessions[session_id]
            if not session.get("authenticated"):
                return None
            
            token_id = session.get("token_id")
            if not token_id or token_id not in self.tokens:
                return None
            
            token_info = self.tokens[token_id]
            
            # Check token expiration
            expires_at = token_info.get("expires_at")
            if expires_at and datetime.utcnow() > expires_at:
                return None
            
            return token_info.get("user_info")
            
        except Exception as e:
            logger.error(f"Failed to get user from request: {e}")
            return None
    
    async def start_server(self, host: str = "localhost", port: int = 3001):
        """Start the OAuth server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(runner, host, port)
        await site.start()
        
        logger.info(f"OAuth server started on http://{host}:{port}")
        return runner
    
    async def stop_server(self, runner):
        """Stop the OAuth server"""
        await runner.cleanup()
        logger.info("OAuth server stopped")
