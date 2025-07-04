#!/usr/bin/env python3
"""
OAuth FastMCP Proxy Server

Main server implementation that wires together all the OAuth proxy modules.
This replaces the monolithic oauth_proxy.py with a modular structure.
"""

import os
import sys
import asyncio
import logging
import argparse
from typing import Optional
from datetime import datetime

from aiohttp import web
from aiohttp_session import setup
from aiohttp_session.cookie_storage import EncryptedCookieStorage

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add parent directory to path for imports when running as script
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from okta_mcp.auth.oauth_provider import OAuthConfig
from okta_mcp.oauth_proxy.utils import generate_secure_session_key, setup_logging
from okta_mcp.oauth_proxy.auth_handler import AuthHandler
from okta_mcp.oauth_proxy.ui_handlers import UIHandlers
from okta_mcp.oauth_proxy.mcp_handler import MCPHandler
from okta_mcp.oauth_proxy.discovery_handler import DiscoveryHandler

logger = logging.getLogger("oauth_proxy")


class OAuthFastMCPProxy:
    """OAuth-protected FastMCP proxy server"""
    
    def __init__(self, backend_server_path: str = "./main.py"):
        self.backend_server_path = backend_server_path
        self.config = OAuthConfig.from_environment()
        
        # Resolve backend path relative to project root if it's a relative path
        if not os.path.isabs(backend_server_path) and backend_server_path.startswith('./'):
            # Get project root (3 levels up from this file)
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            self.backend_server_path = os.path.join(project_root, backend_server_path[2:])  # Remove './'
        
        # Create handlers
        self.auth_handler = AuthHandler(self.config)
        self.ui_handlers = UIHandlers(self.auth_handler)
        
        # Create FastMCP proxy
        from fastmcp import FastMCP
        self.mcp_proxy = FastMCP.as_proxy(
            self.backend_server_path,
            name="OktaOAuthMCPProxy"
        )
        
        self.mcp_handler = MCPHandler(self.mcp_proxy, self.auth_handler)
        self.discovery_handler = DiscoveryHandler(self.config)
        
        # Setup HTTP application
        self.app = web.Application()
        self._setup_middleware()
        self._setup_routes()
        
    def _setup_middleware(self):
        """Setup middleware for security and session management"""
        # Add security middleware first
        self.app.middlewares.append(self._security_middleware)
        
        # Setup encrypted cookie session storage
        session_key = generate_secure_session_key()
        storage = EncryptedCookieStorage(
            session_key,
            cookie_name='AIOHTTP_SESSION',
            domain=None,
            max_age=7200,  # 2 hours
            path='/',
            secure=self.config.require_https,  # Use OAUTH_REQUIRE_HTTPS setting
            httponly=True,  # Prevent XSS access to session cookie
            samesite='Lax'
        )
        setup(self.app, storage)
    
    @web.middleware
    async def _security_middleware(self, request: web.Request, handler):
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
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY', 
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': 'strict-origin-when-cross-origin'
            }
            
            for header, value in security_headers.items():
                response.headers[header] = value
                
            return response
            
        except Exception as e:
            self._audit_log("request_error", details={"error": str(e), "path": request.path})
            raise
    
    def _audit_log(self, event_type: str, user_id: str = None, details: dict = None):
        """Security audit logging"""
        import json
        from datetime import timezone
        audit_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'details': details or {}
        }
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")
    
    def _setup_routes(self):
        """Setup all routes by delegating to handlers"""
        # Home and health routes
        self.app.router.add_get("/", self._home)
        self.app.router.add_post("/", self.mcp_handler.handle_post_root)
        self.app.router.add_get("/health", self._health_check)
        
        # OAuth discovery endpoints (with CORS support)
        self.app.router.add_route('*', '/.well-known/oauth-protected-resource', 
                                 self.discovery_handler.oauth_protected_resource_metadata)
        self.app.router.add_route('*', '/.well-known/oauth-authorization-server', 
                                 self.discovery_handler.oauth_authorization_server_metadata)
        self.app.router.add_route('*', '/.well-known/jwks.json', 
                                 self.discovery_handler.oauth_jwks_proxy)
        
        # OAuth authentication routes
        self.app.router.add_get('/oauth/permissions', self.ui_handlers.permissions_info)
        self.app.router.add_get('/oauth/consent', self.ui_handlers.consent_page)
        self.app.router.add_post('/oauth/consent', self.ui_handlers.handle_consent)
        self.app.router.add_get('/oauth/login', self.auth_handler.oauth_login)
        self.app.router.add_get('/oauth/callback', self.auth_handler.oauth_callback)
        self.app.router.add_get('/oauth/status', self.auth_handler.oauth_status)
        self.app.router.add_get('/oauth/logout', self.auth_handler.oauth_logout)
        
        # Dynamic Client Registration endpoint (for MCP Inspector etc.)
        self.app.router.add_post('/oauth2/v1/clients', self.auth_handler.oauth_register_client)
        self.app.router.add_get('/oauth2/v1/clients', self.auth_handler.oauth_register_client)
        self.app.router.add_options('/oauth2/v1/clients', self.auth_handler.oauth_register_client)
        
        # Authorization and token endpoint proxies
        self.app.router.add_get('/oauth2/v1/authorize', self.auth_handler.oauth_authorize_proxy)
        self.app.router.add_post('/oauth2/v1/token', self.auth_handler.oauth_token_proxy)
        self.app.router.add_options('/oauth2/v1/token', self.auth_handler.oauth_token_proxy)
        
        # OAuth endpoints for virtual clients
        self.app.router.add_get('/oauth/authorize', self.auth_handler.oauth_authorize_virtual)
        self.app.router.add_post('/oauth/token', self.auth_handler.oauth_token_virtual)
        self.app.router.add_get('/oauth/userinfo', self.auth_handler.oauth_userinfo_virtual)
        
        # Protected MCP endpoints
        self.app.router.add_get("/mcp/tools", self.mcp_handler.protected_mcp_tools)
        self.app.router.add_post("/mcp/tools/call", self.mcp_handler.protected_mcp_call)
        self.app.router.add_get("/mcp/resources", self.mcp_handler.protected_mcp_resources)
        self.app.router.add_post("/mcp/resources/read", self.mcp_handler.protected_mcp_read_resource)
        self.app.router.add_get("/mcp/prompts", self.mcp_handler.protected_mcp_prompts)
        
        # Static file serving for images
        # Resolve images path relative to project root
        if not os.path.isabs('./images/'):
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            images_path = os.path.join(project_root, 'images')
        else:
            images_path = './images/'
        
        self.app.router.add_static('/images/', path=images_path, name='images')
    
    async def _home(self, request: web.Request) -> web.Response:
        """Home page with OAuth status and MCP info"""
        user_info = await self.auth_handler.get_user_from_request(request)
        
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
    
    async def _health_check(self, request: web.Request) -> web.Response:
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
    
    async def run(self, host: str = "localhost", port: int = 3001):
        """Run the OAuth FastMCP proxy server"""
        try:
            logger.info(f"Starting OAuth FastMCP proxy server on {host}:{port}")
            
            # Start periodic cleanup task for expired entries
            async def periodic_cleanup():
                while True:
                    try:
                        await asyncio.sleep(300)  # Run every 5 minutes
                        await self.auth_handler.cleanup_expired_entries()
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
    setup_logging(args.log_level)
    
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


if __name__ == "__main__":
    asyncio.run(main())
