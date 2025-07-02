"""
Simple OAuth Proxy Server for MCP Inspector compatibility.
This provides the basic OAuth endpoints that MCP Inspector needs.
"""
import os
import sys
import logging
import asyncio
from typing import Dict, Any
from datetime import datetime, timezone
from dotenv import load_dotenv

from aiohttp import web, ClientSession
import aiohttp_cors
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("oauth_proxy")

class SimpleOAuthProxy:
    def __init__(self):
        load_dotenv()
        
        # Get Okta configuration from environment
        self.okta_domain = os.getenv("OKTA_CLIENT_ORGURL", "").replace("https://", "").replace("http://", "")
        self.client_id = os.getenv("OKTA_CLIENT_ID", "")
        
        if not self.okta_domain or not self.client_id:
            logger.error("Missing OKTA_CLIENT_ORGURL or OKTA_CLIENT_ID in environment")
            sys.exit(1)
        
        logger.info(f"Configured for Okta domain: {self.okta_domain}")
        
        # Simple in-memory store for virtual clients
        self.virtual_clients = {}
        
        # Create web app
        self.app = web.Application()
        
        # Setup CORS
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        # Add routes
        self.setup_routes()
        
        # Add CORS to all routes
        for route in list(self.app.router.routes()):
            cors.add(route)
    
    def setup_routes(self):
        """Setup OAuth proxy routes"""
        
        # Well-known endpoints
        self.app.router.add_get('/.well-known/oauth-protected-resource', self.oauth_protected_resource)
        self.app.router.add_get('/.well-known/oauth-authorization-server', self.oauth_authorization_server)
        self.app.router.add_get('/.well-known/jwks.json', self.jwks)
        
        # Dynamic Client Registration
        self.app.router.add_post('/oauth2/v1/clients', self.register_client)
        self.app.router.add_options('/oauth2/v1/clients', self.handle_options)
        
        # Basic info endpoint
        self.app.router.add_get('/', self.home)
    
    async def handle_options(self, request: web.Request) -> web.Response:
        """Handle CORS preflight requests"""
        return web.Response(status=200)
    
    async def home(self, request: web.Request) -> web.Response:
        """Home page with proxy information"""
        html = f"""
        <html>
        <head><title>OAuth MCP Proxy</title></head>
        <body>
            <h1>OAuth MCP Proxy Server</h1>
            <p>This server provides OAuth proxy endpoints for MCP Inspector.</p>
            <h2>Configuration</h2>
            <ul>
                <li>Okta Domain: {self.okta_domain}</li>
                <li>Client ID: {self.client_id}</li>
            </ul>
            <h2>Available Endpoints</h2>
            <ul>
                <li><a href="/.well-known/oauth-protected-resource">/.well-known/oauth-protected-resource</a></li>
                <li><a href="/.well-known/oauth-authorization-server">/.well-known/oauth-authorization-server</a></li>
                <li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a></li>
                <li>POST /oauth2/v1/clients (Dynamic Client Registration)</li>
            </ul>
            <h2>Virtual Clients Registered</h2>
            <pre>{json.dumps(self.virtual_clients, indent=2)}</pre>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def oauth_protected_resource(self, request: web.Request) -> web.Response:
        """OAuth 2.0 Protected Resource metadata"""
        metadata = {
            "resource": f"https://{request.host}",
            "authorization_servers": [f"https://{self.okta_domain}/oauth2/default"],
            "scopes_supported": [
                "openid", "profile", "email",
                "okta.users.read", "okta.groups.read", "okta.apps.read",
                "okta.events.read", "okta.logs.read", "okta.policies.read",
                "okta.devices.read", "okta.factors.read"
            ],
            "bearer_methods_supported": ["header", "body", "query"],
            "resource_documentation": "https://github.com/modelcontextprotocol/inspector"
        }
        return web.json_response(metadata)
    
    async def oauth_authorization_server(self, request: web.Request) -> web.Response:
        """OAuth 2.0 Authorization Server metadata"""
        base_url = f"https://{self.okta_domain}/oauth2/default"
        
        metadata = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/v1/authorize",
            "token_endpoint": f"{base_url}/v1/token",
            "userinfo_endpoint": f"{base_url}/v1/userinfo",
            "registration_endpoint": f"https://{request.host}/oauth2/v1/clients",
            "jwks_uri": f"{base_url}/v1/keys",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": [
                "openid", "profile", "email", "offline_access",
                "okta.users.read", "okta.groups.read", "okta.apps.read",
                "okta.events.read", "okta.logs.read", "okta.policies.read",
                "okta.devices.read", "okta.factors.read"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic", "client_secret_post", "none"
            ],
            "claims_supported": ["sub", "email", "name", "preferred_username"]
        }
        return web.json_response(metadata)
    
    async def jwks(self, request: web.Request) -> web.Response:
        """Proxy JWKS from Okta"""
        try:
            async with ClientSession() as session:
                jwks_url = f"https://{self.okta_domain}/oauth2/default/v1/keys"
                async with session.get(jwks_url) as response:
                    if response.status == 200:
                        jwks_data = await response.json()
                        return web.json_response(jwks_data)
                    else:
                        logger.error(f"Failed to fetch JWKS: {response.status}")
                        return web.json_response({"error": "Failed to fetch JWKS"}, status=500)
        except Exception as e:
            logger.error(f"JWKS proxy error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def register_client(self, request: web.Request) -> web.Response:
        """Handle Dynamic Client Registration"""
        try:
            # Parse registration request
            registration_data = await request.json()
            logger.info(f"Client registration request: {registration_data}")
            
            client_name = registration_data.get("client_name", "Unknown Client")
            redirect_uris = registration_data.get("redirect_uris", [])
            
            # Basic validation
            if not redirect_uris:
                return web.json_response({
                    "error": "invalid_redirect_uri",
                    "error_description": "redirect_uris is required"
                }, status=400)
            
            # Generate virtual client ID
            import hashlib
            client_id = f"virtual-{hashlib.sha256(client_name.encode()).hexdigest()[:16]}"
            
            # Store virtual client
            self.virtual_clients[client_id] = {
                "client_name": client_name,
                "redirect_uris": redirect_uris,
                "registered_at": datetime.now(timezone.utc).isoformat(),
                "real_client_id": self.client_id  # Map to our real Okta client
            }
            
            logger.info(f"Registered virtual client: {client_id}")
            
            # Return registration response
            response_data = {
                "client_id": client_id,
                "client_name": client_name,
                "redirect_uris": redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "client_id_issued_at": int(datetime.now(timezone.utc).timestamp()),
                "registration_access_token": "not-implemented",
                "registration_client_uri": f"https://{request.host}/oauth2/v1/clients/{client_id}"
            }
            
            return web.json_response(response_data, status=201)
            
        except Exception as e:
            logger.error(f"Client registration failed: {e}")
            return web.json_response({
                "error": "server_error",
                "error_description": str(e)
            }, status=500)

async def main():
    """Main entry point"""
    proxy = SimpleOAuthProxy()
    
    # Create and start the server
    runner = web.AppRunner(proxy.app)
    await runner.setup()
    
    host = "127.0.0.1"
    port = 3001
    
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    logger.info(f"OAuth Proxy Server started on http://{host}:{port}")
    logger.info("Available endpoints:")
    logger.info("  - /.well-known/oauth-protected-resource")
    logger.info("  - /.well-known/oauth-authorization-server")
    logger.info("  - /.well-known/jwks.json")
    logger.info("  - POST /oauth2/v1/clients (DCR)")
    logger.info("")
    logger.info("For MCP Inspector, use this as your OAuth server URL:")
    logger.info(f"  http://{host}:{port}")
    
    try:
        # Keep the server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
