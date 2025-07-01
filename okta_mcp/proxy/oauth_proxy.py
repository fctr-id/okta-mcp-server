"""OAuth proxy implementation for Okta MCP Server"""

import logging
from typing import Optional, Dict, Any
from fastmcp import FastMCP
from okta_mcp.auth.oauth_provider import create_okta_oauth_provider
from okta_mcp.middleware.authorization import OktaAuthorizationMiddleware

logger = logging.getLogger(__name__)

class OktaOAuthProxyServer:
    """OAuth-enabled proxy server for Okta MCP operations"""
    
    def __init__(self, backend_server_path: str = "./main.py"):
        self.backend_server_path = backend_server_path
        self.proxy_server: Optional[FastMCP] = None
        self.oauth_provider = None
    
    async def create_proxy(self, name: str = "Okta OAuth Proxy") -> FastMCP:
        """Create OAuth-protected proxy to Okta MCP server"""
        try:
            # Create OAuth provider
            self.oauth_provider = create_okta_oauth_provider()
            
            # Create proxy to backend server
            proxy = FastMCP.as_proxy(
                self.backend_server_path,
                name=name,
                auth_provider=self.oauth_provider
            )
            
            # Add authorization middleware
            proxy.add_middleware(OktaAuthorizationMiddleware())
            
            logger.info(f"OAuth proxy created for backend: {self.backend_server_path}")
            return proxy
            
        except Exception as e:
            logger.error(f"Failed to create OAuth proxy: {e}")
            raise
    
    async def get_proxy_info(self) -> Dict[str, Any]:
        """Get information about the proxy configuration"""
        if not self.proxy_server:
            return {"status": "not_initialized"}
        
        return {
            "status": "initialized",
            "backend_path": self.backend_server_path,
            "oauth_enabled": self.oauth_provider is not None,
            "proxy_name": self.proxy_server.name if self.proxy_server else None
        }


def create_okta_oauth_proxy(
    backend_path: str = "./main.py",
    name: str = "Okta OAuth Proxy"
) -> FastMCP:
    """Factory function to create OAuth proxy server"""
    import asyncio
    
    async def _create():
        proxy_server = OktaOAuthProxyServer(backend_path)
        return await proxy_server.create_proxy(name)
    
    return asyncio.run(_create())