#!/usr/bin/env python3
"""
OAuth-enabled proxy server for Okta MCP Server.

This proxy server acts as an OAuth 2.0 Confidential Client that:
1. Handles OAuth authentication flow with Okta
2. Protects the backend Okta MCP server
3. Provides secure MCP endpoints for AI clients (Claude, etc.)

Architecture:
AI Client → OAuth Proxy Server (Confidential Client) → Okta MCP Server
                    ↕
                 Okta OAuth

Since FastMCP doesn't have built-in OAuth support yet, this implementation
uses a hybrid approach with standard OAuth libraries and MCP client integration.
"""

import os
import asyncio
import logging
from typing import Optional
from okta_mcp.proxy.oauth_mcp_bridge import OAuthMCPBridge

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("okta_oauth_proxy")

class OktaOAuthProxy:
    """OAuth proxy server for Okta MCP operations using hybrid OAuth-MCP bridge"""
    
    def __init__(self, backend_server_path: str = "./main.py"):
        self.backend_server_path = backend_server_path
        self.oauth_mcp_bridge: Optional[OAuthMCPBridge] = None
        
    async def run(self, transport: str = "http", host: str = "localhost", port: int = 3001):
        """Run the OAuth proxy server"""
        try:
            if transport == "stdio":
                logger.error("OAuth authentication requires HTTP transport")
                logger.info("For STDIO transport, use the regular MCP server: python main.py")
                raise ValueError("OAuth proxy requires HTTP transport")
                
            elif transport == "http":
                logger.info(f"Starting OAuth proxy with HTTP transport on {host}:{port}")
                
                # Create OAuth-MCP bridge
                self.oauth_mcp_bridge = OAuthMCPBridge(self.backend_server_path)
                
                # Start the server
                runner = await self.oauth_mcp_bridge.start_server(host, port)
                
                try:
                    # Keep the server running
                    logger.info("OAuth proxy server is running. Press Ctrl+C to stop.")
                    await asyncio.Event().wait()  # Run forever
                except KeyboardInterrupt:
                    logger.info("Shutting down OAuth proxy server...")
                finally:
                    await self.oauth_mcp_bridge.stop_server(runner)
                    
            else:
                raise ValueError(f"Unsupported transport: {transport}")
                
        except Exception as e:
            logger.error(f"Failed to start OAuth proxy: {e}")
            raise

def main():
    """Main entry point for OAuth proxy server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Okta MCP OAuth Proxy Server")
    parser.add_argument(
        "--transport", 
        choices=["stdio", "http"], 
        default="stdio", 
        help="Transport protocol (default: stdio)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=3001, 
        help="HTTP port if using HTTP transport (default: 3001)"
    )
    
    args = parser.parse_args()
    
    # Set port environment variable for HTTP transport
    if args.transport == "http":
        os.environ["OAUTH_PROXY_PORT"] = str(args.port)
    
    # Create and run proxy
    proxy = OktaOAuthProxy()
    
    try:
        asyncio.run(proxy.run(args.transport))
    except KeyboardInterrupt:
        logger.info("OAuth proxy server stopped by user")
    except Exception as e:
        logger.error(f"OAuth proxy server failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()