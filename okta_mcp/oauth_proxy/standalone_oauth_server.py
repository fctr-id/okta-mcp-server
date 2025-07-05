"""
Standalone OAuth-protected FastMCP server.

This server replicates the main FastMCP server functionality with OAuth authentication
and RBAC filtering, running as a separate HTTP endpoint.
"""

import asyncio
import logging
from fastmcp import FastMCP
from okta_mcp.oauth_proxy.oauth_fastmcp_server import OAuthFastMCPMiddleware
from okta_mcp.oauth_proxy.auth_handler import AuthHandler
from okta_mcp.auth.oauth_provider import OAuthConfig

logger = logging.getLogger("oauth_standalone")

async def create_standalone_oauth_server() -> FastMCP:
    """
    Create a standalone OAuth-protected FastMCP server that replicates
    the main server's functionality with OAuth authentication and RBAC.
    """
    try:
        # Create OAuth configuration and auth handler
        config = OAuthConfig.from_environment()
        auth_handler = AuthHandler(config)
        
        # Create RBAC middleware
        from okta_mcp.middleware.authorization import OktaAuthorizationMiddleware
        rbac_middleware = OktaAuthorizationMiddleware()
        
        # Create OAuth middleware
        middleware = OAuthFastMCPMiddleware(auth_handler, rbac_middleware)
        
        # Create FastMCP server with OAuth middleware
        server = FastMCP(
            name="Okta OAuth MCP Server",
            instructions="""
            This server provides OAuth-protected Okta Identity Cloud management capabilities.
            All requests require OAuth authentication and are filtered based on user roles.
            Use list_okta_users() to search and filter users with SCIM expressions.
            Use get_okta_user() to retrieve detailed user information.
            """,
            middleware=[middleware]
        )
        
        # Register all tools exactly like the main server
        from okta_mcp.utils.okta_client import OktaMcpClient, create_okta_client
        import os
        
        logger.info("Initializing Okta client for OAuth server")
        
        # Create the Okta SDK client
        org_url = os.getenv('OKTA_CLIENT_ORGURL')
        api_token = os.getenv('OKTA_API_TOKEN')
        okta_sdk_client = create_okta_client(org_url, api_token)
        
        # Create the MCP wrapper
        okta_client = OktaMcpClient(client=okta_sdk_client)
        
        # Register all tools exactly like the main server
        from okta_mcp.tools.user_tools import register_user_tools
        from okta_mcp.tools.apps_tools import register_apps_tools
        from okta_mcp.tools.log_events_tools import register_log_events_tools
        from okta_mcp.tools.group_tools import register_group_tools
        from okta_mcp.tools.policy_network_tools import register_policy_tools 
        from okta_mcp.tools.datetime_tools import register_datetime_tools
        
        register_user_tools(server, okta_client)
        register_apps_tools(server, okta_client)
        register_log_events_tools(server, okta_client)
        register_group_tools(server, okta_client)
        register_policy_tools(server, okta_client) 
        register_datetime_tools(server, okta_client)
        
        # Store client reference
        server.okta_client = okta_client
        
        logger.info("Created standalone OAuth-protected FastMCP server with all tools")
        return server
        
    except Exception as e:
        logger.error(f"Failed to create standalone OAuth server: {e}")
        raise

def run_standalone_oauth_server(host: str = "localhost", port: int = 3002):
    """
    Run the standalone OAuth-protected FastMCP server.
    
    This runs the server directly using FastMCP's built-in HTTP transport,
    bypassing the need for proxy integration.
    """
    try:
        logger.info(f"Starting standalone OAuth FastMCP server on {host}:{port}")
        
        # Create the OAuth-protected server synchronously 
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        server = loop.run_until_complete(create_standalone_oauth_server())
        
        # Run with FastMCP's built-in HTTP transport
        logger.info("Starting OAuth FastMCP server with streamable-http transport")
        server.run(
            transport="streamable-http",
            host=host,
            port=port
        )
        
    except Exception as e:
        logger.error(f"Error running standalone OAuth server: {e}")
        raise

if __name__ == "__main__":
    import sys
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Get host and port from command line args
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3002
    
    # Run the server
    run_standalone_oauth_server(host, port)
