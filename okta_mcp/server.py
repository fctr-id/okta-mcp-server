"""Main MCP server implementation for Okta using FastMCP 2.8.1."""

import logging
from fastmcp import FastMCP

logger = logging.getLogger("okta_mcp") 

def create_server():
    """Create and configure the Okta MCP server using FastMCP 2.8.1."""
    try:
        # Create server with modern FastMCP features
        mcp = FastMCP(
            name="Okta MCP Server",
            instructions="""
            This server provides Okta Identity Cloud management capabilities.
            Use list_okta_users() to search and filter users with SCIM expressions.
            Use get_okta_user() to retrieve detailed user information.
            All operations require proper Okta API credentials in environment variables.
            """,
            # Use built-in error masking instead of custom handling
            mask_error_details=False,  # Show detailed errors for debugging
            # Removed stateless_http=True - it causes deprecation warning
        )
        
        # Initialize Okta client properly
        from okta_mcp.utils.okta_client import OktaMcpClient, create_okta_client
        import os
        
        logger.info("Initializing Okta client")
        
        # Create the Okta SDK client first
        org_url = os.getenv('OKTA_CLIENT_ORGURL')
        api_token = os.getenv('OKTA_API_TOKEN')
        okta_sdk_client = create_okta_client(org_url, api_token)
        
        # Now create the MCP wrapper with the SDK client
        okta_client = OktaMcpClient(client=okta_sdk_client)
        
        # Register tools directly - no registry needed
        logger.info("Registering Okta tools")
        from okta_mcp.tools.user_tools import register_user_tools
        from okta_mcp.tools.apps_tools import register_apps_tools
        from okta_mcp.tools.log_events_tools import register_log_events_tools
        from okta_mcp.tools.group_tools import register_group_tools
        from okta_mcp.tools.policy_network_tools import register_policy_tools 
        from okta_mcp.tools.datetime_tools import register_datetime_tools
        
        register_user_tools(mcp, okta_client)
        register_apps_tools(mcp, okta_client)
        register_log_events_tools(mcp, okta_client)
        register_group_tools(mcp, okta_client)
        register_policy_tools(mcp, okta_client) 
        register_datetime_tools(mcp, okta_client)
        
        # Store client reference for potential cleanup
        mcp.okta_client = okta_client
        
        logger.info("Okta MCP server created successfully with all tools registered")
        
        return mcp
    
    except Exception as e:
        logger.error(f"Error creating Okta MCP server: {e}")
        raise

def run_with_stdio(server):
    """Run the server with STDIO transport (secure, default)."""
    logger.info("Starting Okta server with STDIO transport")
    server.run()  # FastMCP defaults to STDIO

def run_with_sse(server, host="0.0.0.0", port=3000, reload=False):
    """Run the server with SSE transport (deprecated)."""
    logger.warning("SSE transport is deprecated in FastMCP 2.8.1, use --http instead")
    logger.info(f"Starting Okta server with SSE transport on {host}:{port}")
    
    try:
        server.run(transport="sse", host=host, port=port)
    except (ValueError, TypeError) as e:
        logger.warning(f"SSE transport failed ({e}), falling back to HTTP")
        run_with_http(server, host, port)

def run_with_http(server, host="0.0.0.0", port=3000):
    """Run the server with HTTP transport (modern, recommended for web)."""
    logger.info(f"Starting Okta server with HTTP transport on {host}:{port}")
    
    try:
        server.run(transport="streamable-http", host=host, port=port)
    except TypeError as e:
        logger.warning(f"Host/port not supported in this FastMCP version: {e}")
        server.run(transport="streamable-http")

if __name__ == "__main__":
    server = create_server()
    run_with_stdio(server)