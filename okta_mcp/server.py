"""Main MCP server implementation for Okta using FastMCP 2.8.1."""

import os
import logging
from fastmcp import FastMCP

logger = logging.getLogger("okta_mcp") 

def create_auth_provider():
    """Create authentication provider if configured."""
    try:
        # Check if authentication is enabled
        enable_auth = os.getenv('ENABLE_AUTH', 'false').lower() == 'true'
        if not enable_auth:
            return None
            
        from fastmcp.server.auth import BearerAuthProvider
        
        # Get auth configuration
        public_key = os.getenv('AUTH_PUBLIC_KEY')
        jwks_uri = os.getenv('AUTH_JWKS_URI')
        issuer = os.getenv('AUTH_ISSUER')
        audience = os.getenv('AUTH_AUDIENCE', 'okta-mcp-server')
        required_scopes_str = os.getenv('AUTH_REQUIRED_SCOPES', '')
        
        # Parse required scopes
        required_scopes = [scope.strip() for scope in required_scopes_str.split(',') if scope.strip()] if required_scopes_str else None
        
        # Validate configuration
        if not public_key and not jwks_uri:
            logger.warning("Authentication enabled but no AUTH_PUBLIC_KEY or AUTH_JWKS_URI provided. Skipping auth.")
            return None
            
        if public_key and jwks_uri:
            logger.warning("Both AUTH_PUBLIC_KEY and AUTH_JWKS_URI provided. Using JWKS_URI.")
            public_key = None
        
        # Create auth provider
        auth_provider = BearerAuthProvider(
            public_key=public_key,
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=audience,
            required_scopes=required_scopes
        )
        
        logger.info(f"Authentication enabled with {'JWKS' if jwks_uri else 'static key'}")
        if issuer:
            logger.info(f"Required issuer: {issuer}")
        if audience:
            logger.info(f"Required audience: {audience}")
        if required_scopes:
            logger.info(f"Required scopes: {required_scopes}")
            
        return auth_provider
        
    except ImportError:
        logger.error("Authentication dependencies not available. Install with: pip install 'fastmcp[auth]'")
        return None
    except Exception as e:
        logger.error(f"Error creating auth provider: {e}")
        return None

def create_server(enable_auth: bool = True):
    """Create and configure the Okta MCP server using FastMCP 2.8.1."""
    try:
        # Create auth provider if enabled
        auth_provider = create_auth_provider() if enable_auth else None
        
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
            auth=auth_provider  # Add authentication if configured
        )
        
        # Create Okta client wrapper (will initialize on demand)
        from okta_mcp.utils.okta_client import OktaMcpClient
        okta_client = OktaMcpClient()  # No immediate initialization
        
        # Register tools with the lazy client
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
        
        auth_status = "with authentication" if auth_provider else "without authentication"
        logger.info(f"Okta MCP server created successfully {auth_status} with all tools registered")
        
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