"""Main MCP server implementation for Okta."""
import os
import logging
from mcp.server.fastmcp import FastMCP, Context

# Configure logging
logger = logging.getLogger("okta_mcp")

def create_server():
    """Create and configure the MCP server for either STDIO or SSE transport."""
    try:
        # Create the Okta MCP server
        mcp = FastMCP(
            "Okta MCP Server", 
            capabilities={
                "tools": {
                    "listChanged": True  # Enable tool change notifications
                }
            }
        )
        
        # Create Okta client
        from okta_mcp.utils.okta_client import create_okta_client, OktaMcpClient
        
        logger.info("Initializing Okta client")
        okta_client = create_okta_client(
            org_url=os.getenv("OKTA_ORG_URL"),
            api_token=os.getenv("OKTA_API_TOKEN")
        )
        okta_mcp_client = OktaMcpClient(okta_client)
        
        # Get the tool registry singleton
        from okta_mcp.tools.tool_registry import ToolRegistry
        registry = ToolRegistry()
        
        # Initialize the registry with the server
        logger.info("Initializing tool registry")
        registry.initialize_server(mcp)
        
        # Register tools using the registry
        logger.info("Registering tools")
        registry.register_all_tools(mcp, okta_mcp_client)
        
        logger.info("MCP server created and tools registered successfully")
        return mcp
    
    except Exception as e:
        logger.error(f"Error creating MCP server: {e}")
        raise

# Non-async function for STDIO transport
def run_with_stdio(server):
    """Run the server with STDIO transport."""
    import anyio
    
    logger.info("Starting server with STDIO transport")
    
    # Use the non-async run method which handles its own event loop
    server.run()

def run_with_sse(server, host="0.0.0.0", port=3000, reload=False):
    """Run the server with SSE transport."""
    import uvicorn
    
    logger.info(f"Starting server with SSE transport on {host}:{port}")
    logger.info(f"Connect to the server at http://{host}:{port}")
    
    app = server.sse_app()
    uvicorn.run(app, host=host, port=port, reload=reload)

if __name__ == "__main__":
    # When run directly, use STDIO transport as a safe default
    mcp = create_server()
    run_with_stdio(mcp)