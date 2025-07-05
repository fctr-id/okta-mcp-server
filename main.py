"""
Main entry point for the Okta MCP Server.

This script runs the main MCP server with STDIO transport for direct MCP client connections
(such as VS Code MCP extensions, Claude Desktop, etc.). It does NOT provide OAuth authentication.

BEHAVIOR:
- Runs MCP server with STDIO transport (no HTTP, no OAuth)
- Validates required Okta environment variables
- Creates and starts the MCP server for direct client connections
- Exits when the STDIO connection is closed

FOR OAUTH-PROTECTED WEB ACCESS:
Use the unified server runner instead:
    python -m okta_mcp.run_server mcp-withauth

FOR ALL SERVER OPTIONS:
    python -m okta_mcp.run_server --help
"""
import os
import sys
import logging

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure logging
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("okta_mcp")

def main():
    """Start the main Okta MCP server with STDIO transport."""
    try:
        # Check for required environment variables
        required_vars = ["OKTA_CLIENT_ORGURL", "OKTA_API_TOKEN"]
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
            logger.error("Create a .env file with:")
            logger.error("OKTA_CLIENT_ORGURL=https://your-org.okta.com")
            logger.error("OKTA_API_TOKEN=your_api_token_here")
            logger.error("LOG_LEVEL=INFO")
            logger.error("OKTA_CONCURRENT_LIMIT=15")
            logger.error("")
            logger.error("Generate an API token in Okta: Admin > Security > API > Tokens")
            return 1
        
        # Validate Okta URL format
        okta_url = os.getenv("OKTA_CLIENT_ORGURL")
        if not okta_url.startswith("https://"):
            logger.error("OKTA_CLIENT_ORGURL must be in format: https://your-org.okta.com")
            return 1
        
        # Import and create server
        from okta_mcp.compatibility.protocol_adapter import create_compatible_server
        from okta_mcp.server import run_with_stdio
        
        logger.info("Starting Okta MCP server with STDIO transport")
        server = create_compatible_server()
        run_with_stdio(server)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        logger.exception("Full error details:")
        return 1

if __name__ == "__main__":
    sys.exit(main())