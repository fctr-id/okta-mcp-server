"""
Main entry point for the Okta MCP Server using FastMCP 2.8.1.
Run this file to start the server.
"""
import os
import sys
import logging
import argparse
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("okta_mcp")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Okta MCP Server")
    
    # Transport flags
    parser.add_argument("--http", action="store_true", 
                      help="Use HTTP transport (recommended for web)")
    parser.add_argument("--sse", action="store_true", 
                      help="Use SSE transport (deprecated, falls back to HTTP)")
    parser.add_argument("--stdio", action="store_true", 
                      help="Use STDIO transport (default, secure)")
    parser.add_argument("--iunderstandtherisks", action="store_true",
                      help="Acknowledge security risks of network transports")
    
    # HTTP configuration
    parser.add_argument("--host", default="127.0.0.1", 
                      help="Host to bind to for HTTP transport (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3000, 
                      help="Port for HTTP transport (default: 3000)")
    
    # General configuration
    parser.add_argument("--log-level", default="INFO", 
                      choices=["DEBUG", "INFO", "WARNING", "ERROR"], 
                      help="Set logging level (default: INFO)")
    
    # Authentication flags (NEW)
    parser.add_argument("--no-auth", action="store_true",
                      help="Disable authentication even if configured in environment")
    
    return parser.parse_args()

def main():
    """Start the Okta MCP server."""
    # Parse arguments
    args = parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Load environment variables
    load_dotenv()
    
    # Check for environment variables (warn but don't block)
    required_vars = ["OKTA_CLIENT_ORGURL", "OKTA_API_TOKEN"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.warning(f"Missing Okta environment variables: {', '.join(missing_vars)}")
        logger.warning("Server will start but Okta tools will require configuration to work.")
        logger.warning("Create a .env file with:")
        logger.warning("OKTA_CLIENT_ORGURL=https://your-org.okta.com")
        logger.warning("OKTA_API_TOKEN=your_api_token_here")
        logger.warning("LOG_LEVEL=INFO")
        logger.warning("OKTA_CONCURRENT_LIMIT=15")
        logger.warning("")
        logger.warning("Generate an API token in Okta: Admin > Security > API > Tokens")
    
    # Validate Okta URL format (only if provided)
    okta_url = os.getenv("OKTA_CLIENT_ORGURL")
    if okta_url and not okta_url.startswith("https://"):
        logger.error("OKTA_CLIENT_ORGURL must be in format: https://your-org.okta.com")
        return 1
    
    try:
        # Import server module
        from okta_mcp.server import create_server, run_with_http, run_with_sse, run_with_stdio
        
        # Create server (now with optional auth)
        server = create_server(enable_auth=not args.no_auth)
        
        # Determine transport
        if args.http:
            if not args.iunderstandtherisks:
                logger.error("HTTP transport requires --iunderstandtherisks flag")
                logger.error("HTTP transport exposes server over network - ensure proper security")
                return 1
            
            logger.warning("SECURITY: HTTP transport exposes server over network")
            run_with_http(server, args.host, args.port)
            
        elif args.sse:
            if not args.iunderstandtherisks:
                logger.error("SSE transport requires --iunderstandtherisks flag")
                return 1
            
            logger.warning("SECURITY: SSE transport exposes server over network")
            logger.warning("DEPRECATED: SSE transport is deprecated, use --http")
            run_with_sse(server, args.host, args.port)
            
        else:
            # Default to STDIO (secure)
            logger.info("Using STDIO transport (secure, recommended)")
            run_with_stdio(server)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        logger.exception("Full error details:")
        return 1

if __name__ == "__main__":
    sys.exit(main())