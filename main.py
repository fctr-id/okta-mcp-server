"""
Main entry point for the Okta MCP Server.
Run this file to start the server.
"""
import os
import sys
import logging
import argparse
from dotenv import load_dotenv

# Add this right after imports
try:
    import mcp.server.lowlevel.server as mcp_server
    mcp_server.VERBOSE_LOGGING = False  # This will disable the processing request logs
    logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.WARNING)
except ImportError:
    print("Could not import mcp server module to disable verbose logging")

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
    parser.add_argument("--sse", action="store_true", 
                      help="Use SSE transport instead of default STDIO")
    parser.add_argument("--iunderstandtherisks", action="store_true",
                      help="Acknowledge security risks of using SSE transport")
    
    # SSE configuration
    parser.add_argument("--host", default="0.0.0.0", 
                      help="Host to bind to for SSE transport (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=3000, 
                      help="Port to run on for SSE transport (default: 3000)")
    parser.add_argument("--reload", action="store_true", 
                      help="Enable auto-reload for development (SSE only)")
    
    # General configuration
    parser.add_argument("--log-level", default="INFO", 
                      choices=["DEBUG", "INFO", "WARNING", "ERROR"], 
                      help="Set logging level (default: INFO)")
    
    return parser.parse_args()

def main():
    """Start the Okta MCP server."""
    # Parse arguments
    args = parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Load environment variables
    load_dotenv()
    
    # Check for required environment variables
    required_vars = ["OKTA_CLIENT_ORGURL", "OKTA_API_TOKEN"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        logger.error("Create a .env file with the following variables:")
        logger.error("OKTA_CLIENT_ORGURL=https://your-org.okta.com")
        logger.error("OKTA_API_TOKEN=your-api-token")
        return 1
    
    # Import server module
    from okta_mcp.server import create_server, run_with_stdio, run_with_sse
    
    try:
        # Create server
        server = create_server()
        
        # Check transport selection
        if args.sse:
            # Check for risk acknowledgment
            if not args.iunderstandtherisks:
                logger.error("SSE transport requires explicit risk acknowledgment")
                logger.error("Add --iunderstandtherisks flag to run with SSE transport")
                return 1
            
            # Show security warning
            logger.warning("SECURITY WARNING: SSE transport exposes API operations over HTTP")
            logger.warning("Do not use in production without proper security measures")
            
            # Run with SSE transport
            run_with_sse(server, args.host, args.port, args.reload)
        else:
            # Run with STDIO transport (default)
            logger.info("Using default STDIO transport")
            run_with_stdio(server)
        
        return 0
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        logger.exception(e)  # Print full exception details for debugging
        return 1

if __name__ == "__main__":
    sys.exit(main())