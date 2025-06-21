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
                      help="Use Streamable HTTP transport (modern, recommended)")
    parser.add_argument("--sse", action="store_true", 
                      help="Use SSE transport (legacy, deprecated)")
    parser.add_argument("--stdio", action="store_true", 
                      help="Use STDIO transport (default)")
    parser.add_argument("--iunderstandtherisks", action="store_true",
                      help="Acknowledge security risks of using HTTP-based transports")
    
    # HTTP/SSE configuration
    parser.add_argument("--host", default="0.0.0.0", 
                      help="Host to bind to for HTTP transports (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=3000, 
                      help="Port to run on for HTTP transports (default: 3000)")
    parser.add_argument("--reload", action="store_true", 
                      help="Enable auto-reload for development (HTTP transports only)")
    
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
        # Add debug mode
        
    
    try:
        # Handle transport-specific setup BEFORE importing server module
        if args.http:
            # Check for risk acknowledgment
            if not args.iunderstandtherisks:
                logger.error("HTTP transport requires explicit risk acknowledgment")
                logger.error("Add --iunderstandtherisks flag to run with HTTP transport")
                return 1
            
            # Show security warning
            logger.warning("SECURITY WARNING: HTTP transport exposes API operations over network")
            logger.warning("Do not use in production without proper security measures")
            
            # CRITICAL: Set sys.argv BEFORE importing FastMCP modules
            original_argv = sys.argv.copy()
            sys.argv = [
                sys.argv[0],  # Keep original script name
                '--port', str(args.port),
                '--host', args.host,
                '--log-level', args.log_level
            ]
            
            logger.info(f"Modified sys.argv for FastMCP: {sys.argv}")
            
            try:
                # Import server module AFTER setting sys.argv
                from okta_mcp.server import create_server, run_with_http
                
                # Create server (FastMCP should read the modified sys.argv)
                server = create_server()
                
                # Run with Streamable HTTP transport
                logger.info("Starting with Streamable HTTP transport (recommended)")
                run_with_http(server, args.host, args.port)
                
            finally:
                # Restore original sys.argv
                sys.argv = original_argv
                
        elif args.sse:
            # Check for risk acknowledgment
            if not args.iunderstandtherisks:
                logger.error("SSE transport requires explicit risk acknowledgment")
                logger.error("Add --iunderstandtherisks flag to run with SSE transport")
                return 1
            
            # Show security warning and deprecation notice
            logger.warning("SECURITY WARNING: SSE transport exposes API operations over HTTP")
            logger.warning("DEPRECATION WARNING: SSE transport is deprecated, use --http instead")
            logger.warning("Do not use in production without proper security measures")
            
            # Import normally for SSE (doesn't need sys.argv modification)
            from okta_mcp.server import create_server, run_with_sse
            
            # Create and run server
            server = create_server()
            logger.info("Starting with SSE transport (deprecated)")
            run_with_sse(server, args.host, args.port, args.reload)
            
        else:
            # Import normally for STDIO
            from okta_mcp.server import create_server, run_with_stdio
            
            # Create and run server
            server = create_server()
            logger.info("Starting with STDIO transport (default, secure)")
            run_with_stdio(server)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        logger.exception(e)  # Print full exception details for debugging
        return 1

if __name__ == "__main__":
    sys.exit(main())