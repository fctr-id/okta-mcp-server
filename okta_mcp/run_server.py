#!/usr/bin/env python3
"""
Unified Okta MCP Server Runner

This script can run:
1. Main MCP server (STDIO transport) - for direct MCP client connections
2. OAuth proxy server (HTTP transport) - for web-based OAuth-protected access
3. Both servers concurrently

Usage:
    python -m okta_mcp.run_server                         # Run main MCP server (STDIO)
    python -m okta_mcp.run_server mcp-with-auth            # Run OAuth proxy server only
    python -m okta_mcp.run_server --both                  # Run both servers
    python -m okta_mcp.run_server --danger-mcp-no-auth    # Run main server with HTTP transport (no auth)
"""

import os
import sys
import asyncio
import logging
import argparse
import multiprocessing
from typing import Optional

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("okta_mcp.runner")


def run_main_server(transport: str = "stdio", host: str = "localhost", port: int = 3000):
    """Run the main MCP server"""
    try:
        from okta_mcp.compatibility.protocol_adapter import create_compatible_server
        
        logger.info(f"Starting main Okta MCP server with {transport} transport")
        server = create_compatible_server()
        
        if transport == "stdio":
            from okta_mcp.server import run_with_stdio
            run_with_stdio(server)
        elif transport == "http":
            from okta_mcp.server import run_with_http
            run_with_http(server, host, port)
        else:
            logger.error(f"Unsupported transport: {transport}")
            return 1
            
        return 0
        
    except Exception as e:
        logger.error(f"Error running main server: {e}")
        return 1


def run_oauth_server(host: str = "localhost", port: int = 3001):
    """Run the OAuth proxy server"""
    try:
        from okta_mcp.oauth_proxy.server import OAuthFastMCPProxy
        
        logger.info(f"Starting OAuth proxy server on {host}:{port}")
        proxy = OAuthFastMCPProxy()
        
        # Run the server
        asyncio.run(proxy.run(host=host, port=port))
        return 0
        
    except Exception as e:
        logger.error(f"Error running OAuth server: {e}")
        return 1


def run_main_server_process(transport: str, host: str, port: int):
    """Wrapper for main server in separate process"""
    return run_main_server(transport, host, port)


def run_oauth_server_process(host: str, port: int):
    """Wrapper for OAuth server in separate process"""
    return run_oauth_server(host, port)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Okta MCP Server Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                                   # Run main MCP server (STDIO)
    %(prog)s mcp-with-auth                      # Run OAuth proxy server only
    %(prog)s --both                            # Run both servers concurrently
    %(prog)s --danger-mcp-no-auth --port 3000  # Run main server with HTTP transport (no auth)
    %(prog)s mcp-with-auth --oauth-port 3001    # Run OAuth server on custom port
        """
    )
    
    # Server selection
    server_group = parser.add_mutually_exclusive_group()
    server_group.add_argument(
        "command", 
        nargs="?",
        choices=["mcp-with-auth"],
        help="mcp-with-auth: Run OAuth proxy server only (HTTP transport)"
    )
    server_group.add_argument(
        "--both", 
        action="store_true",
        help="Run both main and OAuth servers concurrently"
    )
    server_group.add_argument(
        "--danger-mcp-no-auth", 
        action="store_true",
        help="Run main server with HTTP transport (NO AUTHENTICATION - use only for testing)"
    )
    
    # Main server options
    parser.add_argument(
        "--host", 
        default="localhost",
        help="Host for HTTP transport (default: localhost)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=3000,
        help="Port for main server HTTP transport (default: 3000)"
    )
    
    # OAuth server options
    parser.add_argument(
        "--oauth-host", 
        default="localhost",
        help="Host for OAuth proxy server (default: localhost)"
    )
    parser.add_argument(
        "--oauth-port", 
        type=int, 
        default=3001,
        help="Port for OAuth proxy server (default: 3001)"
    )
    
    args = parser.parse_args()
    
    try:
        if args.command == "mcp-with-auth":
            # Run OAuth proxy server only
            logger.info("Running OAuth proxy server only")
            return run_oauth_server(args.oauth_host, args.oauth_port)
            
        elif args.both:
            # Run both servers concurrently using multiprocessing
            logger.info("Running both main and OAuth servers concurrently")
            
            # Start main server process (STDIO)
            main_process = multiprocessing.Process(
                target=run_main_server_process,
                args=("stdio", args.host, args.port)
            )
            
            # Start OAuth server process
            oauth_process = multiprocessing.Process(
                target=run_oauth_server_process,
                args=(args.oauth_host, args.oauth_port)
            )
            
            try:
                main_process.start()
                oauth_process.start()
                
                logger.info("Both servers started. Press Ctrl+C to stop.")
                
                # Wait for both processes
                main_process.join()
                oauth_process.join()
                
                return 0
                
            except KeyboardInterrupt:
                logger.info("Stopping both servers...")
                main_process.terminate()
                oauth_process.terminate()
                main_process.join()
                oauth_process.join()
                return 0
                
        elif args.danger_mcp_no_auth:
            # Run main server with HTTP transport (no authentication)
            logger.warning("Running main server with HTTP transport - NO AUTHENTICATION!")
            logger.warning("This is DANGEROUS and should only be used for testing!")
            logger.info("Running main server with HTTP transport")
            return run_main_server("http", args.host, args.port)
            
        else:
            # Default: run main server with STDIO transport
            logger.info("Running main server with STDIO transport")
            return run_main_server("stdio")
            
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
