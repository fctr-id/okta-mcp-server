"""
Core MCP server utilities for STDIO and HTTP transport.

This module provides basic MCP server startup functions used by main.py and run_server.py.
The actual MCP server implementation is in fastmcp_oauth_server.py for OAuth flows
and protocol_adapter.py for basic MCP functionality.
"""

import asyncio
import logging
from typing import Optional
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

def run_with_stdio(server: FastMCP) -> None:
    """
    Run a FastMCP server with STDIO transport.
    
    Args:
        server: FastMCP server instance to run
    """
    logger.info("Starting MCP server with STDIO transport")
    try:
        server.run(transport="stdio")
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

def run_with_http(server: FastMCP, host: str = "localhost", port: int = 3000) -> None:
    """
    Run a FastMCP server with HTTP transport.
    
    Warning: This runs MCP over HTTP without authentication. Use only for development.
    
    Args:
        server: FastMCP server instance to run
        host: Host to bind to
        port: Port to bind to
    """
    logger.warning("Running MCP server with HTTP transport WITHOUT authentication")
    logger.warning("This should only be used for development purposes")
    
    try:
        server.run(transport="http", host=host, port=port)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

async def run_with_sse(server: FastMCP, host: str = "localhost", port: int = 3000) -> None:
    """
    Run a FastMCP server with SSE transport.
    
    Args:
        server: FastMCP server instance to run  
        host: Host to bind to
        port: Port to bind to
    """
    logger.info(f"Starting MCP server with SSE transport on {host}:{port}")
    
    try:
        server.run(transport="sse", host=host, port=port)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
