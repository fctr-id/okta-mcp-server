#!/usr/bin/env python3
"""
Manual OAuth Proxy Startup Script

Simple script to start the OAuth proxy server for manual testing.
Use this to test the compatibility layer with real MCP clients.
"""

import os
import sys
import logging
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_environment():
    """Setup environment for testing"""
    load_dotenv()
    
    # Check required variables
    required_vars = [
        "OKTA_CLIENT_ORGURL",
        "OKTA_API_TOKEN", 
        "OKTA_CLIENT_ID",
        "OKTA_CLIENT_SECRET"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        logger.error("Please copy .env.sample to .env and configure your Okta settings")
        return False
    
    # Set defaults for OAuth proxy
    os.environ.setdefault("OAUTH_REDIRECT_URI", "http://localhost:3001/oauth/callback")
    os.environ.setdefault("OAUTH_REQUIRE_HTTPS", "false")
    os.environ.setdefault("LOG_LEVEL", "INFO")
    
    logger.info("✅ Environment configured successfully")
    return True

def main():
    """Start the OAuth proxy server"""
    logger.info("🚀 Starting Okta MCP OAuth Proxy with Compatibility Layer")
    logger.info("=" * 60)
    
    if not setup_environment():
        return 1
    
    try:
        # Import and start the OAuth proxy server
        from okta_mcp.oauth_proxy.server import main as oauth_main
        
        # Set up command line arguments for the OAuth proxy
        sys.argv = [
            "server.py",
            "--backend", "./main.py",
            "--host", "localhost", 
            "--port", "3001"
        ]
        
        logger.info("🌐 OAuth Proxy URL: http://localhost:3001")
        logger.info("🔐 OAuth Login: http://localhost:3001/oauth/login")
        logger.info("📊 Health Check: http://localhost:3001/health")
        logger.info("🛠️ MCP Tools: http://localhost:3001/mcp/tools (requires auth)")
        logger.info("")
        logger.info("💡 The server includes automatic MCP protocol compatibility for:")
        logger.info("   - Claude Desktop (MCP 2025-03-26)")
        logger.info("   - VS Code & MCP Inspector (MCP 2025-06-18)")
        logger.info("")
        logger.info("🛑 Press Ctrl+C to stop the server")
        logger.info("=" * 60)
        
        # Start the OAuth proxy server
        oauth_main()
        
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
        return 0
    except Exception as e:
        logger.error(f"💥 Server failed to start: {e}")
        logger.exception("Full error:")
        return 1

if __name__ == "__main__":
    sys.exit(main())
