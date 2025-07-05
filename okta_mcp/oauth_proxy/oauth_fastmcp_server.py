"""
OAuth-Aware FastMCP Server

This module creates a new FastMCP server that:
1. Reuses all tool registration logic from the main server (port 3000)
2. Adds OAuth authentication and RBAC filtering middleware
3. Presents proper auth-required headers for unauthenticated requests
4. Provides full MCP protocol support with filtered tools for authenticated users
5. Serves at /oauth_mcp endpoint on port 3001

This is the core implementation that provides MCP protocol compliance
while enforcing OAuth authentication and role-based access control.
"""

import asyncio
import logging
import os
import sys
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext, ListToolsResult
from aiohttp import web, WSMsgType

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

from okta_mcp.auth.oauth_provider import OAuthConfig
from okta_mcp.oauth_proxy.auth_handler import AuthHandler
from okta_mcp.oauth_proxy.utils import create_401_response, audit_log
from okta_mcp.middleware.oauth_rbac_middleware import OAuthRBACMiddleware

logger = logging.getLogger("oauth_fastmcp")


class OAuthFastMCPMiddleware(Middleware):
    """
    FastMCP middleware that handles OAuth authentication and RBAC filtering.
    
    This middleware:
    - Checks for valid OAuth session/user context
    - Returns auth-required responses for unauthenticated requests
    - Filters available tools based on user role (RBAC)
    - Allows full MCP protocol operations for authorized users
    """
    
    def __init__(self, auth_handler: AuthHandler, rbac_middleware: OAuthRBACMiddleware):
        super().__init__()
        self.auth_handler = auth_handler
        self.rbac_middleware = rbac_middleware
        self.server_instance = None  # Will be set by the server
        logger.info("Initialized OAuth FastMCP middleware with RBAC filtering")
    
    def _get_current_user_info(self):
        """Get current user info from the server instance"""
        if self.server_instance:
            return getattr(self.server_instance, 'current_user_info', None)
        return None
    
    async def on_list_tools(self, context: MiddlewareContext, call_next):
        """Filter tools list based on user role"""
        try:
            # Get the original tools list
            result = await call_next(context)
            
            # Check for user info
            user_info = self._get_current_user_info()
            if not user_info:
                logger.debug("No OAuth user context - returning empty tools list")
                # Return empty tools list for unauthenticated requests
                return ListToolsResult(tools={})
            
            user_role = user_info.get('role')
            if not user_role:
                logger.debug("No user role found - returning empty tools list")
                return ListToolsResult(tools={})
            
            # Filter tools based on role
            filtered_tools = {}
            for name, tool in result.tools.items():
                # Convert tool to simple dict for RBAC check
                tool_dict = {"name": name, "description": getattr(tool, 'description', '')}
                filtered_list = self.rbac_middleware.filter_tools_by_role([tool_dict], user_role)
                
                if filtered_list:  # Tool is allowed for this role
                    filtered_tools[name] = tool
            
            audit_log("mcp_tools_filtered", 
                     user_id=user_info.get("user_id"),
                     details={
                         "total_tools": len(result.tools),
                         "filtered_tools": len(filtered_tools),
                         "user_role": user_role
                     })
            
            logger.debug(f"Filtered tools for role {user_role}: {len(result.tools)} -> {len(filtered_tools)}")
            return ListToolsResult(tools=filtered_tools)
            
        except Exception as e:
            logger.error(f"Error in tools filtering middleware: {e}")
            # Return empty list on error for security
            return ListToolsResult(tools={})
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Validate tool execution permissions"""
        try:
            # Check for user info
            user_info = self._get_current_user_info()
            if not user_info:
                logger.debug("No OAuth user context - denying tool execution")
                from mcp import McpError
                from mcp.types import ErrorData
                raise McpError(ErrorData(
                    code=-32001,
                    message="Authentication required for tool execution"
                ))
            
            user_role = user_info.get('role')
            tool_name = context.message.name
            
            # Check if user can execute this tool
            if not self.rbac_middleware.can_execute_tool(tool_name, user_role):
                audit_log("mcp_tool_access_denied", 
                         user_id=user_info.get("user_id"),
                         details={
                             "tool_name": tool_name,
                             "user_role": user_role,
                             "reason": "Insufficient role permissions"
                         })
                
                raise McpError(ErrorData(
                    code=-32002,
                    message=f"Access denied: role '{user_role}' insufficient for tool '{tool_name}'"
                ))
            
            # User is authorized, continue with execution
            audit_log("mcp_tool_authorized", 
                     user_id=user_info.get("user_id"),
                     details={
                         "tool_name": tool_name,
                         "user_role": user_role
                     })
            
            return await call_next(context)
            
        except Exception as e:
            if isinstance(e, McpError):
                raise  # Re-raise MCP errors as-is
            logger.error(f"Error in tool execution middleware: {e}")
            from mcp import McpError
            from mcp.types import ErrorData
            raise McpError(ErrorData(
                code=-32603,
                message="Internal error during tool authorization"
            ))


class OAuthAwareFastMCPServer:
    """
    OAuth-aware FastMCP server that provides full MCP protocol support
    with OAuth authentication and RBAC filtering.
    
    This server:
    - Reuses all tool registration from the main server
    - Adds OAuth authentication middleware
    - Filters tools and validates permissions based on user role
    - Uses a simple user context injection mechanism
    """
    
    def __init__(self, auth_handler: AuthHandler):
        self.auth_handler = auth_handler
        self.rbac_middleware = OAuthRBACMiddleware(auth_handler)
        self.current_user_info = None  # Simple storage for current request user
        
        # Create FastMCP server
        self.server = FastMCP("OktaOAuthMCPServer")
        
        # Add OAuth middleware
        self.oauth_middleware = OAuthFastMCPMiddleware(auth_handler, self.rbac_middleware)
        # Give middleware access to the server instance for user context
        self.oauth_middleware.server_instance = self
        self.server.add_middleware(self.oauth_middleware)
        
        # Register all tools from the main server
        self._register_all_tools()
        
        logger.info("Initialized OAuth-aware FastMCP server with RBAC filtering")
    
    def _register_all_tools(self):
        """
        Register all tools from the main server by importing and calling
        the tool registration functions.
        """
        try:
            # Import all tool modules and register their tools
            from okta_mcp.tools.user_tools import register_user_tools
            from okta_mcp.tools.group_tools import register_group_tools
            from okta_mcp.tools.apps_tools import register_apps_tools
            from okta_mcp.tools.log_events_tools import register_log_events_tools
            from okta_mcp.tools.policy_network_tools import register_policy_tools
            from okta_mcp.tools.datetime_tools import register_datetime_tools
            
            # Create an Okta client for the tools
            # Note: This client will use environment variables for auth
            # The actual OAuth user context will be passed via tool arguments
            from okta_mcp.utils.okta_client import OktaMcpClient, create_okta_client
            import os
            
            # Create the Okta SDK client first
            org_url = os.getenv('OKTA_CLIENT_ORGURL')
            api_token = os.getenv('OKTA_API_TOKEN')
            okta_sdk_client = create_okta_client(org_url, api_token)
            
            # Now create the MCP wrapper with the SDK client
            okta_client = OktaMcpClient(client=okta_sdk_client)
            
            # Register all tools with this server instance
            register_user_tools(self.server, okta_client)
            register_group_tools(self.server, okta_client)
            register_apps_tools(self.server, okta_client)
            register_log_events_tools(self.server, okta_client)
            register_policy_tools(self.server, okta_client)
            register_datetime_tools(self.server, okta_client)
            
            logger.info("Successfully registered all tools from main server")
            
        except Exception as e:
            logger.error(f"Failed to register tools: {e}")
            raise
    
    async def get_server(self):
        """Get the underlying FastMCP server instance"""
        return self.server
    
    def run_server(self, host="localhost", port=3001):
        """Run the OAuth-aware FastMCP server using FastMCP's built-in HTTP transport."""
        try:
            logger.info(f"Starting OAuth-aware FastMCP server on {host}:{port}")
            
            # Use FastMCP's built-in HTTP transport with middleware
            # This will automatically handle all MCP protocol details
            self.server.run(
                transport="streamable-http",
                host=host,
                port=port
            )
            
        except Exception as e:
            logger.error(f"Error running OAuth FastMCP server: {e}")
            raise


async def create_oauth_fastmcp_server() -> OAuthAwareFastMCPServer:
    """
    Factory function to create and configure the OAuth-aware FastMCP server.
    
    Returns:
        OAuthAwareFastMCPServer: Configured server instance ready to handle requests
    """
    try:
        # Create OAuth configuration and auth handler
        config = OAuthConfig.from_environment()
        auth_handler = AuthHandler(config)
        
        # Create and return the OAuth-aware FastMCP server
        server = OAuthAwareFastMCPServer(auth_handler)
        
        logger.info("Created OAuth-aware FastMCP server successfully")
        return server
        
    except Exception as e:
        logger.error(f"Failed to create OAuth FastMCP server: {e}")
        raise


# Export the main components
__all__ = [
    'OAuthAwareFastMCPServer',
    'OAuthFastMCPMiddleware', 
    'create_oauth_fastmcp_server'
]
