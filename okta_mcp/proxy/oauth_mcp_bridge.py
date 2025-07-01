"""
Hybrid OAuth-FastMCP Integration
Combines OAuth authentication server with FastMCP proxy functionality
"""

import os
import json
import asyncio
import logging
from typing import Optional, Dict, Any
from aiohttp import web, ClientSession
from fastmcp import FastMCP
from fastmcp.client import Client
from okta_mcp.auth.oauth_server import OktaOAuthServer

logger = logging.getLogger(__name__)

class OAuthMCPBridge:
    """
    Bridge between OAuth authentication and MCP proxy functionality
    Provides OAuth-protected MCP endpoints
    """
    
    def __init__(self, backend_server_path: str = "./main.py"):
        self.backend_server_path = backend_server_path
        self.oauth_server = OktaOAuthServer()
        self.mcp_client: Optional[Client] = None
        
        # Override OAuth server's MCP handler
        self._setup_mcp_integration()
    
    def _setup_mcp_integration(self):
        """Setup MCP integration with OAuth server"""
        # Add MCP-specific routes
        self.oauth_server.app.router.add_post("/mcp/call", self.mcp_call_tool)
        self.oauth_server.app.router.add_get("/mcp/tools", self.mcp_list_tools)
        self.oauth_server.app.router.add_get("/mcp/resources", self.mcp_list_resources)
        self.oauth_server.app.router.add_post("/mcp/resources/read", self.mcp_read_resource)
        
        # Replace the generic MCP handler
        async def authenticated_mcp_handler(request):
            """Handle all MCP requests with authentication"""
            user_info = self.oauth_server.get_user_from_request(request)
            if not user_info:
                return web.json_response({"error": "Authentication required"}, status=401)
            
            # Route to appropriate MCP handler based on path
            path = request.match_info.get("path", "")
            
            if path.startswith("call"):
                return await self.mcp_call_tool(request)
            elif path.startswith("tools"):
                return await self.mcp_list_tools(request)
            elif path.startswith("resources"):
                if request.method == "POST":
                    return await self.mcp_read_resource(request)
                else:
                    return await self.mcp_list_resources(request)
            else:
                return web.json_response({"error": "Unknown MCP endpoint"}, status=404)
        
        self.oauth_server.mcp_proxy_handler = authenticated_mcp_handler
    
    async def start_mcp_client(self):
        """Start MCP client connection to backend server"""
        try:
            self.mcp_client = Client(self.backend_server_path)
            await self.mcp_client.connect()
            logger.info(f"Connected to MCP backend: {self.backend_server_path}")
        except Exception as e:
            logger.error(f"Failed to connect to MCP backend: {e}")
            raise
    
    async def stop_mcp_client(self):
        """Stop MCP client connection"""
        if self.mcp_client:
            await self.mcp_client.disconnect()
            logger.info("Disconnected from MCP backend")
    
    async def mcp_call_tool(self, request: web.Request) -> web.Response:
        """Handle MCP tool calls with OAuth authentication"""
        try:
            # Check authentication
            user_info = self.oauth_server.get_user_from_request(request)
            if not user_info:
                return web.json_response({"error": "Authentication required"}, status=401)
            
            # Get request data
            if request.content_type == "application/json":
                data = await request.json()
            else:
                return web.json_response({"error": "Content-Type must be application/json"}, status=400)
            
            tool_name = data.get("name")
            parameters = data.get("parameters", {})
            
            if not tool_name:
                return web.json_response({"error": "Tool name required"}, status=400)
            
            # Add user context to parameters
            parameters["_oauth_user"] = user_info
            
            # Call tool via MCP client
            if not self.mcp_client:
                await self.start_mcp_client()
            
            result = await self.mcp_client.call_tool(tool_name, parameters)
            
            logger.info(f"Tool '{tool_name}' called by {user_info.get('email', 'unknown')}")
            
            return web.json_response({
                "result": result,
                "user": user_info.get("email")
            })
            
        except Exception as e:
            logger.error(f"MCP tool call failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def mcp_list_tools(self, request: web.Request) -> web.Response:
        """List available MCP tools"""
        try:
            # Check authentication
            user_info = self.oauth_server.get_user_from_request(request)
            if not user_info:
                return web.json_response({"error": "Authentication required"}, status=401)
            
            # Get tools from MCP client
            if not self.mcp_client:
                await self.start_mcp_client()
            
            tools = await self.mcp_client.list_tools()
            
            # Filter tools based on user permissions (basic example)
            filtered_tools = []
            user_scopes = user_info.get("scopes", [])
            
            for tool in tools:
                tool_dict = tool.model_dump() if hasattr(tool, 'model_dump') else {"name": str(tool)}
                
                # Basic scope-based filtering
                if "okta.users.read" in user_scopes or "admin" in user_info.get("roles", []):
                    filtered_tools.append(tool_dict)
                elif not tool_dict.get("name", "").startswith("admin_"):
                    filtered_tools.append(tool_dict)
            
            return web.json_response({
                "tools": filtered_tools,
                "user": user_info.get("email"),
                "scopes": user_scopes
            })
            
        except Exception as e:
            logger.error(f"MCP list tools failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def mcp_list_resources(self, request: web.Request) -> web.Response:
        """List available MCP resources"""
        try:
            # Check authentication
            user_info = self.oauth_server.get_user_from_request(request)
            if not user_info:
                return web.json_response({"error": "Authentication required"}, status=401)
            
            # Get resources from MCP client
            if not self.mcp_client:
                await self.start_mcp_client()
            
            resources = await self.mcp_client.list_resources()
            
            return web.json_response({
                "resources": [r.model_dump() if hasattr(r, 'model_dump') else {"uri": str(r)} for r in resources],
                "user": user_info.get("email")
            })
            
        except Exception as e:
            logger.error(f"MCP list resources failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def mcp_read_resource(self, request: web.Request) -> web.Response:
        """Read MCP resource"""
        try:
            # Check authentication
            user_info = self.oauth_server.get_user_from_request(request)
            if not user_info:
                return web.json_response({"error": "Authentication required"}, status=401)
            
            # Get request data
            data = await request.json()
            resource_uri = data.get("uri")
            
            if not resource_uri:
                return web.json_response({"error": "Resource URI required"}, status=400)
            
            # Read resource via MCP client
            if not self.mcp_client:
                await self.start_mcp_client()
            
            content = await self.mcp_client.read_resource(resource_uri)
            
            return web.json_response({
                "content": content,
                "user": user_info.get("email")
            })
            
        except Exception as e:
            logger.error(f"MCP read resource failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def start_server(self, host: str = "localhost", port: int = 3001):
        """Start the OAuth-MCP bridge server"""
        try:
            # Start MCP client connection
            await self.start_mcp_client()
            
            # Start OAuth server
            runner = await self.oauth_server.start_server(host, port)
            
            logger.info(f"OAuth-MCP bridge started on http://{host}:{port}")
            logger.info("Available endpoints:")
            logger.info("  - GET  /oauth/authorize - Start OAuth flow")
            logger.info("  - GET  /oauth/status    - Check auth status")
            logger.info("  - GET  /mcp/tools       - List MCP tools")
            logger.info("  - POST /mcp/call        - Call MCP tool")
            logger.info("  - GET  /mcp/resources   - List MCP resources")
            
            return runner
            
        except Exception as e:
            logger.error(f"Failed to start OAuth-MCP bridge: {e}")
            await self.stop_mcp_client()
            raise
    
    async def stop_server(self, runner):
        """Stop the OAuth-MCP bridge server"""
        await self.oauth_server.stop_server(runner)
        await self.stop_mcp_client()
        logger.info("OAuth-MCP bridge stopped")
