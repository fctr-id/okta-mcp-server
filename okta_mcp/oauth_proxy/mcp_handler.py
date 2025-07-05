"""
MCP Handler for OAuth Proxy Server

Handles all MCP protocol endpoints with OAuth authentication.
"""

import logging
from typing import Optional, Dict, Any
from aiohttp import web

from .utils import create_401_response, audit_log
from okta_mcp.middleware.oauth_rbac_middleware import OAuthRBACMiddleware

logger = logging.getLogger("oauth_proxy.mcp")


class MCPHandler:
    """Handles MCP protocol endpoints with OAuth protection"""
    
    def __init__(self, mcp_server, auth_handler):
        self.mcp_server = mcp_server  # Direct FastMCP server instance
        self.auth_handler = auth_handler
        
        # Initialize RBAC middleware for OAuth proxy testing
        self.rbac_middleware = OAuthRBACMiddleware(auth_handler)
        logger.info("Initialized RBAC middleware for OAuth proxy testing (port 3001)")
        
    async def handle_post_root(self, request: web.Request) -> web.Response:
        """Handle POST requests to root endpoint (required for Claude Desktop/MCP CLI)"""
        user_info = await self.auth_handler.get_user_from_request(request)
        if not user_info:
            return create_401_response(request, "Authentication required for MCP requests")
            
        try:
            # This is likely an MCP protocol request from Claude Desktop or MCP CLI
            # Forward it to the underlying MCP proxy server
            logger.debug(f"POST / request from {user_info.get('email', 'unknown')} - forwarding to MCP server")
            
            # Get the request body
            request_data = await request.json()
            
            # Add user context to the request for audit/security
            if isinstance(request_data, dict):
                request_data["_oauth_context"] = {
                    "user_id": user_info.get("user_id"),
                    "email": user_info.get("email"),
                    "scopes": user_info.get("scopes", [])
                }
            
            # Forward to the MCP proxy server
            # Note: This is a simplified implementation - a full implementation would
            # need to handle the complete MCP protocol specification
            
            return web.json_response({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {}
                    },
                    "serverInfo": {
                        "name": "Okta MCP OAuth Proxy",
                        "version": "1.0.0"
                    }
                },
                "id": request_data.get("id") if isinstance(request_data, dict) else None
            })
            
        except Exception as e:
            logger.error(f"POST / request failed: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                },
                "id": None
            }, status=500)

    async def protected_mcp_tools(self, request: web.Request) -> web.Response:
        """List MCP tools (OAuth protected with RBAC filtering for testing)"""
        user_info = await self.auth_handler.get_user_from_request(request)
        if not user_info:
            return create_401_response(request, "Authentication required to access MCP tools")
            
        try:
            # Get tools from direct FastMCP server
            tools = await self.mcp_server.get_tools()
            tools_data = []
            
            # Convert tools to a serializable format
            for tool_name, tool in tools.items():
                if hasattr(tool, 'model_dump'):
                    tools_data.append(tool.model_dump())
                elif hasattr(tool, 'to_dict'):
                    tools_data.append(tool.to_dict())
                else:
                    # Basic tool info
                    tools_data.append({
                        "name": tool_name,
                        "description": getattr(tool, 'description', f"Tool: {tool_name}")
                    })
            
            # Apply RBAC filtering to tools list
            user_role = user_info.get('role')
            filtered_tools = self.rbac_middleware.filter_tools_by_role(tools_data, user_role)
            
            audit_log("mcp_tools_accessed", user_id=user_info.get("user_id"), details={
                "total_tools": len(tools_data),
                "filtered_tools": len(filtered_tools),
                "user_role": user_role,
                "email": user_info.get("email")
            })
            
            return web.json_response({
                "tools": filtered_tools,
                "user": user_info.get("email"),
                "role": user_role,
                "total_available": len(tools_data),
                "accessible_count": len(filtered_tools)
            })
            
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            audit_log("mcp_tools_error", user_id=user_info.get("user_id"), details={"error": str(e)})
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_call(self, request: web.Request) -> web.Response:
        """Call MCP tool (OAuth protected with RBAC validation for testing)"""
        user_info = await self.auth_handler.get_user_from_request(request)
        if not user_info:
            return create_401_response(request, "Authentication required to call MCP tools")
            
        try:
            data = await request.json()
            tool_name = data.get("name")
            arguments = data.get("arguments", {})
            
            if not tool_name:
                return web.json_response({"error": "Tool name required"}, status=400)
                
            # Validate tool execution permission using RBAC
            user_role = user_info.get('role')
            if not self.rbac_middleware.can_execute_tool(tool_name, user_role):
                audit_log("mcp_tool_access_denied", user_id=user_info.get("user_id"), details={
                    "tool_name": tool_name,
                    "user_role": user_role,
                    "email": user_info.get("email"),
                    "reason": "Insufficient role permissions"
                })
                return web.json_response({
                    "error": f"Access denied: role '{user_role}' insufficient for tool '{tool_name}'",
                    "user_role": user_role,
                    "tool": tool_name
                }, status=403)
                
            # Add user context to arguments for audit and authorization
            arguments["_oauth_user"] = user_info
            
            # Call tool via FastMCP server
            result = await self.mcp_server.call_tool(tool_name, arguments)
            
            audit_log("mcp_tool_called", user_id=user_info.get("user_id"), details={
                "tool_name": tool_name,
                "user_role": user_role,
                "email": user_info.get("email"),
                "virtual_client_id": user_info.get("virtual_client_id")
            })
            
            logger.debug(f"Tool '{tool_name}' called by {user_info.get('email', 'unknown')} with role '{user_role}'")
            
            return web.json_response({
                "result": result,
                "user": user_info.get("email"),
                "role": user_role,
                "tool": tool_name
            })
            
        except Exception as e:
            logger.error(f"Failed to call tool: {e}")
            audit_log("mcp_tool_call_error", user_id=user_info.get("user_id"), details={
                "error": str(e),
                "tool_name": data.get("name") if 'data' in locals() else None
            })
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_resources(self, request: web.Request) -> web.Response:
        """List MCP resources (OAuth protected)"""
        user_info = await self.auth_handler.get_user_from_request(request)
        if not user_info:
            return create_401_response(request, "Authentication required to access MCP resources")
            
        try:
            # Get resources from FastMCP proxy
            resources = await self.mcp_proxy.list_resources()
            resources_data = [res.model_dump() if hasattr(res, 'model_dump') else {"uri": str(res)} for res in resources]
            
            audit_log("mcp_resources_accessed", user_id=user_info.get("user_id"), details={
                "resource_count": len(resources_data),
                "email": user_info.get("email")
            })
            
            return web.json_response({
                "resources": resources_data,
                "user": user_info.get("email"),
                "count": len(resources_data)
            })
            
        except Exception as e:
            logger.error(f"Failed to list resources: {e}")
            audit_log("mcp_resources_error", user_id=user_info.get("user_id"), details={"error": str(e)})
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_read_resource(self, request: web.Request) -> web.Response:
        """Read MCP resource (OAuth protected)"""
        user_info = await self.auth_handler.get_user_from_request(request)
        if not user_info:
            return create_401_response(request, "Authentication required to read MCP resources")
            
        try:
            data = await request.json()
            uri = data.get("uri")
            
            if not uri:
                return web.json_response({"error": "Resource URI required"}, status=400)
                
            # Read resource via FastMCP proxy
            resource_content = await self.mcp_proxy.read_resource(uri)
            
            audit_log("mcp_resource_read", user_id=user_info.get("user_id"), details={
                "uri": uri,
                "email": user_info.get("email")
            })
            
            return web.json_response({
                "content": resource_content,
                "user": user_info.get("email"),
                "uri": uri
            })
            
        except Exception as e:
            logger.error(f"Failed to read resource: {e}")
            audit_log("mcp_resource_read_error", user_id=user_info.get("user_id"), details={
                "error": str(e),
                "uri": data.get("uri") if 'data' in locals() else None
            })
            return web.json_response({"error": str(e)}, status=500)
            
    async def protected_mcp_prompts(self, request: web.Request) -> web.Response:
        """List MCP prompts (OAuth protected)"""
        user_info = await self.auth_handler.get_user_from_request(request)
        if not user_info:
            return create_401_response(request, "Authentication required to access MCP prompts")
            
        try:
            # Get prompts from FastMCP proxy
            prompts = await self.mcp_proxy.list_prompts()
            prompts_data = [prompt.model_dump() if hasattr(prompt, 'model_dump') else {"name": str(prompt)} for prompt in prompts]
            
            audit_log("mcp_prompts_accessed", user_id=user_info.get("user_id"), details={
                "prompt_count": len(prompts_data),
                "email": user_info.get("email")
            })
            
            return web.json_response({
                "prompts": prompts_data,  
                "user": user_info.get("email"),
                "count": len(prompts_data)
            })
            
        except Exception as e:
            logger.error(f"Failed to list prompts: {e}")
            audit_log("mcp_prompts_error", user_id=user_info.get("user_id"), details={"error": str(e)})
            return web.json_response({"error": str(e)}, status=500)

    # Non-authenticated MCP endpoints (new for dual endpoint support)
    
    async def public_mcp_tools(self, request: web.Request) -> web.Response:
        """List MCP tools (no authentication required)"""
        try:
            # Get tools from FastMCP proxy
            tools = await self.mcp_proxy.list_tools()
            tools_data = [tool.model_dump() if hasattr(tool, 'model_dump') else {"name": str(tool)} for tool in tools]
            
            audit_log("mcp_tools_public_access", details={
                "tool_count": len(tools_data),
                "ip": request.remote
            })
            
            return web.json_response({
                "tools": tools_data,
                "count": len(tools_data),
                "auth_required": False
            })
            
        except Exception as e:
            logger.error(f"Failed to list tools (public): {e}")
            return web.json_response({"error": str(e)}, status=500)
            
    async def public_mcp_call(self, request: web.Request) -> web.Response:
        """Call MCP tool (no authentication required)"""
        try:
            data = await request.json()
            tool_name = data.get("name")
            arguments = data.get("arguments", {})
            
            if not tool_name:
                return web.json_response({"error": "Tool name required"}, status=400)
                
            # Add public access context
            arguments["_public_access"] = True
            arguments["_client_ip"] = request.remote
            
            # Call tool via FastMCP proxy
            result = await self.mcp_proxy.call_tool(tool_name, arguments)
            
            audit_log("mcp_tool_public_call", details={
                "tool_name": tool_name,
                "ip": request.remote
            })
            
            logger.debug(f"Tool '{tool_name}' called from {request.remote} (public access)")
            
            return web.json_response({
                "result": result,
                "tool": tool_name,
                "auth_required": False
            })
            
        except Exception as e:
            logger.error(f"Failed to call tool (public): {e}")
            return web.json_response({"error": str(e)}, status=500)
            
    async def public_mcp_resources(self, request: web.Request) -> web.Response:
        """List MCP resources (no authentication required)"""
        try:
            # Get resources from FastMCP proxy
            resources = await self.mcp_proxy.list_resources()
            resources_data = [res.model_dump() if hasattr(res, 'model_dump') else {"uri": str(res)} for res in resources]
            
            audit_log("mcp_resources_public_access", details={
                "resource_count": len(resources_data),
                "ip": request.remote
            })
            
            return web.json_response({
                "resources": resources_data,
                "count": len(resources_data),
                "auth_required": False
            })
            
        except Exception as e:
            logger.error(f"Failed to list resources (public): {e}")
            return web.json_response({"error": str(e)}, status=500)


