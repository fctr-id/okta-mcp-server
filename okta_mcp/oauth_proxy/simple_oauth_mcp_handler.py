"""
Simple OAuth-protected MCP protocol handler for the proxy server.

This module provides a direct MCP protocol handler that integrates with the OAuth proxy
server, handling MCP requests with OAuth authentication and RBAC filtering.
"""

import json
import logging
import os
from typing import Dict, Any, Optional
from aiohttp import web
from okta_mcp.oauth_proxy.auth_handler import AuthHandler
from okta_mcp.middleware.authorization import OktaAuthorizationMiddleware

logger = logging.getLogger("oauth_mcp_handler")

def create_401_response(request: web.Request, message: str) -> web.Response:
    """Create a proper 401 response with OAuth discovery metadata."""
    return web.Response(
        status=401,
        text=json.dumps({
            "jsonrpc": "2.0",
            "error": {
                "code": -32001,
                "message": message,
                "data": {
                    "auth_required": True,
                    "oauth_discovery": "/.well-known/oauth-authorization-server"
                }
            },
            "id": None
        }),
        content_type='application/json',
        headers={
            'WWW-Authenticate': 'Bearer realm="Okta MCP Server", scope="okta.users.read okta.groups.read"',
            'Cache-Control': 'no-store'
        }
    )

class OAuthMCPHandler:
    """
    Simple MCP protocol handler with OAuth authentication and RBAC filtering.
    
    This handler provides the core MCP protocol operations (initialize, tools/list, tools/call)
    with OAuth authentication and role-based access control, without the complexity of 
    integrating with FastMCP's internal HTTP transport.
    """
    
    def __init__(self, auth_handler: AuthHandler):
        self.auth_handler = auth_handler
        self.rbac_middleware = OktaAuthorizationMiddleware()
        
        # Tool registry - will be populated asynchronously
        self.tools = {}
        self.okta_client = None
        
        # Load RBAC configuration
        self.rbac_config = self._load_rbac_config()
        
        logger.info("Initialized OAuth MCP handler with RBAC filtering")
    
    def _load_rbac_config(self) -> Dict[str, Any]:
        """Load RBAC configuration from rbac_config.json"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'auth', 'rbac_config.json')
            config_path = os.path.abspath(config_path)
            
            with open(config_path, 'r') as f:
                config = json.load(f)
                logger.info(f"Loaded RBAC configuration from {config_path}")
                return config
        except Exception as e:
            logger.error(f"Failed to load RBAC config: {e}")
            # Fallback to basic configuration
            return {
                "roles": {
                    "viewer": {"level": 1},
                    "admin": {"level": 2}, 
                    "super-admin": {"level": 5}
                },
                "tools": {}
            }
    
    async def _initialize_tools_async(self):
        """Initialize the tool registry with all Okta tools (async version)."""
        try:
            # Create Okta client
            from okta_mcp.utils.okta_client import OktaMcpClient, create_okta_client
            import os
            
            org_url = os.getenv('OKTA_CLIENT_ORGURL')
            api_token = os.getenv('OKTA_API_TOKEN')
            okta_sdk_client = create_okta_client(org_url, api_token)
            okta_client = OktaMcpClient(client=okta_sdk_client)
            
            # Create a temporary FastMCP server to collect tool registrations
            from fastmcp import FastMCP
            temp_server = FastMCP("temp")
            
            # Register all tools using the same functions as main server
            from okta_mcp.tools.user_tools import register_user_tools
            from okta_mcp.tools.group_tools import register_group_tools  
            from okta_mcp.tools.apps_tools import register_apps_tools
            from okta_mcp.tools.log_events_tools import register_log_events_tools
            from okta_mcp.tools.policy_network_tools import register_policy_tools
            from okta_mcp.tools.datetime_tools import register_datetime_tools
            
            register_user_tools(temp_server, okta_client)
            register_group_tools(temp_server, okta_client)
            register_apps_tools(temp_server, okta_client)
            register_log_events_tools(temp_server, okta_client)
            register_policy_tools(temp_server, okta_client)
            register_datetime_tools(temp_server, okta_client)
            
            # Extract the registered tools from the temp server (async)
            if hasattr(temp_server, 'get_tools'):
                tools_dict = await temp_server.get_tools()
                self.tools = tools_dict
                logger.info(f"Loaded {len(self.tools)} tools using get_tools() method")
            else:
                logger.warning("Could not find get_tools method")
                self.tools = {}
            
            self.okta_client = okta_client
            
        except Exception as e:
            logger.error(f"Failed to initialize tools: {e}")
            self.tools = {}
    
    def _initialize_tools(self):
        """Initialize the tool registry with all Okta tools."""
        # This is now a no-op since we do async initialization
        pass
    
    async def handle_mcp_request(self, request: web.Request) -> web.Response:
        """Handle MCP protocol requests with OAuth authentication."""
        try:
            # Check authentication first
            user_info = await self.auth_handler.get_user_from_request(request)
            
            if not user_info:
                logger.debug("Unauthenticated MCP request")
                return create_401_response(request, "Authentication required for MCP requests")
            
            # Debug: Log user info to understand what we're getting
            logger.debug(f"Authenticated user info: {user_info}")
            logger.debug(f"User info keys: {list(user_info.keys())}")
            if 'role' in user_info:
                logger.debug(f"Role found in user_info: {user_info['role']}")
            else:
                logger.warning("No 'role' key found in user_info!")
            
            # Parse the MCP request
            try:
                data = await request.json()
            except Exception as e:
                return web.json_response({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error",
                        "data": str(e)
                    },
                    "id": None
                })
            
            # Handle MCP methods
            method = data.get('method')
            params = data.get('params', {})
            request_id = data.get('id')
            
            if method == 'initialize':
                return await self._handle_initialize(request_id)
            elif method == 'tools/list':
                return await self._handle_tools_list(request_id, user_info)
            elif method == 'tools/call':
                return await self._handle_tools_call(request_id, params, user_info)
            else:
                return web.json_response({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    },
                    "id": request_id
                })
                
        except Exception as e:
            logger.error(f"Error handling MCP request: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                },
                "id": None
            }, status=500)
    
    async def _handle_initialize(self, request_id) -> web.Response:
        """Handle MCP initialize request."""
        return web.json_response({
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": "Okta OAuth MCP Server",
                    "version": "1.0.0"
                }
            },
            "id": request_id
        })
    
    async def _handle_tools_list(self, request_id, user_info: Dict[str, Any]) -> web.Response:
        """Handle tools/list request with RBAC filtering."""
        try:
            # Debug: Log the full user_info to see what's available
            logger.debug(f"User info for tools/list: {user_info}")
            
            # Try multiple ways to get the role
            user_role = (
                user_info.get('role') or 
                user_info.get('rbac_role') or 
                user_info.get('okta_role') or 
                user_info.get('assigned_role') or
                'viewer'  # fallback
            )
            
            logger.debug(f"Extracted user role: '{user_role}' from user_info keys: {list(user_info.keys())}")
            
            # Convert tools to MCP format and apply RBAC filtering
            tools_list = []
            for name, tool_func in self.tools.items():
                # Get description, ensuring it's never None
                description = getattr(tool_func, '__doc__', None)
                if not description:
                    description = f"Okta tool: {name}"
                
                # Create basic tool info
                tool_info = {
                    "name": name,
                    "description": description,
                    "inputSchema": {
                        "type": "object", 
                        "properties": {},
                        "required": []
                    }
                }
                
                # Check if user has access to this tool based on role
                if self._check_tool_access(name, user_role):
                    tools_list.append(tool_info)
            
            logger.info(f"Returning {len(tools_list)} tools for role '{user_role}' (out of {len(self.tools)} total tools)")
            
            return web.json_response({
                "jsonrpc": "2.0",
                "result": {
                    "tools": tools_list
                },
                "id": request_id
            })
            
        except Exception as e:
            logger.error(f"Error listing tools: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Error listing tools",
                    "data": str(e)
                },
                "id": request_id
            })
    
    async def _handle_tools_call(self, request_id, params: Dict[str, Any], user_info: Dict[str, Any]) -> web.Response:
        """Handle tools/call request with RBAC checking."""
        try:
            tool_name = params.get('name')
            arguments = params.get('arguments', {})
            user_role = (
                user_info.get('role') or 
                user_info.get('rbac_role') or 
                user_info.get('okta_role') or 
                user_info.get('assigned_role') or
                'viewer'  # fallback
            )
            
            if not tool_name:
                return web.json_response({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32602,
                        "message": "Missing tool name"
                    },
                    "id": request_id
                })
            
            # Check if user has access to this tool
            if not self._check_tool_access(tool_name, user_role):
                return web.json_response({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": f"Access denied to tool: {tool_name}"
                    },
                    "id": request_id
                })
            
            # Get the tool function
            tool_func = self.tools.get(tool_name)
            if not tool_func:
                return web.json_response({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": f"Tool not found: {tool_name}"
                    },
                    "id": request_id
                })
            
            # Call the tool
            try:
                result = await tool_func(**arguments)
                
                return web.json_response({
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": str(result)
                            }
                        ]
                    },
                    "id": request_id
                })
                
            except Exception as e:
                logger.error(f"Error calling tool {tool_name}: {e}")
                return web.json_response({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": f"Tool execution failed: {str(e)}"
                    },
                    "id": request_id
                })
                
        except Exception as e:
            logger.error(f"Error in tools/call: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error in tools/call",
                    "data": str(e)
                },
                "id": request_id
            })
    
    def _check_tool_access(self, tool_name: str, user_role: str) -> bool:
        """Check if user role has access to the specified tool using RBAC config."""
        try:
            # Get user role level
            role_level = self.rbac_config.get("roles", {}).get(user_role, {}).get("level", 0)
            
            if role_level == 0:
                logger.warning(f"Unknown role '{user_role}', denying access")
                return False
            
            # Map actual tool names to config tool names (based on actual registered tools)
            tool_mapping = {
                # User tools
                "list_okta_users": "list_okta_users",
                "get_okta_user": "get_okta_user", 
                "list_okta_user_groups": "list_okta_user_groups",
                "list_okta_user_applications": "list_okta_user_applications",
                "list_okta_user_factors": "list_okta_user_factors",
                
                # Group tools
                "list_okta_groups": "list_okta_groups",
                "get_okta_group": "get_okta_group",
                "list_okta_group_users": "list_okta_group_users",
                
                # App tools  
                "list_okta_applications": "list_okta_applications",
                "get_okta_application": "get_okta_application",
                "list_okta_application_users": "list_okta_application_users",
                "list_okta_application_groups": "list_okta_application_groups",
                
                # Policy tools
                "list_okta_policy_rules": "list_okta_policy_rules",
                "get_okta_policy_rule": "get_okta_policy_rule",
                "list_okta_network_zones": "list_okta_network_zones",
                
                # Log/Event tools
                "get_okta_event_logs": "get_okta_event_logs",
                
                # DateTime tools
                "get_current_time": "get_current_time",
                "parse_relative_time": "parse_relative_time"
            }
            
            # Get the config tool name
            config_tool_name = tool_mapping.get(tool_name)
            if not config_tool_name:
                logger.warning(f"Unknown tool '{tool_name}', using fallback check")
                # Fallback: super-admin gets everything, others get basic tools only
                if user_role == 'super-admin':
                    return True
                elif tool_name in ['get_current_time', 'parse_relative_time']:
                    return True
                else:
                    return False
            
            # Check if user level meets tool requirement
            required_level = self.rbac_config.get("tools", {}).get(config_tool_name, {}).get("min_level", 999)
            
            has_access = role_level >= required_level
            logger.debug(f"Tool '{tool_name}' (config: '{config_tool_name}') requires level {required_level}, user '{user_role}' has level {role_level}: {'GRANTED' if has_access else 'DENIED'}")
            
            return has_access
            
        except Exception as e:
            logger.error(f"Error checking tool access for '{tool_name}' and role '{user_role}': {e}")
            return False
