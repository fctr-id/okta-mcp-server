"""Tool registry for dynamically discovering and managing MCP tools."""

import importlib
import logging
import inspect
import os
import pkgutil
from typing import Dict, Any, List, Optional, Callable, Set

from mcp.server import Server
from mcp.types import NotificationParams

from okta_mcp.utils.okta_client import OktaMcpClient

logger = logging.getLogger(__name__)

class ToolRegistry:
    """Registry for discovering and managing MCP tools."""
    
    _instance = None
    
    def __new__(cls):
        """Implement singleton pattern for the registry."""
        if cls._instance is None:
            cls._instance = super(ToolRegistry, cls).__new__(cls)
            cls._instance.tools = {}  # name -> tool info
            cls._instance.categories = {}  # category -> [tool_names]
            cls._instance.active_sessions = set()  # Track active client sessions
            cls._instance.server = None  # Reference to the server for notifications
        return cls._instance
    
    def __init__(self):
        """Initialize tool registry."""
        # Singleton instance already initialized in __new__
        pass
    
    def initialize_server(self, server: Server):
        """Set server reference for notifications."""
        self.server = server
        logger.info("Tool registry initialized with server reference")
    
    def register_session(self, session_id: str):
        """Register an active client session for notifications."""
        self.active_sessions.add(session_id)
        logger.debug(f"Registered client session: {session_id}")
    
    def unregister_session(self, session_id: str):
        """Unregister a client session when it disconnects."""
        if session_id in self.active_sessions:
            self.active_sessions.remove(session_id)
            logger.debug(f"Unregistered client session: {session_id}")
        
    def register_tool(self, tool_def: Dict[str, Any], handler: Callable, category: str = "general"):
        """
        Register a tool with its metadata.
        
        Args:
            tool_def: Tool definition dict with name, description, etc.
            handler: The function implementing the tool
            category: Category for organizing tools
        """
        tool_name = tool_def["name"]
        self.tools[tool_name] = {
            "definition": tool_def,
            "handler": handler,
            "category": category
        }
        
        # Add to category index
        if category not in self.categories:
            self.categories[category] = []
        self.categories[category].append(tool_name)
        
        logger.debug(f"Registered tool '{tool_name}' in category '{category}'")
        
    def register_tools_from_module(self, module, server: Server, client: OktaMcpClient):
        """
        Scan a module for tool definitions and register them.
        
        Args:
            module: The module to scan
            server: MCP server instance
            client: Okta client wrapper
        """
        # Look for register_*_tools functions
        for attr_name in dir(module):
            if attr_name.startswith('register_') and attr_name.endswith('_tools'):
                register_func = getattr(module, attr_name)
                if callable(register_func):
                    try:
                        # Check if function accepts registry parameter
                        sig = inspect.signature(register_func)
                        if 'registry' in sig.parameters:
                            register_func(server, client, registry=self)
                        else:
                            # Call without registry for backward compatibility
                            register_func(server, client)
                            
                        logger.info(f"Registered tools from {module.__name__}.{attr_name}")
                    except Exception as e:
                        logger.error(f"Error registering tools from {module.__name__}.{attr_name}: {str(e)}")
    
    def get_tools_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get all tools in a specific category.
        
        Args:
            category: Category name
            
        Returns:
            List of tool information dictionaries
        """
        return [self.tools[name] for name in self.categories.get(category, [])]
    
    def auto_discover_tools(self, server: Server, client: OktaMcpClient):
        """
        Auto-discover and register all tools from the tools package.
        
        Args:
            server: MCP server instance
            client: Okta client wrapper
        """
        # Store server reference for notifications
        self.server = server
        
        import okta_mcp.tools as tools_package
        
        # Scan the tools package for modules
        tools_path = os.path.dirname(tools_package.__file__)
        for _, name, is_pkg in pkgutil.iter_modules([tools_path]):
            if not is_pkg and name != 'tool_registry' and name != 'query_tools':  # Skip this module and query_tools
                try:
                    # Import the module
                    module = importlib.import_module(f"okta_mcp.tools.{name}")
                    # Register tools from it
                    self.register_tools_from_module(module, server, client)
                except ImportError as e:
                    logger.error(f"Error importing module okta_mcp.tools.{name}: {str(e)}")
        
        logger.info(f"Auto-discovered tools: {len(self.tools)} tools in {len(self.categories)} categories")
        
    def register_all_tools(self, server: Server, client: OktaMcpClient):
        """
        Register all tools with explicit imports.
        
        This is an alternative to auto_discover_tools when you want explicit control.
        
        Args:
            server: MCP server instance
            client: Okta client wrapper
        """
        # Store server reference for notifications
        self.server = server
        
        # Import the tool modules 
        try:
            from okta_mcp.tools import user_tools
            self.register_tools_from_module(user_tools, server, client)
        except ImportError:
            logger.warning("Could not import user_tools module")
            
        try:
            from okta_mcp.tools import group_tools
            self.register_tools_from_module(group_tools, server, client)
        except ImportError:
            logger.warning("Could not import group_tools module")   
            
        try:
            from okta_mcp.tools import apps_tools
            self.register_tools_from_module(apps_tools, server, client)
        except ImportError:
            logger.warning("Could not import apps_tools module")    
            
        try:
            from okta_mcp.tools import datetime_tools
            self.register_tools_from_module(datetime_tools, server, client)
        except ImportError:
            logger.warning("Could not import datetime_tools module")                               
            
        try:
            from okta_mcp.tools import log_events_tools
            self.register_tools_from_module(log_events_tools, server, client)
        except ImportError:
            logger.warning("Could not import log_events_tools module") 

        try:
            from okta_mcp.tools import policy_network_tools
            self.register_tools_from_module(policy_network_tools, server, client)
        except ImportError:
            logger.warning("Could not import polciy_network_tools module")                        
            
        # Additional modules can be added here as they're implemented
        # from okta_mcp.tools import group_tools
        # from okta_mcp.tools import app_tools
        
        #logger.info(f"Registered tools: {len(self.tools)} tools in {len(self.categories)} categories")
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tool."""
        return self.tools.get(tool_name)
    
    def list_all_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools."""
        return [
            {
                "name": name,
                "category": info["category"],
                "description": info["definition"].get("description", ""),
            }
            for name, info in self.tools.items()
        ]
    
    def list_categories(self) -> List[str]:
        """List all available tool categories."""
        return list(self.categories.keys())
        
    async def refresh_tools(self, server: Server, client: OktaMcpClient) -> bool:
        """
        Refresh all tool definitions and notify clients of changes.
        
        Args:
            server: MCP server instance
            client: Okta client wrapper
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Store current tools for comparison
            old_tools = set(self.tools.keys())
            
            # Clear existing tools and categories
            self.tools = {}
            self.categories = {}
            
            # Re-register all tools
            self.register_all_tools(server, client)
            
            # Notify all active client sessions
            await self.notify_tool_changes()
            
            # Log changes
            new_tools = set(self.tools.keys())
            added = new_tools - old_tools
            removed = old_tools - new_tools
            unchanged = old_tools & new_tools
            
            logger.info(f"Tools refreshed: {len(unchanged)} unchanged, {len(added)} added, {len(removed)} removed")
            if added:
                logger.info(f"Added tools: {', '.join(added)}")
            if removed:
                logger.info(f"Removed tools: {', '.join(removed)}")
                
            return True
        except Exception as e:
            logger.error(f"Error refreshing tools: {str(e)}")
            return False
    
    async def notify_tool_changes(self):
        """Notify all connected clients that tool definitions have changed."""
        if not self.server:
            logger.error("Cannot send notifications: server reference not set")
            return
            
        notification_count = 0
        for session_id in self.active_sessions:
            try:
                # Send notification using tools/list_changed as per MCP spec
                await self.server.send_notification(
                    session_id=session_id,
                    method="tools/list_changed",
                    params=NotificationParams()
                )
                notification_count += 1
            except Exception as e:
                logger.error(f"Failed to notify session {session_id}: {str(e)}")
                
        logger.info(f"Sent tool change notifications to {notification_count} clients")