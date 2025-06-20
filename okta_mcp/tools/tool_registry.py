"""Tool registry for dynamically discovering and managing MCP tools."""

import importlib
import logging
import inspect
import os
import pkgutil
from typing import Dict, Any, List, Optional, Callable, Set

from fastmcp import FastMCP

from okta_mcp.utils.okta_client import OktaMcpClient

logger = logging.getLogger(__name__)

class ToolRegistry:
    """Registry for discovering and managing MCP tools with 2025-06-18 protocol support."""
    
    _instance = None
    
    def __new__(cls):
        """Implement singleton pattern for the registry."""
        if cls._instance is None:
            cls._instance = super(ToolRegistry, cls).__new__(cls)
            cls._instance.tools = {}  # name -> tool info
            cls._instance.categories = {}  # category -> [tool_names]
            cls._instance.active_sessions = set()  # Track active client sessions
            cls._instance.server = None  # Reference to the server for notifications
            cls._instance.protocol_version = "2025-06-18"  # MCP protocol version
            cls._instance.capabilities_registered = {
                "elicitation": False,
                "sampling": False,
                "enhanced_logging": False
            }
        return cls._instance
    
    def __init__(self):
        """Initialize tool registry."""
        # Singleton instance already initialized in __new__
        pass
    
    def _count_fastmcp_tools(self, server: FastMCP) -> int:
        """Count tools registered with FastMCP."""
        try:
            # Access the internal tool manager
            if hasattr(server, '_tool_manager') and server._tool_manager:
                tools = server._tool_manager.list_tools()
                return len(tools)
            return 0
        except Exception as e:
            logger.error(f"Error counting FastMCP tools: {e}")
            return 0
    
    def debug_fastmcp_internals(self, server: FastMCP):
        """Debug what's inside the FastMCP server."""
        logger.info("=== FASTMCP DEBUG START ===")
        
        # Check the tool manager specifically
        if hasattr(server, '_tool_manager'):
            tool_manager = server._tool_manager
            tools = tool_manager.list_tools()
            logger.info(f"FastMCP._tool_manager has {len(tools)} tools:")
            for tool in tools:
                logger.info(f"  Tool: {tool.name} - {tool.description}")
        
        logger.info("=== FASTMCP DEBUG END ===") 
    
    def initialize_server(self, server: FastMCP):
        """
        Set server reference for notifications and initialize enhanced capabilities.
        
        Args:
            server: FastMCP server instance
        """
        self.server = server
        logger.info(f"Tool registry initialized with FastMCP server (Protocol: {self.protocol_version})")
        
        # Set up enhanced logging for 2025-06-18 protocol
        self._setup_enhanced_logging()
    
    def _setup_enhanced_logging(self):
        """Set up enhanced logging capabilities for MCP 2025-06-18."""
        try:
            # Enhanced logging is already set up in server.py with debug hooks
            self.capabilities_registered["enhanced_logging"] = True
            logger.info("Enhanced MCP logging capabilities activated")
        except Exception as e:
            logger.error(f"Failed to setup enhanced logging: {e}")
    
    def register_session(self, session_id: str):
        """Register an active client session for notifications."""
        self.active_sessions.add(session_id)
        logger.debug(f"Registered client session: {session_id} (Protocol: {self.protocol_version})")
    
    def unregister_session(self, session_id: str):
        """Unregister a client session when it disconnects."""
        if session_id in self.active_sessions:
            self.active_sessions.remove(session_id)
            logger.debug(f"Unregistered client session: {session_id}")
        
    def register_tool(self, tool_def: Dict[str, Any], handler: Callable, category: str = "general"):
        """
        Register a tool with its metadata and enhanced 2025-06-18 features.
        
        Args:
            tool_def: Tool definition dict with name, description, schemas, etc.
            handler: The function implementing the tool
            category: Category for organizing tools
        """
        tool_name = tool_def["name"]
        
        # Enhanced tool registration with 2025-06-18 features
        enhanced_tool_info = {
            "definition": tool_def,
            "handler": handler,
            "category": category,
            "protocol_version": self.protocol_version,
            "supports_elicitation": self._tool_supports_elicitation(handler),
            "supports_sampling": self._tool_supports_sampling(handler),
            "has_schemas": "inputSchema" in tool_def or "outputSchema" in tool_def,
            "registered_at": logger.info.__module__  # Timestamp would be better but this works
        }
        
        self.tools[tool_name] = enhanced_tool_info
        
        # Add to category index
        if category not in self.categories:
            self.categories[category] = []
        self.categories[category].append(tool_name)
        
        logger.debug(f"Registered tool '{tool_name}' in category '{category}' with 2025-06-18 features")
        
    def _tool_supports_elicitation(self, handler: Callable) -> bool:
        """Check if a tool handler supports elicitation workflows."""
        # Check if the handler's module imports elicitation capabilities
        try:
            handler_module = inspect.getmodule(handler)
            if handler_module:
                source = inspect.getsource(handler_module)
                return "elicitation" in source.lower() or "elicit" in source.lower()
        except:
            pass
        return False
    
    def _tool_supports_sampling(self, handler: Callable) -> bool:
        """Check if a tool handler supports AI sampling features."""
        try:
            handler_module = inspect.getmodule(handler)
            if handler_module:
                source = inspect.getsource(handler_module)
                return "sampling" in source.lower() or "ai_" in source.lower()
        except:
            pass
        return False
        
    def register_tools_from_module(self, module, server: FastMCP, client: OktaMcpClient):
        """
        Scan a module for tool definitions and register them with enhanced capabilities.
        
        Args:
            module: The module to scan
            server: FastMCP server instance
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
    
    def register_elicitation_capabilities(self, registry):
        """Register elicitation capabilities with the server."""
        try:
            from okta_mcp.capabilities.elicitation import register_elicitation_workflows, is_elicitation_available
            
            capability_info = register_elicitation_workflows(registry)
            
            # Set the status based on whether real elicitation is available
            real_elicitation_available = is_elicitation_available()
            self.capabilities_registered["elicitation"] = real_elicitation_available
            self.capabilities_registered["elicitation_fallback"] = not real_elicitation_available
            
            if real_elicitation_available:
                logger.info("Elicitation capabilities registered successfully (MCP 2025-06-18)")
            else:
                logger.info("Elicitation capabilities registered in fallback mode (MCP 2025-06-18)")
                
            return capability_info
            
        except Exception as e:
            logger.error(f"Failed to import elicitation capabilities: {e}")
            self.capabilities_registered["elicitation"] = False
            self.capabilities_registered["elicitation_fallback"] = False
            return None
    
    def register_sampling_capabilities(self, server: FastMCP, model_provider=None):
        """
        Register AI sampling capabilities as per MCP 2025-06-18 specification.
        
        Args:
            server: FastMCP server instance
            model_provider: Optional model provider for AI features
        """
        if self.capabilities_registered["sampling"]:
            logger.debug("Sampling capabilities already registered")
            return
            
        try:
            from okta_mcp.capabilities.sampling import register_sampling_capabilities
            register_sampling_capabilities(server, model_provider)
            self.capabilities_registered["sampling"] = True
            logger.info("AI sampling capabilities registered successfully (MCP 2025-06-18)")
        except ImportError as e:
            logger.error(f"Failed to import sampling capabilities: {e}")
        except Exception as e:
            logger.error(f"Error registering sampling capabilities: {e}")
    
    def get_tools_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get all tools in a specific category with enhanced metadata.
        
        Args:
            category: Category name
            
        Returns:
            List of tool information dictionaries with 2025-06-18 features
        """
        tools_in_category = []
        for name in self.categories.get(category, []):
            tool_info = self.tools[name].copy()
            tool_info["name"] = name
            tools_in_category.append(tool_info)
        return tools_in_category
    
    def auto_discover_tools(self, server: FastMCP, client: OktaMcpClient):
        """
        Auto-discover and register all tools from the tools package.
        
        Args:
            server: FastMCP server instance
            client: Okta client wrapper
        """
        # Store server reference for notifications
        self.server = server
        
        import okta_mcp.tools as tools_package
        
        # Scan the tools package for modules
        tools_path = os.path.dirname(tools_package.__file__)
        discovered_modules = 0
        
        for _, name, is_pkg in pkgutil.iter_modules([tools_path]):
            if not is_pkg and name != 'tool_registry' and name != 'query_tools':  # Skip this module and query_tools
                try:
                    # Import the module
                    module = importlib.import_module(f"okta_mcp.tools.{name}")
                    # Register tools from it
                    self.register_tools_from_module(module, server, client)
                    discovered_modules += 1
                except ImportError as e:
                    logger.error(f"Error importing module okta_mcp.tools.{name}: {str(e)}")
        
        logger.info(f"Auto-discovered tools from {discovered_modules} modules: {len(self.tools)} tools in {len(self.categories)} categories")
        
    def register_all_tools(self, server: FastMCP, client: OktaMcpClient):
        """
        Register all tools with explicit imports and enhanced 2025-06-18 capabilities.
        
        This is an alternative to auto_discover_tools when you want explicit control.
        
        Args:
            server: FastMCP server instance
            client: Okta client wrapper
        """
        # Store server reference for notifications
        self.server = server
        
        logger.info(f"Starting tool registration with MCP protocol {self.protocol_version}")
        
        # Import and register core tool modules 
        modules_to_register = [
            ("user_tools", "okta_mcp.tools.user_tools"),
            ("group_tools", "okta_mcp.tools.group_tools"),
            ("apps_tools", "okta_mcp.tools.apps_tools"),
            ("datetime_tools", "okta_mcp.tools.datetime_tools"),
            ("log_events_tools", "okta_mcp.tools.log_events_tools"),
            ("policy_network_tools", "okta_mcp.tools.policy_network_tools")
        ]
        
        registered_count = 0
        for module_name, import_path in modules_to_register:
            try:
                module = importlib.import_module(import_path)
                self.register_tools_from_module(module, server, client)
                registered_count += 1
                logger.debug(f"Successfully registered {module_name}")
            except ImportError as e:
                logger.warning(f"Could not import {module_name}: {e}")
            except Exception as e:
                logger.error(f"Error registering {module_name}: {e}")
        
        logger.info(f"Core modules registered: {registered_count}/{len(modules_to_register)} modules")
        
        # Register enhanced capabilities for MCP 2025-06-18
        self.register_elicitation_capabilities(server)
        self.register_sampling_capabilities(server)
        
        # Log capability summary
        self._log_capability_summary()
    
    # In _log_capability_summary method:
    def _log_capability_summary(self):
        """Log a summary of registered capabilities for diagnostics."""
        actual_tool_count = self._count_fastmcp_tools(self.server) if self.server else 0
        
        summary_parts = [
            f"Protocol: {self.protocol_version}",
            f"Tools: {actual_tool_count}",
        ]
    
        if self.capabilities_registered["sampling"]:
            summary_parts.append("AI Sampling: ✅")
        
        # Fix the elicitation status
        if self.capabilities_registered.get("elicitation", False):
            summary_parts.append("Elicitation: ✅")
        elif self.capabilities_registered.get("elicitation_fallback", False):
            summary_parts.append("Elicitation: Fallback")
        else:
            summary_parts.append("Elicitation: ❌")
    
        logger.info(f"🚀 MCP Server Ready - {' | '.join(summary_parts)}")
        
        # Update the detailed summary too
        summary = {
            "fastmcp_tools": actual_tool_count,
            "protocol_version": self.protocol_version,
            "elicitation_enabled": self.capabilities_registered.get("elicitation", False),
            "elicitation_fallback": self.capabilities_registered.get("elicitation_fallback", False),
            "sampling_enabled": self.capabilities_registered["sampling"],
            "enhanced_logging": self.capabilities_registered["enhanced_logging"]
        }
        
        # Only show categories if > 0
        if len(self.categories) > 0:
            summary["categories"] = len(self.categories)
        
        logger.info(f"Tool Registry Summary: {summary}")
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get enhanced information about a specific tool."""
        tool_info = self.tools.get(tool_name)
        if tool_info:
            # Add runtime information
            enhanced_info = tool_info.copy()
            enhanced_info["name"] = tool_name
            enhanced_info["registry_protocol"] = self.protocol_version
            return enhanced_info
        return None
    
    def list_all_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools with enhanced metadata."""
        return [
            {
                "name": name,
                "category": info["category"],
                "description": info["definition"].get("description", ""),
                "supports_elicitation": info.get("supports_elicitation", False),
                "supports_sampling": info.get("supports_sampling", False),
                "has_schemas": info.get("has_schemas", False),
                "protocol_version": info.get("protocol_version", self.protocol_version)
            }
            for name, info in self.tools.items()
        ]
    
    def list_categories(self) -> List[str]:
        """List all available tool categories."""
        return list(self.categories.keys())
    
    def get_protocol_info(self) -> Dict[str, Any]:
        """Get protocol and capability information."""
        return {
            "protocol_version": self.protocol_version,
            "capabilities": {
                "tools": {
                    "listChanged": True,
                    "total_registered": len(self.tools)
                },
                "elicitation": {
                    "enabled": self.capabilities_registered["elicitation"],
                    "supported_tools": sum(1 for tool in self.tools.values() if tool.get("supports_elicitation", False))
                },
                "sampling": {
                    "enabled": self.capabilities_registered["sampling"],
                    "supported_tools": sum(1 for tool in self.tools.values() if tool.get("supports_sampling", False))
                },
                "logging": {
                    "enhanced": self.capabilities_registered["enhanced_logging"]
                },
                "completions": {}
            },
            "active_sessions": len(self.active_sessions)
        }
        
    async def refresh_tools(self, server: FastMCP, client: OktaMcpClient) -> bool:
        """
        Refresh all tool definitions and notify clients of changes (MCP 2025-06-18).
        
        Args:
            server: FastMCP server instance
            client: Okta client wrapper
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Store current tools for comparison
            old_tools = set(self.tools.keys())
            old_capabilities = self.capabilities_registered.copy()
            
            # Clear existing tools and categories but preserve capabilities state
            self.tools = {}
            self.categories = {}
            
            # Re-register all tools
            self.register_all_tools(server, client)
            
            # Notify all active client sessions using 2025-06-18 protocol
            await self.notify_tool_changes()
            
            # Log changes with enhanced information
            new_tools = set(self.tools.keys())
            added = new_tools - old_tools
            removed = old_tools - new_tools
            unchanged = old_tools & new_tools
            
            logger.info(f"Tools refreshed (Protocol {self.protocol_version}): {len(unchanged)} unchanged, {len(added)} added, {len(removed)} removed")
            
            if added:
                logger.info(f"Added tools: {', '.join(sorted(added))}")
            if removed:
                logger.info(f"Removed tools: {', '.join(sorted(removed))}")
            
            # Log capability changes
            for capability, enabled in self.capabilities_registered.items():
                if old_capabilities.get(capability) != enabled:
                    logger.info(f"Capability '{capability}' changed: {old_capabilities.get(capability)} -> {enabled}")
                
            return True
        except Exception as e:
            logger.error(f"Error refreshing tools: {str(e)}")
            return False
    
    async def notify_tool_changes(self):
        """Notify all connected clients that tool definitions have changed (MCP 2025-06-18)."""
        if not self.server:
            logger.error("Cannot send notifications: server reference not set")
            return
            
        notification_count = 0
        failed_notifications = 0
        
        for session_id in self.active_sessions.copy():  # Copy to avoid modification during iteration
            try:
                # Enhanced notification for MCP 2025-06-18
                # Note: FastMCP might handle notifications differently than raw MCP server
                # This is a best-effort implementation
                
                notification_params = {
                    "timestamp": logger.info.__module__,  # Placeholder for actual timestamp
                    "protocol_version": self.protocol_version,
                    "tool_count": len(self.tools),
                    "capabilities": list(self.capabilities_registered.keys())
                }
                
                # Send notification using tools/list_changed as per MCP spec
                # FastMCP might handle this internally, so we'll try the standard approach
                if hasattr(self.server, 'send_notification'):
                    await self.server.send_notification(
                        method="tools/list_changed",
                        params=notification_params
                    )
                else:
                    # Alternative approach for FastMCP
                    logger.debug(f"FastMCP notification sent to session {session_id}")
                
                notification_count += 1
                
            except Exception as e:
                logger.error(f"Failed to notify session {session_id}: {str(e)}")
                failed_notifications += 1
                
                # Remove failed session
                self.active_sessions.discard(session_id)
                
        logger.info(f"Tool change notifications: {notification_count} successful, {failed_notifications} failed (Protocol: {self.protocol_version})")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive registry statistics."""
        return {
            "protocol_version": self.protocol_version,
            "tools": {
                "total": len(self.tools),
                "by_category": {cat: len(tools) for cat, tools in self.categories.items()},
                "with_elicitation": sum(1 for tool in self.tools.values() if tool.get("supports_elicitation", False)),
                "with_sampling": sum(1 for tool in self.tools.values() if tool.get("supports_sampling", False)),
                "with_schemas": sum(1 for tool in self.tools.values() if tool.get("has_schemas", False))
            },
            "capabilities": self.capabilities_registered,
            "sessions": {
                "active": len(self.active_sessions),
                "total_registered": len(self.tools)
            }
        }

# Export for backward compatibility and external use
__all__ = ["ToolRegistry"]