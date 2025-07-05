"""
RBAC Middleware for OAuth-protected MCP endpoints.
Filters tools and validates permissions based on user roles.
"""
import json
import os
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

class OAuthRBACMiddleware:
    """Middleware to enforce RBAC on MCP tool access"""
    
    def __init__(self, auth_handler):
        self.auth_handler = auth_handler
        self.role_config = self._load_rbac_config()
        logger.debug(f"RBAC middleware initialized with {len(self.role_config.get('roles', {}))} roles and {len(self.role_config.get('tools', {}))} tool permissions")
        
    def _load_rbac_config(self) -> Dict[str, Any]:
        """Load RBAC configuration from JSON file"""
        # Hard-coded path relative to the auth module
        config_path = os.path.join(os.path.dirname(__file__), '..', 'auth', 'rbac_config.json')
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                logger.debug(f"Loaded RBAC config from {config_path}")
                logger.debug(f"RBAC roles: {list(config.get('roles', {}).keys())}")
                logger.debug(f"RBAC tool count: {len(config.get('tools', {}))}")
                return config
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load RBAC config from {config_path}: {e}")
            # Return minimal default config
            return {
                "roles": {"viewer": {"level": 1}},
                "tools": {}
            }
    
    def filter_tools_by_role(self, tools: List[Dict[str, Any]], user_role: Optional[str]) -> List[Dict[str, Any]]:
        """Filter tools list based on user role"""
        if not user_role:
            logger.debug("No user role provided - returning empty tools list")
            return []
            
        user_level = self.role_config.get('roles', {}).get(user_role, {}).get('level', 0)
        logger.debug(f"User role '{user_role}' has level {user_level}")
        
        if user_level == 0:
            logger.warning(f"Role '{user_role}' not found in RBAC config - blocking all tools")
            return []
            
        filtered_tools = []
        tool_permissions = self.role_config.get('tools', {})
        
        for tool in tools:
            tool_name = tool.get('name', '')
            required_level = tool_permissions.get(tool_name, {}).get('min_level', 1)
            
            if user_level >= required_level:
                filtered_tools.append(tool)
                logger.debug(f"Tool '{tool_name}' accessible: user level {user_level} >= required {required_level}")
            else:
                logger.debug(f"Tool '{tool_name}' blocked: user level {user_level} < required {required_level}")
        
        logger.debug(f"Role '{user_role}' can access {len(filtered_tools)}/{len(tools)} tools")
        return filtered_tools
    
    def can_execute_tool(self, tool_name: str, user_role: Optional[str]) -> bool:
        """Check if user role can execute a specific tool"""
        if not user_role:
            logger.debug(f"Tool '{tool_name}' execution denied: no user role")
            return False
            
        user_level = self.role_config.get('roles', {}).get(user_role, {}).get('level', 0)
        
        if user_level == 0:
            logger.warning(f"Tool '{tool_name}' execution denied: role '{user_role}' not found in RBAC config")
            return False
            
        tool_permissions = self.role_config.get('tools', {})
        required_level = tool_permissions.get(tool_name, {}).get('min_level', 1)
        
        can_execute = user_level >= required_level
        
        if can_execute:
            logger.debug(f"Tool '{tool_name}' execution allowed: role '{user_role}' level {user_level} >= required {required_level}")
        else:
            logger.warning(f"Tool '{tool_name}' execution denied: role '{user_role}' level {user_level} < required {required_level}")
            
        return can_execute
