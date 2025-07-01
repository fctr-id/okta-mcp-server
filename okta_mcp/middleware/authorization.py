"""Authorization middleware for Okta MCP Server using FastMCP middleware system"""

import logging
import json
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, field
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.exceptions import ToolError
from okta_mcp.auth.oauth_provider import validate_oauth_token

logger = logging.getLogger(__name__)

@dataclass
class ToolPermission:
    """Configuration for a single tool's permissions"""
    roles: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    public: bool = False
    description: str = ""
    context_rules: List[str] = field(default_factory=list)  # For contextual authorization
    
    def requires_authorization(self) -> bool:
        """Check if tool requires authorization"""
        return not self.public

@dataclass 
class AuthorizationConfig:
    """Complete authorization configuration"""
    tool_permissions: Dict[str, ToolPermission] = field(default_factory=dict)
    role_hierarchy: Dict[str, List[str]] = field(default_factory=dict)
    default_permissions: ToolPermission = field(default_factory=lambda: ToolPermission(roles=["admin"]))
    
    @classmethod
    def from_file(cls, config_path: str) -> 'AuthorizationConfig':
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
            
            config = cls()
            
            # Load tool permissions
            for tool_name, perm_data in data.get('tool_permissions', {}).items():
                config.tool_permissions[tool_name] = ToolPermission(**perm_data)
            
            # Load role hierarchy
            config.role_hierarchy = data.get('role_hierarchy', {})
            
            # Load default permissions
            if 'default_permissions' in data:
                config.default_permissions = ToolPermission(**data['default_permissions'])
            
            logger.info(f"Authorization configuration loaded from {config_path}")
            return config
            
        except Exception as e:
            logger.error(f"Failed to load authorization config from {config_path}: {e}")
            raise
    
    @classmethod
    def default_okta_config(cls) -> 'AuthorizationConfig':
        """Create default Okta configuration"""
        config = cls()
        
        # Tool permissions
        config.tool_permissions = {
            # Public tools
            "get_current_time": ToolPermission(public=True, description="Get current time"),
            "parse_relative_time": ToolPermission(public=True, description="Parse relative time"),
            
            # User management
            "list_okta_users": ToolPermission(
                roles=["user.read", "admin"], 
                scopes=["okta.users.read"],
                description="List Okta users",
                context_rules=["bulk_operation_limit"]
            ),
            "get_okta_user": ToolPermission(
                roles=["user.read", "admin"], 
                scopes=["okta.users.read"],
                description="Get specific user details",
                context_rules=["self_or_admin"]
            ),
            "list_okta_user_groups": ToolPermission(
                roles=["user.read", "admin"], 
                scopes=["okta.users.read", "okta.groups.read"],
                description="List user's groups"
            ),
            "list_okta_user_applications": ToolPermission(
                roles=["user.read", "admin"], 
                scopes=["okta.users.read", "okta.apps.read"],
                description="List user's applications"
            ),
            "list_okta_user_factors": ToolPermission(
                roles=["user.read", "admin"], 
                scopes=["okta.users.read"],
                description="List user's authentication factors"
            ),
            
            # Group management
            "list_okta_groups": ToolPermission(
                roles=["group.read", "admin"], 
                scopes=["okta.groups.read"],
                description="List Okta groups",
                context_rules=["bulk_operation_limit"]
            ),
            "get_okta_group": ToolPermission(
                roles=["group.read", "admin"], 
                scopes=["okta.groups.read"],
                description="Get specific group details"
            ),
            "list_okta_group_members": ToolPermission(
                roles=["group.read", "admin"], 
                scopes=["okta.groups.read"],
                description="List group members"
            ),
            "list_okta_assigned_applications_for_group": ToolPermission(
                roles=["group.read", "admin"], 
                scopes=["okta.groups.read", "okta.apps.read"],
                description="List applications assigned to group"
            ),
            
            # Application management
            "list_okta_applications": ToolPermission(
                roles=["app.read", "admin"], 
                scopes=["okta.apps.read"],
                description="List Okta applications"
            ),
            "list_okta_application_users": ToolPermission(
                roles=["app.read", "admin"], 
                scopes=["okta.apps.read"],
                description="List application users"
            ),
            "list_okta_application_group_assignments": ToolPermission(
                roles=["app.read", "admin"], 
                scopes=["okta.apps.read"],
                description="List application group assignments"
            ),
            
            # Administrative tools
            "list_okta_policy_rules": ToolPermission(
                roles=["admin"], 
                scopes=["okta.policies.read"],
                description="List policy rules - admin only"
            ),
            "get_okta_policy_rule": ToolPermission(
                roles=["admin"], 
                scopes=["okta.policies.read"],
                description="Get specific policy rule - admin only"
            ),
            "list_okta_network_zones": ToolPermission(
                roles=["admin"], 
                scopes=["okta.networkZones.read"],
                description="List network zones - admin only"
            ),
            "get_okta_event_logs": ToolPermission(
                roles=["admin"], 
                scopes=["okta.logs.read"],
                description="Access audit logs - admin only"
            ),
        }
        
        # Role hierarchy
        config.role_hierarchy = {
            "admin": ["user.read", "group.read", "app.read"],
            "user.admin": ["user.read"],
            "group.admin": ["group.read"],
            "app.admin": ["app.read"]
        }
        
        return config
    
    def add_tool_permission(self, tool_name: str, permission: ToolPermission):
        """Add or update tool permission"""
        self.tool_permissions[tool_name] = permission
        logger.info(f"Added permission for tool: {tool_name}")
    
    def get_tool_permission(self, tool_name: str) -> ToolPermission:
        """Get tool permission or default"""
        return self.tool_permissions.get(tool_name, self.default_permissions)


class ContextualRule(ABC):
    """Abstract base class for contextual authorization rules"""
    
    @abstractmethod
    def evaluate(self, tool_name: str, arguments: Dict, user_info: Dict) -> bool:
        """Evaluate the contextual rule"""
        pass
    
    @abstractmethod
    def get_error_message(self, tool_name: str, arguments: Dict, user_info: Dict) -> str:
        """Get error message when rule fails"""
        pass


class SelfOrAdminRule(ContextualRule):
    """Rule that allows access to own data or admin access"""
    
    def evaluate(self, tool_name: str, arguments: Dict, user_info: Dict) -> bool:
        user_roles = user_info.get("roles", [])
        user_id = user_info.get("user_id")
        target_user_id = arguments.get("user_id")
        
        return "admin" in user_roles or target_user_id == user_id
    
    def get_error_message(self, tool_name: str, arguments: Dict, user_info: Dict) -> str:
        return f"Access denied: You can only access your own user data unless you have admin privileges"


class BulkOperationLimitRule(ContextualRule):
    """Rule that limits bulk operations for non-admins"""
    
    def __init__(self, max_limit: int = 50):
        self.max_limit = max_limit
    
    def evaluate(self, tool_name: str, arguments: Dict, user_info: Dict) -> bool:
        user_roles = user_info.get("roles", [])
        limit = arguments.get("limit", 10)
        
        return "admin" in user_roles or limit <= self.max_limit
    
    def get_error_message(self, tool_name: str, arguments: Dict, user_info: Dict) -> str:
        limit = arguments.get("limit", 10)
        return f"Access denied: Bulk operations limited to {self.max_limit} items (requested: {limit}). Admin role required for larger operations."


class ContextualRuleEngine:
    """Engine for evaluating contextual authorization rules"""
    
    def __init__(self):
        self.rules = {
            "self_or_admin": SelfOrAdminRule(),
            "bulk_operation_limit": BulkOperationLimitRule()
        }
    
    def add_rule(self, name: str, rule: ContextualRule):
        """Add a custom contextual rule"""
        self.rules[name] = rule
        logger.info(f"Added contextual rule: {name}")
    
    def evaluate_rules(self, rule_names: List[str], tool_name: str, arguments: Dict, user_info: Dict) -> tuple[bool, Optional[str]]:
        """Evaluate list of rules and return result with error message"""
        for rule_name in rule_names:
            if rule_name not in self.rules:
                logger.warning(f"Unknown contextual rule: {rule_name}")
                continue
            
            rule = self.rules[rule_name]
            if not rule.evaluate(tool_name, arguments, user_info):
                return False, rule.get_error_message(tool_name, arguments, user_info)
        
        return True, None


class OktaAuthorizationMiddleware(Middleware):
    """Enhanced role-based authorization middleware for Okta MCP tools"""
    
    def __init__(self, config: Optional[AuthorizationConfig] = None, config_file: Optional[str] = None):
        """Initialize with configuration"""
        if config_file:
            self.config = AuthorizationConfig.from_file(config_file)
        elif config:
            self.config = config
        else:
            # Try to load from environment or use default
            config_path = os.getenv("OKTA_MCP_AUTH_CONFIG")
            if config_path and os.path.exists(config_path):
                self.config = AuthorizationConfig.from_file(config_path)
            else:
                self.config = AuthorizationConfig.default_okta_config()
        
        self.contextual_rules = ContextualRuleEngine()
        logger.info("OktaAuthorizationMiddleware initialized with configuration")
    
    def add_tool_permission(self, tool_name: str, permission: ToolPermission):
        """Add new tool permission at runtime"""
        self.config.add_tool_permission(tool_name, permission)
    
    def add_contextual_rule(self, name: str, rule: ContextualRule):
        """Add custom contextual rule"""
        self.contextual_rules.add_rule(name, rule)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Authorize tool execution based on user roles and OAuth scopes"""
        tool_name = context.message.name
        arguments = context.message.arguments or {}
        
        # Get tool permission configuration
        tool_permission = self.config.get_tool_permission(tool_name)
        
        # Check if tool requires authorization
        if not tool_permission.requires_authorization():
            return await call_next(context)
        
        # Extract user info from OAuth token
        user_info = self._extract_user_from_context(context)
        if not user_info:
            raise ToolError("Authentication required")
        
        # Check basic authorization (roles and scopes)
        if not self._is_authorized(tool_name, tool_permission, user_info):
            raise ToolError(
                f"Access denied: insufficient permissions for {tool_name}. "
                f"Required roles: {tool_permission.roles}, "
                f"Required scopes: {tool_permission.scopes}"
            )
        
        # Check contextual authorization rules
        if tool_permission.context_rules:
            is_allowed, error_message = self.contextual_rules.evaluate_rules(
                tool_permission.context_rules, tool_name, arguments, user_info
            )
            if not is_allowed:
                raise ToolError(error_message or "Access denied based on request context")
        
        # Log authorized access
        self._log_authorized_access(tool_name, user_info, tool_permission)
        
        return await call_next(context)
    
    def _extract_user_from_context(self, context: MiddlewareContext) -> Optional[Dict]:
        """Extract user information from OAuth token in context"""
        try:
            # Get authorization header from FastMCP context
            if not hasattr(context, 'authorization') or not context.authorization:
                return None
            
            auth_header = context.authorization
            if not auth_header.startswith('Bearer '):
                return None
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Validate token and extract user info
            user_info = validate_oauth_token(token)
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to extract user from context: {e}")
            return None
    
    def _is_authorized(self, tool_name: str, tool_permission: ToolPermission, user_info: Dict) -> bool:
        """Check if user is authorized for tool"""
        # Get user roles and scopes
        user_roles = set(user_info.get("roles", []))
        user_scopes = set(user_info.get("scopes", []))
        
        # Expand roles with hierarchy
        expanded_roles = self._expand_roles(user_roles)
        
        # Check required roles
        required_roles = set(tool_permission.roles)
        if required_roles and not required_roles.intersection(expanded_roles):
            logger.warning(
                f"Role check failed for {tool_name}. "
                f"User roles: {expanded_roles}, Required: {required_roles}"
            )
            return False
        
        # Check required OAuth scopes
        required_scopes = set(tool_permission.scopes)
        if required_scopes and not required_scopes.issubset(user_scopes):
            logger.warning(
                f"Scope check failed for {tool_name}. "
                f"User scopes: {user_scopes}, Required: {required_scopes}"
            )
            return False
        
        return True
    
    def _expand_roles(self, user_roles: Set[str]) -> Set[str]:
        """Expand user roles based on hierarchy"""
        expanded = set(user_roles)
        
        for role in user_roles:
            if role in self.config.role_hierarchy:
                expanded.update(self.config.role_hierarchy[role])
        
        return expanded
    
    def _log_authorized_access(self, tool_name: str, user_info: Dict, tool_permission: ToolPermission):
        """Log authorized tool access for audit purposes"""
        logger.info(
            f"AUDIT: User {user_info.get('email', 'unknown')} "
            f"(ID: {user_info.get('user_id', 'unknown')}) "
            f"accessed {tool_name} ({tool_permission.description}) "
            f"with roles {user_info.get('roles', [])}"
        )
    
    def _is_authorized(self, tool_name: str, user_info: Dict) -> bool:
        """Check if user is authorized for tool"""
        tool_config = self.config.tool_permissions.get(tool_name, {})
        
        # Get user roles and scopes
        user_roles = set(user_info.get("roles", []))
        user_scopes = set(user_info.get("scopes", []))
        
        # Expand roles with hierarchy
        expanded_roles = self._expand_roles(user_roles)
        
        # Check required roles
        required_roles = set(tool_config.get("roles", []))
        if required_roles and not required_roles.intersection(expanded_roles):
            logger.warning(
                f"Role check failed for {tool_name}. "
                f"User roles: {expanded_roles}, Required: {required_roles}"
            )
            return False
        
        # Check required OAuth scopes
        required_scopes = set(tool_config.get("scopes", []))
        if required_scopes and not required_scopes.issubset(user_scopes):
            logger.warning(
                f"Scope check failed for {tool_name}. "
                f"User scopes: {user_scopes}, Required: {required_scopes}"
            )
            return False
        
        return True
    
    def _expand_roles(self, user_roles: Set[str]) -> Set[str]:
        """Expand user roles based on hierarchy"""
        expanded = set(user_roles)
        
        for role in user_roles:
            if role in self.config.role_hierarchy:
                expanded.update(self.config.role_hierarchy[role])
        
        return expanded
    
    def _log_authorized_access(self, tool_name: str, user_info: Dict):
        """Log authorized tool access for audit purposes"""
        logger.info(
            f"AUDIT: User {user_info.get('email', 'unknown')} "
            f"(ID: {user_info.get('user_id', 'unknown')}) "
            f"accessed {tool_name} with roles {user_info.get('roles', [])}"
        )


class ContextualAuthorizationMiddleware(Middleware):
    """Context-aware authorization that considers request parameters"""
    
    def __init__(self, config: AuthorizationConfig = None):
        self.authorization_middleware = OktaAuthorizationMiddleware(config)
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Apply contextual authorization rules"""
        tool_name = context.message.name
        arguments = context.message.arguments or {}
        
        # First, apply standard authorization
        await self.authorization_middleware.on_call_tool(context, lambda ctx: None)
        
        # Get user info for contextual checks
        user_info = self.authorization_middleware._extract_user_from_context(context)
        if not user_info:
            raise ToolError("Authentication required for contextual authorization")
        
        # Apply contextual authorization rules
        if not self._is_contextually_authorized(tool_name, arguments, user_info):
            raise ToolError("Access denied based on request context")
        
        return await call_next(context)
    
    def _is_contextually_authorized(self, tool_name: str, arguments: Dict, user_info: Dict) -> bool:
        """Apply context-specific authorization rules"""
        user_roles = user_info.get("roles", [])
        user_id = user_info.get("user_id")
        
        # Example: Users can only query their own data unless they're admin
        if tool_name == "get_okta_user":
            target_user_id = arguments.get("user_id")
            if "admin" not in user_roles and target_user_id != user_id:
                logger.warning(f"User {user_id} attempted to access other user's data: {target_user_id}")
                return False
        
        # Example: Limit sensitive operations to admins
        if tool_name in ["get_okta_event_logs", "list_okta_policy_rules"]:
            if "admin" not in user_roles:
                logger.warning(f"Non-admin user {user_id} attempted sensitive operation: {tool_name}")
                return False
        
        # Example: Restrict bulk operations for non-admins
        if tool_name in ["list_okta_users", "list_okta_groups"]:
            limit = arguments.get("limit", 10)
            if "admin" not in user_roles and limit > 50:
                logger.warning(f"Non-admin user {user_id} attempted bulk operation with limit {limit}")
                return False
        
        return True