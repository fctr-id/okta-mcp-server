"""
Role Mapper for RBAC implementation.
Maps Okta groups to roles using environment variables.

Environment Variable Format:
    GROUP_TO_ROLE_<ROLE_NAME>=<OKTA_GROUP_NAME(S)>

Examples:
    GROUP_TO_ROLE_ADMIN="MCP Admins"
    GROUP_TO_ROLE_VIEWER="Users,Everyone"
    GROUP_TO_ROLE_SECURITY_ADMIN="Security Team,SOC Analysts"

Features:
- Case-insensitive group matching
- Support for group names with spaces
- Comma-separated multiple groups per role
- Optional quotes around group names
- Highest role wins when user has multiple qualifying groups
"""
import os
import json
import re
from typing import List, Dict, Optional, Set
import logging

logger = logging.getLogger(__name__)

class OktaGroupRoleMapper:
    def __init__(self):
        # Parse environment variables for role-to-group mapping
        # Format: GROUP_TO_ROLE_<ROLE_NAME>=<OKTA_GROUP_NAME(S)>
        # Example: GROUP_TO_ROLE_ADMIN="MCP Admins,Security Team"
        self.role_to_groups = self._parse_role_mappings()
        
        # Load role hierarchy from config (extensible for new roles)
        self.role_levels = self._load_role_levels()
        
    def _parse_role_mappings(self) -> Dict[str, Set[str]]:
        """
        Parse role-to-group mappings from environment variables
        
        Converts environment variables like:
            GROUP_TO_ROLE_ADMIN="MCP Admins,Security Team"
            GROUP_TO_ROLE_VIEWER=Users
        
        Into normalized mappings:
            {'admin': {'mcp admins', 'security team'}, 'viewer': {'users'}}
        """
        mappings = {}
        
        for key, value in os.environ.items():
            if key.startswith('GROUP_TO_ROLE_'):
                # Extract role name: GROUP_TO_ROLE_ADMIN -> admin
                role_name = key[14:].lower().replace('_', '-')  # Convert to lowercase with hyphens
                
                # Parse group names (support comma-separated, quoted values)
                group_names = self._parse_group_names(value)
                
                if group_names:
                    mappings[role_name] = group_names
                    logger.debug(f"Role '{role_name}' mapped to groups: {sorted(group_names)}")
                else:
                    logger.warning(f"Role '{role_name}' has no valid group mappings")
        
        # Log loaded mappings for debugging
        if mappings:
            total_groups = sum(len(groups) for groups in mappings.values())
            logger.debug(f"Loaded {len(mappings)} roles with {total_groups} total group mappings")
        else:
            logger.warning("No role-to-group mappings found. Users will have no roles.")
            
        return mappings
    
    def _parse_group_names(self, value: str) -> Set[str]:
        """Parse group names from environment variable value with flexible formatting"""
        if not value or not value.strip():
            return set()
        
        group_names = set()
        
        # Split by comma and clean up each group name
        raw_groups = [g.strip() for g in value.split(',')]
        
        for group in raw_groups:
            if not group:
                continue
                
            # Remove optional quotes and normalize
            cleaned_group = group.strip('\'"').strip()
            if cleaned_group:
                # Store in lowercase for case-insensitive matching
                group_names.add(cleaned_group.lower())
        
        return group_names
        
    def _load_role_levels(self) -> Dict[str, int]:
        """Load role hierarchy from RBAC config (supports dynamic role addition)"""
        # Hard-coded path relative to this module
        config_path = os.path.join(os.path.dirname(__file__), 'rbac_config.json')
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                role_levels = {role: data['level'] for role, data in config.get('roles', {}).items()}
                logger.debug(f"Loaded {len(role_levels)} roles from config: {list(role_levels.keys())}")
                return role_levels
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to load RBAC config from {config_path}: {e}")
            # Fallback to default roles if config fails
            default_roles = {
                'viewer': 1,
                'admin': 2,
                'super-admin': 3
            }
            logger.warning(f"Using default role hierarchy: {default_roles}")
            return default_roles
        
    def get_user_role(self, user_groups: List[str]) -> Optional[str]:
        """Map user groups to single role (highest role wins)"""
        if not user_groups:
            logger.debug("User has no groups - no role assigned")
            return None  # No role assigned - blocks all tool access
        
        # Normalize user groups for case-insensitive matching
        normalized_user_groups = {group.lower().strip() for group in user_groups if group and group.strip()}
        
        if not normalized_user_groups:
            logger.debug("User has no valid groups after normalization - no role assigned")
            return None
            
        logger.debug(f"Normalized user groups: {sorted(normalized_user_groups)}")
        
        # Find all roles that the user qualifies for
        qualified_roles = []
        
        for role, mapped_groups in self.role_to_groups.items():
            # Check if user has any of the groups mapped to this role
            if normalized_user_groups.intersection(mapped_groups):
                # Only add role if it exists in our role hierarchy
                if role in self.role_levels:
                    qualified_roles.append(role)
                    matching_groups = normalized_user_groups.intersection(mapped_groups)
                    logger.debug(f"User qualifies for role '{role}' via groups: {sorted(matching_groups)}")
                else:
                    logger.warning(f"Role '{role}' is mapped but not in hierarchy - skipping")
                    
        if not qualified_roles:
            logger.debug(f"User groups {sorted(user_groups)} do not map to any valid roles")
            return None  # No role assigned if no groups map to valid roles
            
        # Return highest role (by level) - handles new roles automatically
        highest_role = max(qualified_roles, key=lambda role: self.role_levels.get(role, 0))
        logger.info(f"User assigned role '{highest_role}' (highest from {qualified_roles})")
        return highest_role

    def get_all_mapped_groups(self) -> Set[str]:
        """Get all groups that are mapped to any role (for debugging)"""
        all_groups = set()
        for groups in self.role_to_groups.values():
            all_groups.update(groups)
        return all_groups
    
    def get_role_for_group(self, group_name: str) -> Optional[str]:
        """Get the highest role that a specific group maps to (for debugging)"""
        normalized_group = group_name.lower().strip()
        
        # Find all roles this group qualifies for
        qualified_roles = []
        for role, mapped_groups in self.role_to_groups.items():
            if normalized_group in mapped_groups and role in self.role_levels:
                qualified_roles.append(role)
        
        if not qualified_roles:
            return None
            
        # Return highest role
        return max(qualified_roles, key=lambda role: self.role_levels.get(role, 0))
    
    def validate_configuration(self) -> Dict[str, any]:
        """Validate the current RBAC configuration and return status"""
        status = {
            'valid': True,
            'issues': [],
            'summary': {
                'total_roles': len(self.role_to_groups),
                'total_groups': len(self.get_all_mapped_groups()),
                'role_hierarchy_size': len(self.role_levels)
            }
        }
        
        # Check for roles without hierarchy definition
        for role in self.role_to_groups.keys():
            if role not in self.role_levels:
                status['valid'] = False
                status['issues'].append(f"Role '{role}' is mapped but not defined in hierarchy")
        
        # Check for empty group mappings
        for role, groups in self.role_to_groups.items():
            if not groups:
                status['issues'].append(f"Role '{role}' has no group mappings")
        
        return status

    def reload_config(self):
        """Reload both role hierarchy and role mappings"""
        logger.debug("Reloading RBAC configuration...")
        self.role_levels = self._load_role_levels()
        self.role_to_groups = self._parse_role_mappings()
        logger.debug("RBAC configuration reloaded")
