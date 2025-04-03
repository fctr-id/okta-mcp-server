"""Group management tools for Okta MCP server."""

import logging
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response

logger = logging.getLogger(__name__)

def register_group_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all group-related tools with the MCP server.
    
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def list_groups(
        query: str = None,
        filter_type: str = None,
        limit: int = 20,
        name: str = None,
        type: str = None,
        after: str = None
    ) -> Dict[str, Any]:
        """List Okta groups with various filtering options.
        
        Args:
            query: Simple text search on name (e.g., 'Engineering')
            filter_type: Group filter (e.g., 'type eq "OKTA_GROUP"')
            limit: Maximum number of groups to return (1-200)
            name: Filter by exact group name
            type: Filter by group type (OKTA_GROUP, APP_GROUP, etc.)
            after: Pagination cursor
            
        Returns:
            Dictionary containing groups and pagination information
        """
        try:
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if query:
                params['q'] = query
                
            if filter_type:
                params['filter'] = filter_type
                
            if name:
                # Add name filter if not using general query
                if 'q' not in params:
                    params['q'] = name
                    
            if type:
                # Add type filter if not already specified
                if 'filter' not in params:
                    params['filter'] = f'type eq "{type}"'
                    
            if after:
                params['after'] = after
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_groups(params)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups: {err}")
                return handle_okta_result(err, "list_groups")
            
            # Format response
            result = {
                "groups": [group.as_dict() for group in groups],
                "pagination": {
                    "limit": limit,
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_groups tool")
            return handle_okta_result(e, "list_groups")
    
    @server.tool()
    async def get_group(group_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific Okta group.
        
        Args:
            group_id: The ID of the group to retrieve
            
        Returns:
            Dictionary containing detailed group information
        """
        try:
            # Get the group by ID
            raw_response = await okta_client.client.get_group(group_id)
            group, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting group {group_id}: {err}")
                return handle_okta_result(err, "get_group")
            
            # Format response
            result = group.as_dict()
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in get_group tool for group_id {group_id}")
            return handle_okta_result(e, "get_group")
    
    @server.tool()
    async def list_group_members(
        group_id: str,
        limit: int = 50,
        after: str = None
    ) -> Dict[str, Any]:
        """List all members of a specific Okta group.
        
        Args:
            group_id: The ID of the group
            limit: Maximum number of members to return (1-200)
            after: Pagination cursor
            
        Returns:
            Dictionary containing group members and pagination information
        """
        try:
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if after:
                params['after'] = after
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_group_users(group_id, params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing group members for group {group_id}: {err}")
                return handle_okta_result(err, "list_group_users")
            
            # Format response
            result = {
                "members": [user.as_dict() for user in users],
                "group_id": group_id,
                "pagination": {
                    "limit": limit,
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_group_members tool for group_id {group_id}")
            return handle_okta_result(e, "list_group_members")
    
    logger.info("Registered group management tools")