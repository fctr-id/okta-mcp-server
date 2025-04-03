"""User management tools for Okta MCP server."""

import logging
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response

logger = logging.getLogger(__name__)

def register_user_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all user-related tools with the MCP server.
    
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def list_users(
        query: str = None,
        search: str = None, 
        limit: int = 20, 
        filter_type: str = None,
        sort_by: str = "created",
        sort_order: str = "desc"
    ) -> Dict[str, Any]:
        """List Okta users with  filtering. Use query for simple terms (e.g. 'Dan') or search for SCIM filters (e.g. profile.firstName eq "Dan").
            q (Simple Query):
            Basic startsWith search on firstName, lastName, email.
            Example: {'q': 'john'}
            filter (Limited Filtering):
            Simpler syntax, mainly uses eq (equal).
            Supports date comparisons (gt, lt, etc.) only for lastUpdated.
            Filters on specific fields like status, lastUpdated, id, profile.login, profile.email, profile.firstName, profile.lastName.
            Examples:
            {'filter': 'status eq "ACTIVE"'}
            {'filter': 'lastUpdated gt "2024-01-01T00:00:00.000Z"'}
            {'filter': 'status eq "ACTIVE" and profile.lastName eq "Doe"'}
            search (Recommended, Powerful):
            Uses flexible SCIM filter syntax.
            Supports operators: eq, ne, gt, lt, ge, le, sw (starts with), co (contains), pr (present), and, or.
            Filters on most user properties, including custom attributes, id, status, dates, arrays.
            Supports sorting (sortBy, sortOrder).
            Examples:
            {'search': 'profile.department eq "Engineering" and status eq "ACTIVE"'}
            {'search': 'profile.firstName sw "A"'}
            {'search': 'profile.city eq "San Francisco" or profile.city eq "London"'}
            Sorting: {'search': 'status eq "ACTIVE"', 'sortBy': 'profile.lastName', 'sortOrder': 'ascending'}
            Custom Attribute (Exact): {'search': 'profile.employeeNumber eq "12345"'}
            Custom Attribute (Starts With): {'search': 'profile.employeeNumber sw "123"'}
            Custom Attribute (Present): {'search': 'profile.employeeNumber pr'}
        Args:
            query: Simple text search only - use plain names like "Dan" (NOT "firstname:Dan")
            search: SCIM filtering (recommended) - use exact syntax like 'profile.firstName eq "Dan"'
            limit: Maximum number of users to return (1-200)
            filter_type: Filter type (status, type, etc.)
            sort_by: Field to sort by
            sort_order: Sort direction (asc or desc)
        Returns:
            Dictionary containing users and pagination information
        """
        try:
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            if sort_order.lower() not in ['asc', 'desc']:
                raise ValueError("Sort order must be 'asc' or 'desc'")
            
            # Prepare request parameters
            params = {
                'limit': limit,
                'sortBy': sort_by,
                'sortOrder': sort_order
            }
            
            # Priority: search > query > filter
            if search:
                params['search'] = search
            elif query:
                params['q'] = query
                
            if filter_type and not search:
                params['filter'] = filter_type
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_users(params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing users: {err}")
                return handle_okta_result(err, "list_users")
            
            # Format response - with fix for pagination handling
            result = {
                "users": [user.as_dict() for user in users],
                "pagination": {
                    "limit": limit,
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_users tool")
            return handle_okta_result(e, "list_users")
    
    @server.tool()
    async def get_user(user_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific Okta user.
        
        Args:
            user_id: The ID or login of the user to retrieve
            
        Returns:
            Dictionary containing detailed user information
        """
        try:
            # Determine if user_id is an ID or a login
            if "@" in user_id:
                # Assume it's a login (email)
                raw_response = await okta_client.client.get_user_by_login(user_id)
                user, resp, err = normalize_okta_response(raw_response)
            else:
                # Assume it's a user ID
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting user {user_id}: {err}")
                return handle_okta_result(err, "get_user")
            
            # Format response
            result = user.as_dict()
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in get_user tool for user_id {user_id}")
            return handle_okta_result(e, "get_user")
    
    logger.info("Registered user management tools")