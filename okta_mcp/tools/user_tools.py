"""User management tools for Okta MCP server."""

import logging
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

logger = logging.getLogger("okta_mcp_server")

def register_user_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all user-related tools with the MCP server.
    
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def list_okta_users(
        query: str = None,
        search: str = None, 
        filter_type: str = None,
        sort_by: str = "created",
        sort_order: str = "desc",
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta users with filtering. Use query for simple terms (e.g. 'Dan') or search for SCIM filters (e.g. profile.firstName eq "Dan").
            search (Recommended, Powerful):
            Uses flexible SCIM filter syntax.
            Supports operators: eq, ne, gt, lt, ge, le, sw (starts with), co (contains), pr (present), and, or.
            Filters on most user properties, including custom attributes, id, status, dates, arrays.
            Supports sorting (sortBy, sortOrder) - NOTE: Sorting parameters ONLY work with 'search' parameter, not with 'query'.
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
            filter_type: Filter type (status, type, etc.)
            sort_by: Field to sort by (only works with 'search' parameter)
            sort_order: Sort direction (asc or desc) (only works with 'search' parameter)
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing users and pagination information
        """
        try:
            limit = 200
            
            if ctx:
                await ctx.info(f"Listing users with parameters: query={query}, search={search}, filter={filter_type}")
            
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            if sort_order.lower() not in ['asc', 'desc']:
                raise ValueError("Sort order must be 'asc' or 'desc'")
            
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            # Priority: search > query > filter
            if search:
                params['search'] = search
                # Sort parameters only work with search queries
                params['sortBy'] = sort_by
                params['sortOrder'] = sort_order
            elif query:
                params['q'] = query
                
            if filter_type and not search:
                params['filter'] = filter_type
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_users(params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing users: {err}")
                if ctx:
                    await ctx.error(f"Error listing users: {err}")
                return handle_okta_result(err, "list_users")
            
            # Apply pagination based on environment variable
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_users = []
            page_count = 0
            
            # Process first page
            if users:
                all_users.extend(users)
                page_count += 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.list_users_next(resp)
                users, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        await ctx.error(f"Error during pagination: {err}")
                    break
                
                if users:
                    all_users.extend(users)
                    page_count += 1
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_users)} users across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination information
            result = {
                "users": [user.as_dict() for user in all_users],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_users),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_users tool")
            if ctx:
                await ctx.error(f"Error in list_users tool: {str(e)}")
            return handle_okta_result(e, "list_users")
    
    @server.tool()
    async def get_okta_user(user_id: str, ctx: Context = None) -> Dict[str, Any]:
        """Get detailed information about a specific Okta user.
        
        Args:
            user_id: The ID or login of the user to retrieve
            ctx: MCP Context for logging
            
        Returns:
            Dictionary containing detailed user information
        """
        try:
            if ctx:
                await ctx.info(f"Getting user info for: {user_id}")
            
            # Determine if user_id is an ID or a login
            if "@" in user_id:
                # Assume it's a login (email)
                if ctx:
                    await ctx.info(f"Identified {user_id} as email login, getting user by login")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
            else:
                # Assume it's a user ID
                if ctx:
                    await ctx.info(f"Identified {user_id} as user ID, getting user by ID")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting user {user_id}: {err}")
                if ctx:
                    await ctx.error(f"Error getting user {user_id}: {err}")
                return handle_okta_result(err, "get_user")
            
            # Format response
            result = user.as_dict()
            
            if ctx:
                await ctx.info(f"Successfully retrieved user data for {user_id}")
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in get_user tool for user_id {user_id}")
            if ctx:
                await ctx.error(f"Error in get_user tool: {str(e)}")
            return handle_okta_result(e, "get_user")
        
    @server.tool()
    async def list_okta_user_groups(
        user_id: str,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all groups that a specific Okta user belongs to.
        
        Args:
            user_id: The ID or login of the user
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing the user's groups and pagination information
        """
        try:
            if ctx:
                await ctx.info(f"Listing groups for user: {user_id}")
            
            # Normalize user_id (handle email/login case)
            if "@" in user_id:
                # If it's an email/login, we need to get the user ID first
                if ctx:
                    await ctx.info(f"Converting login {user_id} to user ID")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    logger.error(f"Error getting user {user_id}: {err}")
                    if ctx:
                        await ctx.error(f"Error getting user {user_id}: {err}")
                    return handle_okta_result(err, "list_user_groups")
                    
                # Extract the actual user ID
                user_id = user.id
                
            # Execute Okta API request to get user's groups - single call, no pagination
            if ctx:
                await ctx.info(f"Fetching groups for user ID: {user_id}")
                
            raw_response = await okta_client.client.list_user_groups(user_id)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups for user {user_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing groups for user {user_id}: {err}")
                return handle_okta_result(err, "list_user_groups")
            
            if ctx:
                await ctx.info(f"Retrieved {len(groups) if groups else 0} groups")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response without pagination info since there's no pagination
            result = {
                "groups": [group.as_dict() for group in groups] if groups else [],
                "total_groups": len(groups) if groups else 0
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_user_groups tool for user_id {user_id}")
            if ctx:
                await ctx.error(f"Error in list_user_groups tool: {str(e)}")
            return handle_okta_result(e, "list_user_groups")      
        
    @server.tool()
    async def list_okta_user_applications(
        user_id: str,
        show_all: bool = True,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all application links (assigned applications) for a specific Okta user.
        
        Args:
            user_id: The ID or login of the user
            show_all: If True, shows all app links; if False, only shows app links assigned directly to the user
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing the user's app links
        """
        try:
            if ctx:
                await ctx.info(f"Listing app links for user: {user_id}")
            
            # Normalize user_id (handle email/login case)
            if "@" in user_id:
                # If it's an email/login, we need to get the user ID first
                if ctx:
                    await ctx.info(f"Converting login {user_id} to user ID")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    logger.error(f"Error getting user {user_id}: {err}")
                    if ctx:
                        await ctx.error(f"Error getting user {user_id}: {err}")
                    return handle_okta_result(err, "list_app_links")
                    
                # Extract the actual user ID
                user_id = user.id
                
            # Execute Okta API request to get user's app links
            if ctx:
                await ctx.info(f"Fetching app links for user ID: {user_id}")
            
            # Prepare request parameters
            params = {}
            if show_all:
                params['showAll'] = True
                
            raw_response = await okta_client.client.list_app_links(user_id, params)
            app_links, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing app links for user {user_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing app links for user {user_id}: {err}")
                return handle_okta_result(err, "list_app_links")
            
            # For app links, no need for pagination as it's returned as a single list
            
            if ctx:
                await ctx.info(f"Retrieved {len(app_links) if app_links else 0} app links for user {user_id}")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response
            result = {
                "app_links": [app_link.as_dict() for app_link in app_links] if app_links else [],
                "total_results": len(app_links) if app_links else 0
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_app_links tool for user_id {user_id}")
            if ctx:
                await ctx.error(f"Error in list_app_links tool: {str(e)}")
            return handle_okta_result(e, "list_app_links")
        
    @server.tool()
    async def list_okta_user_factors(
        user_id: str,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all authentication factors enrolled for a specific Okta user.
        
        Args:
            user_id: The ID or login of the user
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing the user's authentication factors
        """
        try:
            if ctx:
                await ctx.info(f"Listing authentication factors for user: {user_id}")
            
            # Normalize user_id (handle email/login case)
            if "@" in user_id:
                # If it's an email/login, we need to get the user ID first
                if ctx:
                    await ctx.info(f"Converting login {user_id} to user ID")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    logger.error(f"Error getting user {user_id}: {err}")
                    if ctx:
                        await ctx.error(f"Error getting user {user_id}: {err}")
                    return handle_okta_result(err, "list_user_factors")
                    
                # Extract the actual user ID
                user_id = user.id
                
            # Execute Okta API request to get user's factors
            if ctx:
                await ctx.info(f"Fetching authentication factors for user ID: {user_id}")
                
            raw_response = await okta_client.client.list_factors(user_id)
            factors, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing factors for user {user_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing factors for user {user_id}: {err}")
                return handle_okta_result(err, "list_user_factors")
            
            # For factors, we typically don't need pagination as they come in a single response
            
            if ctx:
                await ctx.info(f"Retrieved {len(factors) if factors else 0} authentication factors")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response
            result = {
                "factors": [factor.as_dict() for factor in factors] if factors else [],
                "total_factors": len(factors) if factors else 0
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_user_factors tool for user_id {user_id}")
            if ctx:
                await ctx.error(f"Error in list_user_factors tool: {str(e)}")
            return handle_okta_result(e, "list_user_factors")                 
    
    #logger.info("Registered user management tools")