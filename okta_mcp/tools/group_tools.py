"""Group management tools for Okta MCP server."""

import logging
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

logger = logging.getLogger("okta_mcp_server")

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
        name: str = None,
        type: str = None,
        after: str = None,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta groups with various filtering options.
        
        Args:
            query: Simple text search on name (e.g., 'Engineering')
            filter_type: Group filter (e.g., 'type eq "OKTA_GROUP"')
            name: Filter by exact group name
            type: Filter by group type (OKTA_GROUP, APP_GROUP, etc.)
            after: Pagination cursor
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing groups and pagination information
        """
        try:
            limit = 200
            
            if ctx:
                ctx.info(f"Listing groups with parameters: query={query}, filter={filter_type}, name={name}, type={type}")
            
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
            
            if ctx:
                ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_groups(params)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups: {err}")
                if ctx:
                    ctx.error(f"Error listing groups: {err}")
                return handle_okta_result(err, "list_groups")
            
            # Apply pagination
            if ctx:
                ctx.info("Retrieving paginated results...")
            
            all_groups = []
            page_count = 0
            
            # Process first page
            if groups:
                all_groups.extend(groups)
                page_count += 1
                if ctx:
                    ctx.info(f"Retrieved {len(groups)} groups")
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.list_groups_next(resp)
                groups, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        ctx.error(f"Error during pagination: {err}")
                    break
                
                if groups:
                    all_groups.extend(groups)
                    page_count += 1
                    if ctx:
                        ctx.info(f"Retrieved {len(groups)} additional groups")
            
            if ctx:
                ctx.info(f"Retrieved {len(all_groups)} groups across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "groups": [group.as_dict() for group in all_groups],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_groups),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_groups tool")
            if ctx:
                ctx.error(f"Error in list_groups tool: {str(e)}")
            return handle_okta_result(e, "list_groups")
    
    @server.tool()
    async def get_group(group_id: str, ctx: Context = None) -> Dict[str, Any]:
        """Get detailed information about a specific Okta group.
        
        Args:
            group_id: The ID of the group to retrieve
            ctx: MCP Context for logging
            
        Returns:
            Dictionary containing detailed group information
        """
        try:
            if ctx:
                ctx.info(f"Getting detailed information for group: {group_id}")
            
            # Get the group by ID
            raw_response = await okta_client.client.get_group(group_id)
            group, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting group {group_id}: {err}")
                if ctx:
                    ctx.error(f"Error getting group {group_id}: {err}")
                return handle_okta_result(err, "get_group")
            
            if ctx:
                ctx.info(f"Successfully retrieved group information")
            
            # Format response
            result = group.as_dict()
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in get_group tool for group_id {group_id}")
            if ctx:
                ctx.error(f"Error in get_group tool: {str(e)}")
            return handle_okta_result(e, "get_group")
    
    @server.tool()
    async def list_group_members(
        group_id: str,
        after: str = None,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all members of a specific Okta group. 
        
        Args:
            group_id: The ID of the group
            after: Pagination cursor
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing group members and pagination information
        """
        try:
            limit = 200
            
            if ctx:
                ctx.info(f"Listing members of group: {group_id}")
            
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if after:
                params['after'] = after
            
            if ctx:
                ctx.info(f"Executing Okta API request for group members")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_group_users(group_id, params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing group members for group {group_id}: {err}")
                if ctx:
                    ctx.error(f"Error listing group members: {err}")
                return handle_okta_result(err, "list_group_users")
            
            # Apply pagination
            if ctx:
                ctx.info("Retrieving paginated results...")
            
            all_users = []
            page_count = 0
            
            # Process first page
            if users:
                all_users.extend(users)
                page_count += 1
                if ctx:
                    ctx.info(f"Retrieved {len(users)} members")
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.list_group_users_next(resp)
                users, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        ctx.error(f"Error during pagination: {err}")
                    break
                
                if users:
                    all_users.extend(users)
                    page_count += 1
                    if ctx:
                        ctx.info(f"Retrieved {len(users)} additional members")
            
            if ctx:
                ctx.info(f"Retrieved {len(all_users)} total members across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "members": [user.as_dict() for user in all_users],
                "group_id": group_id,
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
            logger.exception(f"Error in list_group_members tool for group_id {group_id}")
            if ctx:
                ctx.error(f"Error in list_group_members tool: {str(e)}")
            return handle_okta_result(e, "list_group_members")
        
    @server.tool()
    async def list_assigned_applications_for_group(
        group_id: str,
        after: str = None,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all applications assigned to a specific Okta group.
        
        Args:
            group_id: The ID of the group
            after: Pagination cursor
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing applications and pagination information
        """
        try:
            limit = 200
            
            if ctx:
                ctx.info(f"Listing applications assigned to group: {group_id}")
            
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if after:
                params['after'] = after
            
            if ctx:
                ctx.info(f"Executing Okta API request for group applications")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_assigned_applications_for_group(group_id, params)
            apps, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing applications for group {group_id}: {err}")
                if ctx:
                    ctx.error(f"Error listing applications: {err}")
                return handle_okta_result(err, "list_assigned_applications")
            
            # Apply pagination
            if ctx:
                ctx.info("Retrieving paginated results...")
            
            all_apps = []
            page_count = 0
            
            # Process first page
            if apps:
                all_apps.extend(apps)
                page_count += 1
                if ctx:
                    ctx.info(f"Retrieved {len(apps)} applications")
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate
                
                raw_response = await okta_client.client.list_assigned_applications_for_group_next(resp)
                apps, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        ctx.error(f"Error during pagination: {err}")
                    break
                
                if apps:
                    all_apps.extend(apps)
                    page_count += 1
                    if ctx:
                        ctx.info(f"Retrieved {len(apps)} additional applications")
            
            if ctx:
                ctx.info(f"Retrieved {len(all_apps)} total applications across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "applications": [app.as_dict() for app in all_apps],
                "group_id": group_id,
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_apps),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_assigned_applications tool for group_id {group_id}")
            if ctx:
                ctx.error(f"Error in list_assigned_applications tool: {str(e)}")
            return handle_okta_result(e, "list_assigned_applications")
    
    logger.info("Registered group management tools")