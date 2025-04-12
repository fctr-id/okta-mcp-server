"""Group management tools for Okta MCP server."""

import logging
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
import asyncio
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
    async def list_okta_groups(
        search: str = None,
        after: str = None,
        limit: int = 200,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta groups with various filtering options. The search parameter supports the following operators and these can be applied id, type, lastUpdated, lastMembershipUpdated, create and profile.attributes(ex: profile.name and not just name):
          The search can be combined with multiple criteria , for example: search=type eq "APP_GROUP" and (created lt "2014-01-01T00:00:00.000Z" and source.id eq "0oa2v0el0gP90aqjJ0g7"). Dates are in ISO 8601 format
          eq (equals), ne (not equals), co (contains), sw (starts with), ew (ends with), pr (present - has value or null), gt (greater than), (less than), ge (greater than or equal to date), lt(less than data) 
          Do NOT use 'eq' for dates, use 'lt' or 'gt' instead and be generous with times
        
        Args:
            search: Okta expression to filter groups using Okta Expression Language.
            after: Pagination cursor for retrieving additional pages
            limit: Maximum number of results per page (1-200)
            ctx: MCP Context for progress reporting and logging
                
        Returns:
            Dictionary containing groups and pagination information
        """
        try:
            # Validate parameters
            limit = min(max(1, limit), 200)
            
            if ctx:
                await ctx.info(f"Listing groups with parameters: search={search}, limit={limit}")
            
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            # Add search parameter if provided
            if search:
                params['search'] = search
                
            if after:
                params['after'] = after
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_groups(params)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups: {err}")
                if ctx:
                    await ctx.error(f"Error CTX listing groups: {err}")
                return handle_okta_result(err, "list_groups")
            
            # Apply pagination
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_groups = []
            page_count = 0
            
            while True:
                # Process current page
                if groups:
                    all_groups.extend(groups)
                    page_count += 1
                    
                    if ctx:
                        await ctx.info(f"Page {page_count}: Retrieved {len(groups)} groups (total: {len(all_groups)})")
                
                if resp and resp.has_next():
                    if ctx:
                        await ctx.info("Getting next page...")
                    
                    # Get next page with small delay to prevent rate limiting
                    await asyncio.sleep(0.2)
                    groups, err = await resp.next()
                    
                    if err:
                        if ctx:
                            await ctx.error(f"Error getting next page: {err}")
                        break
                else:
                    if ctx:
                        await ctx.info("No more pages available.")
                    break
            
            if ctx:
                await ctx.info(f"Pagination complete. Retrieved {len(all_groups)} total groups in {page_count} pages.")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with pagination info
            result = {
                "groups": [group.as_dict() for group in all_groups],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_groups),
                    "has_more": False  # We've already processed all pages
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_groups tool")
            if ctx:
                await ctx.error(f"Error in list_groups tool: {str(e)}")
            return handle_okta_result(e, "list_groups")
    
    @server.tool()
    async def get_okta_group(group_id: str, ctx: Context = None) -> Dict[str, Any]:
        """Get detailed information about a specific Okta group.
        
        Args:
            group_id: The ID of the group to retrieve
            ctx: MCP Context for logging
            
        Returns:
            Dictionary containing detailed group information
        """
        try:
            if ctx:
                await ctx.info(f"Getting detailed information for group: {group_id}")
            
            # Get the group by ID
            raw_response = await okta_client.client.get_group(group_id)
            group, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting group {group_id}: {err}")
                if ctx:
                    await ctx.error(f"Error getting group {group_id}: {err}")
                return handle_okta_result(err, "get_group")
            
            if ctx:
                await ctx.info(f"Successfully retrieved group information")
            
            # Format response
            result = group.as_dict()
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in get_group tool for group_id {group_id}")
            if ctx:
                await ctx.error(f"Error in get_group tool: {str(e)}")
            return handle_okta_result(e, "get_group")
    
    @server.tool()
    async def list_okta_group_members(
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
                await ctx.info(f"Listing members of group: {group_id}")
            
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
                await ctx.info(f"Executing Okta API request for group members")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_group_users(group_id, params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing group members for group {group_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing group members: {err}")
                return handle_okta_result(err, "list_group_users")
            
            # Apply pagination
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_users = []
            page_count = 0
            
            while True:
                # Process current page
                if users:
                    all_users.extend(users)
                    page_count += 1
                    
                    if ctx:
                        await ctx.info(f"Page {page_count}: Retrieved {len(users)} members (total: {len(all_users)})")
                
                if resp and resp.has_next():
                    if ctx:
                        await ctx.info("Getting next page...")
                    
                    # Get next page with small delay to prevent rate limiting
                    await asyncio.sleep(0.2)
                    users, err = await resp.next()
                    
                    if err:
                        if ctx:
                            await ctx.error(f"Error getting next page: {err}")
                        break
                else:
                    if ctx:
                        await ctx.info("No more pages available.")
                    break
            
            if ctx:
                await ctx.info(f"Pagination complete. Retrieved {len(all_users)} total members in {page_count} pages.")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with pagination info
            result = {
                "members": [user.as_dict() for user in all_users],
                "group_id": group_id,
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_users),
                    "has_more": False  # We've already processed all pages
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_group_members tool for group_id {group_id}")
            if ctx:
                await ctx.error(f"Error in list_group_members tool: {str(e)}")
            return handle_okta_result(e, "list_group_members")
        
    @server.tool()
    async def list_okta_assigned_applications_for_group(
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
                await ctx.info(f"Listing applications assigned to group: {group_id}")
            
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
                await ctx.info(f"Executing Okta API request for group applications")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_assigned_applications_for_group(group_id, params)
            apps, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing applications for group {group_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing applications: {err}")
                return handle_okta_result(err, "list_assigned_applications")
            
            # Apply pagination
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_apps = []
            page_count = 0
            
            while True:
                # Process current page
                if apps:
                    all_apps.extend(apps)
                    page_count += 1
                    
                    if ctx:
                        await ctx.info(f"Page {page_count}: Retrieved {len(apps)} applications (total: {len(all_apps)})")
                
                if resp and resp.has_next():
                    if ctx:
                        await ctx.info("Getting next page...")
                    
                    # Get next page with small delay to prevent rate limiting
                    await asyncio.sleep(0.2)
                    apps, err = await resp.next()
                    
                    if err:
                        if ctx:
                            await ctx.error(f"Error getting next page: {err}")
                        break
                else:
                    if ctx:
                        await ctx.info("No more pages available.")
                    break
            
            if ctx:
                await ctx.info(f"Pagination complete. Retrieved {len(all_apps)} total applications in {page_count} pages.")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with pagination info
            result = {
                "applications": [app.as_dict() for app in all_apps],
                "group_id": group_id,
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_apps),
                    "has_more": False  # We've already processed all pages
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_assigned_applications tool for group_id {group_id}")
            if ctx:
                await ctx.error(f"Error in list_assigned_applications tool: {str(e)}")
            return handle_okta_result(e, "list_assigned_applications")
    
    #logger.info("Registered group management tools")