"""Application management tools for Okta MCP server."""

import logging
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
import asyncio
from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

logger = logging.getLogger("okta_mcp_server")

def register_apps_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all application-related tools with the MCP server.
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def list_okta_applications(
        search: str = None,
        after: str = None,
        limit: int = 200,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta applications with various filtering options. The search parameter supports the following operators and these can be applied id, type, lastUpdated, lastMembershipUpdated, create and profile.attributes(ex: profile.name and not just name):
          The search can be combined with multiple criteria , for example: search=type eq "APP_GROUP" and (created lt "2014-01-01T00:00:00.000Z" and source.id eq "0oa2v0el0gP90aqjJ0g7"). Dates are in ISO 8601 format
          eq (equals), ne (not equals), co (contains), sw (starts with), ew (ends with), pr (present - has value or null), gt (greater than), (less than), ge (greater than or equal to date), lt(less than data) 
          Do NOT use 'eq' for dates, use 'lt' or 'gt' instead and be generous with times
        
        Args:
            search: Okta expression to filter applications using Okta Expression Language.
            after: Pagination cursor for retrieving additional pages
            limit: Maximum number of results per page (1-200)
            ctx: MCP Context for progress reporting and logging
                
        Returns:
            Dictionary containing applications and pagination information
        """
        try:
            # Validate parameters
            limit = min(max(1, limit), 200)
            
            if ctx:
                await ctx.info(f"Listing applications with parameters: search={search}, limit={limit}")
            
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
            raw_response = await okta_client.client.list_applications(params)
            apps, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing applications: {err}")
                if ctx:
                    await ctx.error(f"Error CTX listing applications: {err}")
                return handle_okta_result(err, "list_applications")
            
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
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_apps),
                    "has_more": False  # We've already processed all pages
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_applications tool")
            if ctx:
                await ctx.error(f"Error in list_applications tool: {str(e)}")
            return handle_okta_result(e, "list_applications")
    
    @server.tool()
    async def get_okta_application(app_id: str, ctx: Context = None) -> Dict[str, Any]:
        """Get detailed information about a specific Okta application.
        
        Args:
            app_id: The ID of the application to retrieve
            ctx: MCP Context for logging
            
        Returns:
            Dictionary containing detailed application information
        """
        try:
            if ctx:
                await ctx.info(f"Getting detailed information for application: {app_id}")
            
            # Get the application by ID
            raw_response = await okta_client.client.get_application(app_id)
            app, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting application {app_id}: {err}")
                if ctx:
                    await ctx.error(f"Error getting application {app_id}: {err}")
                return handle_okta_result(err, "get_application")
            
            if ctx:
                await ctx.info(f"Successfully retrieved application information")
            
            # Format response
            result = app.as_dict()
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in get_application tool for app_id {app_id}")
            if ctx:
                await ctx.error(f"Error in get_application tool: {str(e)}")
            return handle_okta_result(e, "get_application")
    
    @server.tool()
    async def list_okta_application_users(
        app_id: str,
        after: str = None,
        limit: int = 200,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all users assigned to a specific Okta application.
        
        Args:
            app_id: The ID of the application
            after: Pagination cursor
            limit: Maximum number of results per page (1-200)
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing assigned users and pagination information
        """
        try:
            # Validate parameters
            limit = min(max(1, limit), 200)
            
            if ctx:
                await ctx.info(f"Listing users assigned to application: {app_id}, limit={limit}")
            
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if after:
                params['after'] = after
            
            if ctx:
                await ctx.info(f"Executing Okta API request for application users")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_application_users(app_id, params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing users for application {app_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing application users: {err}")
                return handle_okta_result(err, "list_application_users")
            
            # Apply pagination (using the pattern from list_okta_groups)
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
                        await ctx.info(f"Page {page_count}: Retrieved {len(users)} users (total: {len(all_users)})")
                
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
                await ctx.info(f"Pagination complete. Retrieved {len(all_users)} total users in {page_count} pages.")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with pagination info
            result = {
                "users": [user.as_dict() for user in all_users],
                "application_id": app_id,
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_users),
                    "has_more": False  # We've already processed all pages
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_application_users tool for app_id {app_id}")
            if ctx:
                await ctx.error(f"Error in list_application_users tool: {str(e)}")
            return handle_okta_result(e, "list_application_users")
        
    @server.tool()
    async def list_okta_application_groups(
        app_id: str,
        after: str = None,
        limit: int = 200,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all groups assigned to a specific Okta application.
        
        Args:
            app_id: The ID of the application
            after: Pagination cursor
            limit: Maximum number of results per page (1-200)
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing assigned groups and pagination information
        """
        try:
            # Validate parameters
            limit = min(max(1, limit), 200)
            
            if ctx:
                await ctx.info(f"Listing groups assigned to application: {app_id}, limit={limit}")
            
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if after:
                params['after'] = after
            
            if ctx:
                await ctx.info(f"Executing Okta API request for application groups")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_application_group_assignments(app_id, params)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups for application {app_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing application groups: {err}")
                return handle_okta_result(err, "list_application_group_assignments")
            
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
                "application_id": app_id,
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_groups),
                    "has_more": False  # We've already processed all pages
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_application_groups tool for app_id {app_id}")
            if ctx:
                await ctx.error(f"Error in list_application_groups tool: {str(e)}")
            return handle_okta_result(e, "list_application_group_assignments")
    
    #logger.info("Registered application management tools")