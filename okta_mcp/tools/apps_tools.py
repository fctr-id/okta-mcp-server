"""Application management tools for Okta MCP server."""

import logging
from typing import Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

logger = logging.getLogger("okta_mcp_server")

def register_application_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all application-related tools with the MCP server.
    
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def list_okta_applications(
        q: str = None,
        filter_string: str = None,
        after: str = None,
        expand: str = None,
        include_non_deleted: bool = None,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta applications with various filtering options or get a specific application by ID.
        All application objects in the response include complete nested properties that can be accessed using 
        standard JSON path notation:
        Examples of important nested properties:
        - Credentials signing key ID: credentials.signing.kid
        - Access Policy ID: The last part of the URL in _links.accessPolicy.href
        - Profile Enrollment Policy ID: The last part of the URL in _links.profileEnrollment.href
        - SAML settings: settings.signOn.attributeStatements
        
        Args:
            q: Search term for application name
            filter_string: Filter expression for applications 
            after: Pagination cursor
            expand: Embedded resources to expand in the response
            include_non_deleted: Include non-deleted applications
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing applications and pagination information
        """
        try:
            limit = 200
            
            if ctx:
                await ctx.info(f"Listing applications with parameters: q={q}, filter={filter_string}")
            
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if q:
                params['q'] = q
                
            if filter_string:
                params['filter'] = filter_string
                    
            if after:
                params['after'] = after
                
            if expand:
                params['expand'] = expand
                
            if include_non_deleted is not None:
                params['includeNonDeleted'] = str(include_non_deleted).lower()
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_applications(params)
            applications, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing applications: {err}")
                if ctx:
                    await ctx.error(f"Error listing applications: {err}")
                return handle_okta_result(err, "list_applications")
            
            # Apply pagination based on environment variable
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_applications = []
            page_count = 0
            
            # Process first page
            if applications:
                all_applications.extend(applications)
                page_count += 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.get_next_page(resp)
                applications, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        await ctx.error(f"Error during pagination: {err}")
                    break
                
                if applications:
                    all_applications.extend(applications)
                    page_count += 1
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_applications)} applications across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "applications": [app.as_dict() for app in all_applications],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_applications),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_applications tool")
            if ctx:
                await ctx.error(f"Error in list_applications tool: {str(e)}")
            return handle_okta_result(e, "list_applications")
    
    @server.tool()
    async def list_okta_application_users(
        application_id: str,
        limit: int = 200,
        after: str = None,
        expand: str = None,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List users assigned to a specific Okta application.
        
        Args:
            application_id: ID of the application to list users for
            limit: Number of results to return (1-200)
            after: Pagination cursor
            expand: Embedded resources to expand in the response
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing application users and pagination information
        """
        try:
            if ctx:
                await ctx.info(f"Listing users for application ID: {application_id}")
            
            # Validate parameters
            if not application_id:
                raise ValueError("Application ID is required")
                
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
                
            if after:
                params['after'] = after
                
            if expand:
                params['expand'] = expand
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_application_users(application_id, params)
            app_users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing application users: {err}")
                if ctx:
                    await ctx.error(f"Error listing application users: {err}")
                return handle_okta_result(err, "list_application_users")
            
            # Apply pagination
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_app_users = []
            page_count = 0
            
            # Process first page
            if app_users:
                all_app_users.extend(app_users)
                page_count += 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.get_next_page(resp)
                app_users, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        await ctx.error(f"Error during pagination: {err}")
                    break
                
                if app_users:
                    all_app_users.extend(app_users)
                    page_count += 1
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_app_users)} application users across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "application_users": [user.as_dict() for user in all_app_users],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_app_users),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_application_users tool")
            if ctx:
                await ctx.error(f"Error in list_application_users tool: {str(e)}")
            return handle_okta_result(e, "list_application_users")
        
    @server.tool()
    async def list_okta_application_group_assignments(
        application_id: str,
        limit: int = 200,
        after: str = None,
        expand: str = None,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List groups assigned to a specific Okta application. Fetch the group name once you have the group id using get_group tool
        
        All group assignment objects in the response include complete nested properties that can be accessed using 
        standard JSON path notation. Important properties include the group profile, assignment details,
        and application-specific settings.
        
        Args:
            application_id: ID of the application to list group assignments for
            limit: Number of results to return (1-200)
            after: Pagination cursor
            expand: Embedded resources to expand in the response
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing group assignments and pagination information
        """
        try:
            if ctx:
                await ctx.info(f"Listing group assignments for application ID: {application_id}")
            
            # Validate parameters
            if not application_id:
                raise ValueError("Application ID is required")
                
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
                
            if after:
                params['after'] = after
                
            if expand:
                params['expand'] = expand
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_application_group_assignments(application_id, params)
            app_groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing application group assignments: {err}")
                if ctx:
                    await ctx.error(f"Error listing application group assignments: {err}")
                return handle_okta_result(err, "list_application_group_assignments")
            
            # Apply pagination
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_app_groups = []
            page_count = 0
            
            # Process first page
            if app_groups:
                all_app_groups.extend(app_groups)
                page_count += 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.get_next_page(resp)
                app_groups, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        await ctx.error(f"Error during pagination: {err}")
                    break
                
                if app_groups:
                    all_app_groups.extend(app_groups)
                    page_count += 1
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_app_groups)} application group assignments across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "application_groups": [group.as_dict() for group in all_app_groups],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_app_groups),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in list_application_group_assignments tool")
            if ctx:
                await ctx.error(f"Error in list_application_group_assignments tool: {str(e)}")
            return handle_okta_result(e, "list_application_group_assignments")        

    
    #logger.info("Registered application management tools")