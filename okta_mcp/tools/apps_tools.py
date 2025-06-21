"""Application management tools for Okta MCP server."""

import logging
import anyio
from typing import List, Dict, Any, Optional
from fastmcp import FastMCP, Context
from pydantic import Field
import asyncio
from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

logger = logging.getLogger("okta_mcp_server")

def register_apps_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all application-related tools with the MCP server."""
    
    @server.tool()
    async def list_okta_applications(
        search: str = Field(default="", description="Okta expression to filter applications using operators: eq, ne, co, sw, ew, pr, gt, lt, ge"),
        max_results: int = Field(default=50, description="Maximum applications to return (1-100). Limited for LLM context window."),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta applications with filtering - limited to 50 apps by default for context efficiency. Use search filters like 'profile.name co \"Slack\"' or 'status eq \"ACTIVE\"' to find specific applications."""
        try:
            # Validate max_results parameter
            if max_results < 1 or max_results > 100:
                raise ValueError("max_results must be between 1 and 100")
            
            if ctx:
                logger.info(f"Listing applications with search={search}, max_results={max_results}")
            
            # Prepare request parameters
            params = {'limit': min(max_results, 100)}
            
            if search:
                params['search'] = search
            
            if ctx:
                logger.info(f"Executing Okta API request with params: {params}")
            
            # Execute single Okta API request (no pagination)
            raw_response = await okta_client.client.list_applications(params)
            apps, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing applications: {err}")
                return handle_okta_result(err, "list_applications")
            
            # Get apps up to max_results limit
            all_apps = apps[:max_results] if apps else []
            
            if ctx:
                logger.info(f"Retrieved {len(all_apps)} applications (limited to {max_results})")
                await ctx.report_progress(100, 100)
            
            # Determine if there are more results available
            has_more = resp and resp.has_next() and len(apps) == params['limit']
            
            # Format and return results
            result = {
                "applications": [app.as_dict() for app in all_apps],
                "summary": {
                    "returned_count": len(all_apps),
                    "max_requested": max_results,
                    "context_limited": True
                }
            }
            
            # Add helpful messaging
            if has_more:
                result["message"] = (
                    f"Showing first {len(all_apps)} applications (limited for LLM context). "
                    f"Use search filters like 'profile.name co \"Slack\"' to find specific apps."
                )
            elif len(all_apps) == 0:
                result["message"] = (
                    "No applications found. Try broader search criteria or check your filters."
                )
            else:
                result["message"] = f"Found {len(all_apps)} applications matching your criteria."
            
            return result
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_applications. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_applications")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_applications'
                }
            
            logger.exception("Error in list_applications tool")
            return handle_okta_result(e, "list_applications")
    
    @server.tool()
    async def get_okta_application(
        app_id: str = Field(..., description="The ID of the application to retrieve"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get detailed information about a specific Okta application."""
        try:
            if ctx:
                logger.info(f"Getting detailed information for application: {app_id}")
            
            # Validate input
            if not app_id or not app_id.strip():
                raise ValueError("app_id cannot be empty")
            
            app_id = app_id.strip()
            
            # Get the application by ID
            raw_response = await okta_client.client.get_application(app_id)
            app, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting application {app_id}: {err}")
                return handle_okta_result(err, "get_application")
            
            if ctx:
                logger.info(f"Successfully retrieved application information")
            
            return app.as_dict()
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during get_okta_application. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in get_okta_application")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'get_okta_application'
                }
            
            logger.exception(f"Error in get_application tool for app_id {app_id}")
            return handle_okta_result(e, "get_application")
    
    @server.tool()
    async def list_okta_application_users(
        app_id: str = Field(..., description="The ID of the application"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all users assigned to a specific Okta application with full pagination for complete results."""
        try:
            if ctx:
                logger.info(f"Listing users assigned to application: {app_id}")
            
            # Validate input
            if not app_id or not app_id.strip():
                raise ValueError("app_id cannot be empty")
            
            app_id = app_id.strip()
            
            # Prepare request parameters
            params = {'limit': 200}
            
            if ctx:
                logger.info(f"Executing Okta API request for application users")
            
            # Execute Okta API request with full pagination
            raw_response = await okta_client.client.list_application_users(app_id, params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing users for application {app_id}: {err}")
                return handle_okta_result(err, "list_application_users")
            
            # Apply full pagination for complete results
            all_users = users if users else []
            page_count = 1
            
            while resp and resp.has_next():
                if ctx:
                    logger.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count * 10, 100)
                
                try:
                    await asyncio.sleep(0.2)  # Rate limit protection
                    users_page, err = await resp.next()
                    
                    if err:
                        if ctx:
                            logger.error(f"Error during pagination: {err}")
                        break
                    
                    if users_page:
                        all_users.extend(users_page)
                        page_count += 1
                        
                        # Safety check
                        if page_count > 50:
                            if ctx:
                                logger.warning("Reached maximum page limit (50), stopping")
                            break
                    else:
                        break
                        
                except Exception as pagination_error:
                    if ctx:
                        logger.error(f"Pagination error: {pagination_error}")
                    break
            
            if ctx:
                logger.info(f"Retrieved {len(all_users)} total users in {page_count} pages")
                await ctx.report_progress(100, 100)
            
            return {
                "users": [user.as_dict() for user in all_users],
                "application_id": app_id,
                "pagination": {
                    "total_pages": page_count,
                    "total_results": len(all_users)
                }
            }
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_application_users. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_application_users")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_application_users'
                }
            
            logger.exception(f"Error in list_application_users tool for app_id {app_id}")
            return handle_okta_result(e, "list_application_users")
        
    @server.tool()
    async def list_okta_application_groups(
        app_id: str = Field(..., description="The ID of the application"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all groups assigned to a specific Okta application with full pagination for complete results."""
        try:
            if ctx:
                logger.info(f"Listing groups assigned to application: {app_id}")
            
            # Validate input
            if not app_id or not app_id.strip():
                raise ValueError("app_id cannot be empty")
            
            app_id = app_id.strip()
            
            # Prepare request parameters
            params = {'limit': 200}
            
            if ctx:
                logger.info(f"Executing Okta API request for application groups")
            
            # Execute Okta API request with full pagination
            raw_response = await okta_client.client.list_application_group_assignments(app_id, params)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups for application {app_id}: {err}")
                return handle_okta_result(err, "list_application_group_assignments")
            
            # Apply full pagination for complete results
            all_groups = groups if groups else []
            page_count = 1
            
            while resp and resp.has_next():
                if ctx:
                    logger.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count * 10, 100)
                
                try:
                    await asyncio.sleep(0.2)  # Rate limit protection
                    groups_page, err = await resp.next()
                    
                    if err:
                        if ctx:
                            logger.error(f"Error during pagination: {err}")
                        break
                    
                    if groups_page:
                        all_groups.extend(groups_page)
                        page_count += 1
                        
                        # Safety check
                        if page_count > 50:
                            if ctx:
                                logger.warning("Reached maximum page limit (50), stopping")
                            break
                    else:
                        break
                        
                except Exception as pagination_error:
                    if ctx:
                        logger.error(f"Pagination error: {pagination_error}")
                    break
            
            if ctx:
                logger.info(f"Retrieved {len(all_groups)} total groups in {page_count} pages")
                await ctx.report_progress(100, 100)
            
            return {
                "groups": [group.as_dict() for group in all_groups],
                "application_id": app_id,
                "pagination": {
                    "total_pages": page_count,
                    "total_results": len(all_groups)
                }
            }
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_application_groups. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_application_groups")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_application_groups'
                }
            
            logger.exception(f"Error in list_application_groups tool for app_id {app_id}")
            return handle_okta_result(e, "list_application_group_assignments")