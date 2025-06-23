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
        search: str = Field(default="", description="Okta expression to filter applications"),
        max_results: int = Field(default=50, ge=1, le=100, description="Maximum applications to return (1-100)"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta applications with filtering - limited to 50 apps by default for context efficiency.
        
        IMPORTANT LIMITATION: Returns only first 50 applications by default (max 100) to stay within 
        LLM context limits. Use specific search filters to find the applications you need.
        
        Search Parameter:
        Uses Okta expression language to filter applications with operators:
        • eq (equals), ne (not equals), co (contains), sw (starts with), ew (ends with)
        • pr (present), gt (greater than), lt (less than), ge (>=), le (<=)
        
        Common Application Filters:
        • profile.name co "Slack" - Applications containing "Slack" in name
        • status eq "ACTIVE" - Only active applications
        • status eq "INACTIVE" - Only inactive applications
        • signOnMode eq "SAML_2_0" - SAML applications only
        • signOnMode eq "OPENID_CONNECT" - OIDC applications only
        • profile.label sw "Test" - Applications with labels starting with "Test"
        • lastUpdated gt "2024-01-01T00:00:00.000Z" - Recently updated applications
        
        Application Sign-On Modes:
        • BOOKMARK, BASIC_AUTH, BROWSER_PLUGIN, SECURE_PASSWORD_STORE
        • SAML_2_0, WS_FEDERATION, OPENID_CONNECT, AUTO_LOGIN
        
        Examples:
        • 'profile.name co "Office"' - Find Office 365 or similar apps
        • 'status eq "ACTIVE" and signOnMode eq "SAML_2_0"' - Active SAML apps
        • 'profile.label sw "Prod"' - Production environment apps
        
        Use search filters to find specific applications rather than browsing all apps.
        Returns application details including ID, name, label, status, and sign-on configuration.
        """
        try:
            # Validate max_results parameter
            if max_results < 1 or max_results > 100:
                raise ValueError("max_results must be between 1 and 100")
            
            if ctx:
                logger.info(f"SERVER: Executing list_okta_applications with search={search}, max_results={max_results}")
            
            # Prepare request parameters
            params = {'limit': min(max_results, 100)}
            
            if search:
                params['search'] = search
            
            if ctx:
                logger.info(f"Executing Okta API request with params: {params}")
                await ctx.report_progress(25, 100)
            
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
        """Get detailed information about a specific Okta application.
        
        Returns comprehensive application details including:
        • Basic information: name, label, status, description
        • Sign-on configuration: mode, credentials, authentication settings
        • User assignment settings and policies
        • Group assignment configuration
        • Application-specific settings and features
        • Provisioning configuration (if applicable)
        • Application URLs and endpoints
        • Custom attributes and profile mappings
        
        Application Status Values:
        • ACTIVE - Application is active and available to users
        • INACTIVE - Application is disabled and not available
        
        Sign-On Modes:
        • SAML_2_0 - SAML 2.0 federation
        • OPENID_CONNECT - OpenID Connect/OAuth 2.0
        • SECURE_PASSWORD_STORE - Password-based with secure storage
        • AUTO_LOGIN - Automatic login with stored credentials
        • BOOKMARK - Simple bookmark/link application
        • BASIC_AUTH - HTTP Basic Authentication
        • BROWSER_PLUGIN - Browser plugin required
        • WS_FEDERATION - WS-Federation protocol
        
        Use this tool to get complete application configuration details for troubleshooting,
        auditing, or configuration review purposes.
        """
        try:
            if ctx:
                logger.info(f"SERVER: Executing get_okta_application for app_id: {app_id}")
            
            # Validate input
            if not app_id or not app_id.strip():
                raise ValueError("app_id cannot be empty")
            
            app_id = app_id.strip()
            
            if ctx:
                await ctx.report_progress(25, 100)
            
            # Get the application by ID
            raw_response = await okta_client.client.get_application(app_id)
            app, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting application {app_id}: {err}")
                return handle_okta_result(err, "get_application")
            
            if ctx:
                logger.info(f"Successfully retrieved application information")
                await ctx.report_progress(100, 100)
            
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
        """List all users assigned to a specific Okta application with full pagination.
        
        Returns complete list of all users assigned to the application including:
        • User profile information (ID, email, name, status)
        • Assignment details (scope, credentials, profile)
        • Assignment timestamps and metadata
        • Application-specific user attributes
        • User status within the application context
        
        Assignment Types:
        • Direct assignment - User assigned directly to application
        • Group assignment - User assigned via group membership
        • Rule-based assignment - User assigned via assignment rules
        
        User Assignment Status:
        • PROVISIONED - User is provisioned and active in application
        • STAGED_FOR_PROVISIONING - User staged for provisioning
        • DEPROVISIONED - User removed from application
        • SUSPENDED - User temporarily suspended in application
        
        This tool uses full pagination to return ALL assigned users, which may take longer
        for applications with many users but ensures complete data for compliance and auditing.
        
        Use for application access reviews, user assignment audits, and troubleshooting
        user access issues.
        """
        try:
            if ctx:
                logger.info(f"SERVER: Executing list_okta_application_users for app_id: {app_id}")
            
            # Validate input
            if not app_id or not app_id.strip():
                raise ValueError("app_id cannot be empty")
            
            app_id = app_id.strip()
            
            # Prepare request parameters
            params = {'limit': 200}
            
            if ctx:
                logger.info(f"Executing Okta API request for application users")
                await ctx.report_progress(20, 100)
            
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
                    await ctx.report_progress(min(20 + (page_count * 15), 90), 100)
                
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
        """List all groups assigned to a specific Okta application with full pagination.
        
        Returns complete list of all groups assigned to the application including:
        • Group information (ID, name, description, type)
        • Assignment details and configuration
        • Group assignment scope and permissions
        • Application-specific group attributes
        • Assignment timestamps and metadata
        
        Group Assignment Types:
        • Direct assignment - Group explicitly assigned to application
        • Inherited assignment - Group assigned via policy or rule
        
        Group Types:
        • OKTA_GROUP - Standard Okta group
        • APP_GROUP - Application-imported group
        • BUILT_IN - Built-in Okta group (Everyone, etc.)
        
        Assignment Scope:
        • USER - Group assignment applies to user access
        • GROUP - Group assignment for group-level permissions
        
        This tool uses full pagination to return ALL assigned groups, ensuring complete
        visibility into group-based application access for security reviews and auditing.
        
        Use for application access governance, group assignment reviews, and troubleshooting
        group-based access issues.
        """
        try:
            if ctx:
                logger.info(f"SERVER: Executing list_okta_application_groups for app_id: {app_id}")
            
            # Validate input
            if not app_id or not app_id.strip():
                raise ValueError("app_id cannot be empty")
            
            app_id = app_id.strip()
            
            # Prepare request parameters
            params = {'limit': 200}
            
            if ctx:
                logger.info(f"Executing Okta API request for application groups")
                await ctx.report_progress(20, 100)
            
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
                    await ctx.report_progress(min(20 + (page_count * 15), 90), 100)
                
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