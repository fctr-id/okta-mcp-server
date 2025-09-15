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
        q: str = Field(default="", description="Searches for apps with name or label properties that start with the q value"),
        filter: str = Field(default="", description="Filters apps by status, user.id, group.id, credentials.signing.kid or name"),
        limit: int = Field(default=50, ge=1, le=200, description="Maximum applications to return (1-200)"),
        after: str = Field(default="", description="Pagination cursor for the next page of results"),
        use_optimization: bool = Field(default=False, description="Use query optimization for subset of app properties"),
        include_non_deleted: bool = Field(default=False, description="Include non-active, but not deleted apps"),
        expand: str = Field(default="", description="Link expansion to embed more resources (supports expand=user/{userId})"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all applications in the Okta organization with pagination and filtering.
        
        OAuth 2.0 scopes: okta.apps.read
        
        Lists all apps in the org with pagination. A subset of apps can be returned that match 
        a supported filter expression or query. The results are paginated according to the 
        limit parameter. If there are multiple pages of results, the header contains a next link.
        
        Note: To list all of a member's assigned app links, use the List all assigned app 
        links endpoint in the User Resources API.
        
        Query Parameters:
        
        q (string): Searches for apps with name or label properties that starts with the q 
        value using the startsWith operation.
        Example: q=Okta
        
        filter (string): Filters apps by status, user.id, group.id, credentials.signing.kid 
        or name expression that supports the eq operator.
        
        Filter Examples:
        • Filter for active apps: status eq "ACTIVE"
        • Filter for apps with specific name: name eq "okta_org2org"
        • Filter for apps using a specific key: credentials.signing.kid eq "SIMcCQNY3uwXoW3y0vf6VxiBb5n9pf8L2fK8d-F1bm4"
        • Filter by user assignment: user.id eq "00u1emaK22p5pX0123d7"
        • Filter by group assignment: group.id eq "00g1emaK22p5pX0123d7"
        
        limit (integer): Specifies the number of results per page (max 200, default -1 for all)
        
        after (string): Specifies the pagination cursor for the next page of results. 
        Treat this as an opaque value obtained through the next link relationship.
        
        use_optimization (boolean): Specifies whether to use query optimization. If true, 
        the response contains a subset of app instance properties for better performance.
        
        include_non_deleted (boolean): Specifies whether to include non-active, but not 
        deleted apps in the results.
        
        expand (string): An optional parameter for link expansion to embed more resources 
        in the response. Only supports expand=user/{userId} and must be used with the 
        user.id eq "{userId}" filter query for the same user.
        
        Application Status Values:
        • ACTIVE - Application is active and available to users
        • INACTIVE - Application is disabled and not available
        
        Common Sign-On Modes:
        • SAML_2_0, OPENID_CONNECT, SECURE_PASSWORD_STORE, AUTO_LOGIN
        • BOOKMARK, BASIC_AUTH, BROWSER_PLUGIN, WS_FEDERATION
        
        Returns application details including ID, name, label, status, and sign-on configuration.
        """
        try:
            # Validate limit parameter
            if limit < 1 or limit > 200:
                raise ValueError("limit must be between 1 and 200")
            
            if ctx:
                logger.info(f"SERVER: Executing list_okta_applications with q={q}, filter={filter}, limit={limit}")
            
            # Prepare request parameters
            params = {'limit': limit}
            
            if q:
                params['q'] = q
            
            if filter:
                params['filter'] = filter
                
            if after:
                params['after'] = after
                
            if use_optimization:
                params['useOptimization'] = use_optimization
                
            if include_non_deleted:
                params['includeNonDeleted'] = include_non_deleted
                
            if expand:
                params['expand'] = expand
            
            if ctx:
                logger.info(f"Executing Okta API request with params: {params}")
                await ctx.report_progress(25, 100)
            
            # Execute single Okta API request (no pagination)
            raw_response = await okta_client.client.list_applications(params)
            apps, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing applications: {err}")
                return handle_okta_result(err, "list_applications")
            
            # Get apps up to limit
            all_apps = apps[:limit] if apps else []
            
            if ctx:
                logger.info(f"Retrieved {len(all_apps)} applications (limited to {limit})")
                await ctx.report_progress(100, 100)
            
            # Determine if there are more results available
            has_more = resp and resp.has_next() and len(apps) == params['limit']
            
            # Format and return results
            result = {
                "applications": [app.as_dict() for app in all_apps],
                "summary": {
                    "returned_count": len(all_apps),
                    "limit": limit,
                    "has_more": has_more
                }
            }
            
            # Add pagination info if available
            if resp and resp.has_next():
                result["pagination"] = {
                    "next_cursor": resp.get_next_cursor(),
                    "has_next": True
                }
            
            # Add helpful messaging
            if has_more:
                result["message"] = (
                    f"Showing {len(all_apps)} applications. "
                    f"Use pagination cursor or refine filters to get more specific results."
                )
            elif len(all_apps) == 0:
                result["message"] = (
                    "No applications found. Try different search criteria or filters."
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