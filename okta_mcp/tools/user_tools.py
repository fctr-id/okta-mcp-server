"""User management tools for Okta MCP server."""

import anyio
import logging
from typing import List, Dict, Any, Optional, Union
from fastmcp import FastMCP, Context
from pydantic import Field


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
        query: str = Field(default="", description="Simple text search matched against firstName, lastName, or email"),
        search: str = Field(default="", description="SCIM filter syntax like - profile.firstName eq \"Dan\""),
        filter_type: str = Field(default="", description="Filter type (status, type, etc.)"),
        sort_by: str = Field(default="created", description="Field to sort by (only works with 'search' parameter)"),
        sort_order: str = Field(default="desc", description="Sort direction (asc or desc) (only works with 'search' parameter)"),
        max_results: int = Field(default=50, description="Maximum users to return (1-100). Limited for LLM context window."),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta users with filtering - returns first 50 users by default due to LLM context limitations.

        IMPORTANT: This tool returns only the first 50 users by default (max 100) to stay within LLM context limits.
        Use specific search filters to find the users you need rather than browsing all users.
        
        search (Recommended, Powerful):
        Uses flexible SCIM filter syntax for precise filtering.
        Supports operators: eq, ne, gt, lt, ge, le, sw (starts with), co (contains), pr (present), and, or.
        Filters on most user properties, including custom attributes, id, status, dates, arrays.
        Supports sorting (sortBy, sortOrder) - NOTE: Sorting parameters ONLY work with 'search' parameter, not with 'query'.
        
        Examples:
        - Active engineering users: search='profile.department eq "Engineering" and status eq "ACTIVE"'
        - Users with first name starting with A: search='profile.firstName sw "A"'
        - Users in SF or London: search='profile.city eq "San Francisco" or profile.city eq "London"'
        - Sorted results: search='status eq "ACTIVE"', sort_by='profile.lastName', sort_order='asc'
        - Custom attribute search: search='profile.employeeNumber eq "12345"'
            
        """
        try:
            # Validate max_results parameter
            if max_results < 1 or max_results > 100:
                raise ValueError("max_results must be between 1 and 100")
                
            if sort_order.lower() not in ['asc', 'desc']:
                raise ValueError("Sort order must be 'asc' or 'desc'")
            
            if ctx:
                logger.info(f"Listing users with parameters: query={query}, search={search}, filter={filter_type}, max_results={max_results}")
            
            # Use smaller API limit to be rate-limit friendly
            api_limit = min(max_results, 100)
            
            # Prepare request parameters
            params = {'limit': api_limit}
            
            # Priority: search > query > filter
            if search:
                params['search'] = search
                params['sortBy'] = sort_by
                params['sortOrder'] = sort_order
            elif query:
                params['q'] = query
                
            if filter_type and not search:
                params['filter'] = filter_type
            
            if ctx:
                logger.info(f"Executing Okta API request with params: {params}")
            
            # Execute single Okta API request (no pagination)
            raw_response = await okta_client.client.list_users(params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing users: {err}")
                if ctx:
                    logger.error(f"Error listing users: {err}")
                return handle_okta_result(err, "list_users")
            
            # Get users up to max_results limit
            all_users = users[:max_results] if users else []
            
            if ctx:
                logger.info(f"Retrieved {len(all_users)} users (limited to {max_results})")
                await ctx.report_progress(100, 100)
            
            # Determine if there are more results available
            has_more = resp and resp.has_next() and len(users) == api_limit
            
            # Format and return results
            result = {
                "users": [user.as_dict() for user in all_users],
                "summary": {
                    "returned_count": len(all_users),
                    "max_requested": max_results,
                    "context_limited": True  # Always true since we limit for context
                }
            }
            
            # Add helpful messaging
            if has_more:
                result["message"] = (
                    f"Showing first {len(all_users)} users (limited for LLM context). "
                    f"Use specific search filters like 'profile.department eq \"Engineering\"' "
                    f"or 'status eq \"ACTIVE\"' to find specific users."
                )
            elif len(all_users) == 0:
                result["message"] = (
                    "No users found. Try broader search criteria or check your filters. "
                    "Use 'query' for simple name searches or 'search' for advanced SCIM filtering."
                )
            else:
                result["message"] = f"Found {len(all_users)} users matching your criteria."
            
            return result
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected from server. The 'list_okta_users' task has been terminated gracefully. The server is ready for new requests.")
            return None
            
        except Exception as e:       
            logger.exception("Error in list_users tool")
            if ctx:
                logger.error(f"Error in list_users tool: {str(e)}")
            return handle_okta_result(e, "list_users")
        
    
    @server.tool()
    async def get_okta_user(
        user_id: str = Field(..., description="Enter the login of the user to retrieve details for"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get detailed information about a specific Okta user."""
        try:
            if ctx:
                logger.info(f"Getting user info for: {user_id}")
            
            # Validate input
            if not user_id or not user_id.strip():
                raise ValueError("user_id cannot be empty")
            
            user_id = user_id.strip()
            
            # Execute API call
            raw_response = await okta_client.client.get_user(user_id)
            user, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting user {user_id}: {err}")
                return handle_okta_result(err, "get_user")
            
            result = user.as_dict()
            
            if ctx:
                logger.info(f"Successfully retrieved user data for {user_id}")
            
            return result
        
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during get_okta_user. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in get_okta_user")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'get_okta_user'
                }
            
            logger.exception(f"Error in get_user tool for user_id {user_id}")
            return handle_okta_result(e, "get_user")
    
    @server.tool()
    async def list_okta_user_groups(
        user_id: str = Field(..., description="The ID or login of the user to retrieve groups for"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all groups that a specific Okta user belongs to."""
        try:
            if ctx:
                logger.info(f"Listing groups for user: {user_id}")
            
            # Validate input
            if not user_id or not user_id.strip():
                raise ValueError("user_id cannot be empty")
            
            user_id = user_id.strip()
            
            # Normalize user_id (handle email/login case)
            if "@" in user_id:
                if ctx:
                    logger.info(f"Converting login {user_id} to user ID")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    logger.error(f"Error getting user {user_id}: {err}")
                    return handle_okta_result(err, "list_user_groups")
                    
                user_id = user.id
                
            # Execute API request
            if ctx:
                logger.info(f"Fetching groups for user ID: {user_id}")
                
            raw_response = await okta_client.client.list_user_groups(user_id)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups for user {user_id}: {err}")
                return handle_okta_result(err, "list_user_groups")
            
            if ctx:
                logger.info(f"Retrieved {len(groups) if groups else 0} groups")
                await ctx.report_progress(100, 100)
            
            result = {
                "groups": [group.as_dict() for group in groups] if groups else [],
                "total_groups": len(groups) if groups else 0
            }
            
            return result
        
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_user_groups. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_user_groups")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_user_groups'
                }
            
            logger.exception(f"Error in list_user_groups tool for user_id {user_id}")
            return handle_okta_result(e, "list_user_groups")
    
    @server.tool()
    async def list_okta_user_applications(
        user_id: str = Field(..., description="The ID or login of the user to retrieve applications for"),
        show_all: bool = Field(default=True, description="If True, shows all app links; if False, only shows app links assigned directly to the user"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all application links (assigned applications) for a specific Okta user."""
        try:
            if ctx:
                logger.info(f"Listing app links for user: {user_id}")
            
            # Validate input
            if not user_id or not user_id.strip():
                raise ValueError("user_id cannot be empty")
            
            user_id = user_id.strip()
            
            # Normalize user_id (handle email/login case)
            if "@" in user_id:
                if ctx:
                    logger.info(f"Converting login {user_id} to user ID")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    logger.error(f"Error getting user {user_id}: {err}")
                    return handle_okta_result(err, "list_app_links")
                    
                user_id = user.id
                
            # Execute API request
            if ctx:
                logger.info(f"Fetching app links for user ID: {user_id}")
            
            params = {}
            if show_all:
                params['showAll'] = True
                
            raw_response = await okta_client.client.list_app_links(user_id, params)
            app_links, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing app links for user {user_id}: {err}")
                return handle_okta_result(err, "list_app_links")
            
            if ctx:
                logger.info(f"Retrieved {len(app_links) if app_links else 0} app links for user {user_id}")
                await ctx.report_progress(100, 100)
            
            result = {
                "app_links": [app_link.as_dict() for app_link in app_links] if app_links else [],
                "total_results": len(app_links) if app_links else 0
            }
            
            return result
        
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_user_applications. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_user_applications")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_user_applications'
                }
            
            logger.exception(f"Error in list_app_links tool for user_id {user_id}")
            return handle_okta_result(e, "list_app_links")
    
    @server.tool()
    async def list_okta_user_factors(
        user_id: str = Field(..., description="The ID or login of the user to retrieve authentication factors for"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all authentication factors enrolled for a specific Okta user."""
        try:
            if ctx:
                logger.info(f"Listing authentication factors for user: {user_id}")
            
            # Validate input
            if not user_id or not user_id.strip():
                raise ValueError("user_id cannot be empty")
            
            user_id = user_id.strip()
            
            # Normalize user_id (handle email/login case)
            if "@" in user_id:
                if ctx:
                    logger.info(f"Converting login {user_id} to user ID")
                raw_response = await okta_client.client.get_user(user_id)
                user, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    logger.error(f"Error getting user {user_id}: {err}")
                    return handle_okta_result(err, "list_user_factors")
                    
                user_id = user.id
                
            # Execute API request
            if ctx:
                logger.info(f"Fetching authentication factors for user ID: {user_id}")
                
            raw_response = await okta_client.client.list_factors(user_id)
            factors, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing factors for user {user_id}: {err}")
                return handle_okta_result(err, "list_user_factors")
            
            if ctx:
                logger.info(f"Retrieved {len(factors) if factors else 0} authentication factors")
                await ctx.report_progress(100, 100)
            
            result = {
                "factors": [factor.as_dict() for factor in factors] if factors else [],
                "total_factors": len(factors) if factors else 0
            }
            
            return result
        
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_user_factors. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_user_factors")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_user_factors'
                }
            
            logger.exception(f"Error in list_user_factors tool for user_id {user_id}")
            return handle_okta_result(e, "list_user_factors")                
    
    #logger.info("Registered user management tools")
    
    # @server.tool()
    # async def list_okta_users(
    #     query: str = "",
    #     search: str = "", 
    #     filter_type: str = "",
    #     sort_by: str = "created",
    #     sort_order: str = "desc",
    #     ctx: Context = None
    # ) -> Dict[str, Any]:
    #     """List Okta users with AI-enhanced filtering. Use query for simple terms (e.g. 'Dan') or search for SCIM filters (e.g. profile.firstName eq "Dan").
    #         search (Recommended, Powerful):
    #         Uses flexible SCIM filter syntax.
    #         Supports operators: eq, ne, gt, lt, ge, le, sw (starts with), co (contains), pr (present), and, or.
    #         Filters on most user properties, including custom attributes, id, status, dates, arrays.
    #         Supports sorting (sortBy, sortOrder) - NOTE: Sorting parameters ONLY work with 'search' parameter, not with 'query'.
    #         Examples:
    #         {'search': 'profile.department eq "Engineering" and status eq "ACTIVE"'}
    #         {'search': 'profile.firstName sw "A"'}
    #         {'search': 'profile.city eq "San Francisco" or profile.city eq "London"'}
    #         Sorting: {'search': 'status eq "ACTIVE"', 'sortBy': 'profile.lastName', 'sortOrder': 'ascending'}
    #         Custom Attribute (Exact): {'search': 'profile.employeeNumber eq "12345"'}
    #         Custom Attribute (Starts With): {'search': 'profile.employeeNumber sw "123"'}
    #         Custom Attribute (Present): {'search': 'profile.employeeNumber pr'}
            
    #     Args:
    #         query: Simple text search or natural language (AI will convert to SCIM if needed)
    #         search: SCIM filtering (recommended) - use exact syntax like 'profile.firstName eq "Dan"'
    #         filter_type: Filter type (status, type, etc.)
    #         sort_by: Field to sort by (only works with 'search' parameter)
    #         sort_order: Sort direction (asc or desc) (only works with 'search' parameter)
    #         ctx: MCP Context for progress reporting and logging
            
    #     Returns:
    #         Dictionary containing users and pagination information
    #     """
    #     try:
    #         logger.info(f"[DEBUG] Function called with ctx: {ctx is not None}, query: '{query}', search: '{search}'")
    #         limit = 200
    #         ai_converted = False
    #         original_query = query
    #         query = query.strip() or None
    #         search = search.strip() or None
    #         filter_type = filter_type.strip() or None
            
    #         if ctx:
    #             logger.info(f"Listing users with parameters: query={query}, search={search}, filter={filter_type}")
                
    #         logger.info(f"[DEBUG] AI condition check: query={bool(query)}, not_search={not search}, ctx={ctx is not None}")
    #         logger.info(f"[DEBUG] Search is None: {search is None}")
    #         logger.info(f"[DEBUG] Search bool value: {bool(search)}")
    #         logger.info(f"[DEBUG] Will attempt AI: {bool(query and not search and ctx is not None)}")               
            
    #         logger.info(f"[DEBUG] About to check AI condition...")
            
    #         # ==================== AI ENHANCEMENT ====================
    #         # For testing: Always use AI sampling when query is provided
    #         if query and not search and ctx is not None:
    #             logger.info(f"[DEBUG] *** INSIDE AI CONVERSION BLOCK ***")
    #             try:
    #                 logger.info(f"[DEBUG] Step 1: About to send ctx.info message")
    #                 if ctx:
    #                     await ctx.info(f"[TESTING] Always converting query to SCIM: '{query}'")
                        
    #                 logger.info(f"[DEBUG] Step 2: About to import asyncio")
    #                 import asyncio
                   
    #                 logger.info(f"[DEBUG] Step 3: About to call ctx.sample()") 
    #                 sampling_result = await asyncio.wait_for(
    #                     ctx.sample(
    #                         f"Convert this to an Okta SCIM filter: '{query}'",
    #                         system_prompt="""You are an expert in Okta SCIM filtering. Convert any search request into proper Okta SCIM filter expressions.
    
    # SCIM Filter Operators:
    # - eq (equals): profile.firstName eq "John"
    # - ne (not equals): profile.department ne "IT" 
    # - sw (starts with): profile.email sw "john"
    # - co (contains): profile.displayName co "Smith"
    # - pr (present): profile.mobilePhone pr
    
    # Common Profile Fields:
    # - profile.firstName, profile.lastName, profile.email
    # - profile.department, profile.title, profile.city
    # - status (ACTIVE, SUSPENDED, DEPROVISIONED)
    
    # Examples:
    # - "Dan" → profile.firstName co "Dan" or profile.lastName co "Dan"
    # - "users named Dan" → profile.firstName co "Dan" or profile.lastName co "Dan"
    # - "engineering" → profile.department co "Engineering"
    # - "active users" → status eq "ACTIVE"
    
    # Respond with ONLY the SCIM filter expression, no explanation."""
    #                     ),
    #                     timeout=10.0
    #                 )
                    
    #                 logger.info(f"[DEBUG] Step 4: Got sampling result: {type(sampling_result)}")
                    
    #                 if ctx:
    #                     await ctx.info(f"[DEBUG] Raw sampling result type: {type(sampling_result)}")
    #                     await ctx.info(f"[DEBUG] Raw sampling result: {repr(sampling_result)}")
                    
    #                 logger.info(f"[DEBUG] Step 5: Processing sampling result...")
                    
    #                 # Handle different types of sampling results
    #                 converted_search = None
                    
    #                 # NEW: Handle MCP TextContent objects
    #                 if hasattr(sampling_result, 'text'):
    #                     converted_search = sampling_result.text.strip()
    #                     logger.info(f"[DEBUG] Extracted from TextContent.text: '{converted_search}'")
                    
    #                 # Handle other response types
    #                 elif isinstance(sampling_result, str):
    #                     converted_search = sampling_result.strip()
    #                     logger.info(f"[DEBUG] Direct string: '{converted_search}'")
                    
    #                 elif hasattr(sampling_result, 'data'):
    #                     converted_search = str(sampling_result.data).strip()
    #                     logger.info(f"[DEBUG] Extracted from .data: '{converted_search}'")
                    
    #                 elif hasattr(sampling_result, 'content'):
    #                     converted_search = str(sampling_result.content).strip()
    #                     logger.info(f"[DEBUG] Extracted from .content: '{converted_search}'")
                    
    #                 elif isinstance(sampling_result, dict):
    #                     if 'data' in sampling_result:
    #                         converted_search = str(sampling_result['data']).strip()
    #                         logger.info(f"[DEBUG] Extracted from dict['data']: '{converted_search}'")
    #                     elif 'content' in sampling_result:
    #                         converted_search = str(sampling_result['content']).strip()
    #                         logger.info(f"[DEBUG] Extracted from dict['content']: '{converted_search}'")
    #                     elif 'text' in sampling_result:
    #                         converted_search = str(sampling_result['text']).strip()
    #                         logger.info(f"[DEBUG] Extracted from dict['text']: '{converted_search}'")
                    
    #                 else:
    #                     converted_search = str(sampling_result).strip()
    #                     logger.info(f"[DEBUG] Converted to string: '{converted_search}'")
                    
    #                 logger.info(f"[DEBUG] Step 6: Converted search value: '{converted_search}'")
                    
    #                 if ctx:
    #                     await ctx.info(f"[DEBUG] Converted search: '{converted_search}'")
                    
    #                 # Clean up the response
    #                 if converted_search:
    #                     # Remove quotes around the entire response
    #                     if converted_search.startswith('"') and converted_search.endswith('"'):
    #                         converted_search = converted_search[1:-1]
                        
    #                     # Remove any escape characters
    #                     converted_search = converted_search.replace('\\"', '"')
                        
    #                     logger.info(f"[DEBUG] Step 7: Cleaned search value: '{converted_search}'")
                        
    #                     # Validate it looks like a SCIM filter
    #                     if (converted_search and 
    #                         not converted_search.startswith('type=') and 
    #                         not converted_search.startswith('{') and
    #                         len(converted_search) > 5):
                            
    #                         # Move to search parameter and clear query
    #                         search = converted_search
    #                         query = None
    #                         ai_converted = True
                            
    #                         logger.info(f"[DEBUG] Step 8: Successfully converted to SCIM: '{search}'")
    #                         if ctx:
    #                             await ctx.info(f"[TESTING] AI converted to SCIM: '{search}'")
    #                     else:
    #                         logger.info(f"[DEBUG] Step 8: Invalid SCIM format, keeping original query")
    #                         if ctx:
    #                             await ctx.info(f"[TESTING] AI conversion invalid format: '{converted_search}', using original query")
    #                 else:
    #                     logger.info(f"[DEBUG] Step 6: Empty result, keeping original query")
    #                     if ctx:
    #                         await ctx.info("[TESTING] AI conversion returned empty result, using original query")
                            
    #             except asyncio.TimeoutError:
    #                 logger.error(f"[DEBUG] AI conversion timeout")
    #                 if ctx:
    #                     await ctx.info("[TESTING] AI conversion timed out, using original query")
    #             except Exception as e:
    #                 logger.error(f"[DEBUG] AI conversion exception: {type(e).__name__}: {str(e)}")
    #                 import traceback
    #                 logger.error(f"[DEBUG] Full traceback: {traceback.format_exc()}")
    #                 if ctx:
    #                     await ctx.info(f"[TESTING] AI conversion failed: {e}, using original query")
            
    #         # Validate parameters
    #         if limit < 1 or limit > 200:
    #             raise ValueError("Limit must be between 1 and 200")
                
    #         if sort_order.lower() not in ['asc', 'desc']:
    #             raise ValueError("Sort order must be 'asc' or 'desc'")
            
    #         # Prepare request parameters
    #         params = {
    #             'limit': limit
    #         }
            
    #         # Priority: search > query > filter
    #         if search:
    #             params['search'] = search
    #             params['sortBy'] = sort_by
    #             params['sortOrder'] = sort_order
    #         elif query:
    #             params['q'] = query
                
    #         if filter_type and not search:
    #             params['filter'] = filter_type
            
    #         if ctx:
    #             logger.info(f"Executing Okta API request with params: {params}")
    #             await ctx.info(f"[DEBUG] About to call Okta with params: {params}")
    #             await ctx.info(f"[DEBUG] Search parameter value: {repr(params.get('search'))}")
    #             await ctx.info(f"[DEBUG] Search parameter type: {type(params.get('search'))}")
    
            
    #         # Execute Okta API request
    #         raw_response = await okta_client.client.list_users(params)
    #         users, resp, err = normalize_okta_response(raw_response)
            
    #         if err:
    #             logger.error(f"Error listing users: {err}")
    #             if ctx:
    #                 logger.error(f"Error listing users: {err}")
    #             return handle_okta_result(err, "list_users")
            
    #         # Collect all users (including pagination)
    #         all_users = users if users else []
    #         page_count = 1
            
    #         # Process additional pages if available
    #         while resp and resp.has_next():
    #             if ctx:
    #                 logger.info(f"Retrieving page {page_count + 1}...")
    #                 await ctx.report_progress(page_count * 10, 100)
                
    #             try:
    #                 # Use the correct SDK pagination method
    #                 users_page, err = await resp.next()
                    
    #                 if err:
    #                     if ctx:
    #                         logger.error(f"Error during pagination: {err}")
    #                     break
                    
    #                 if users_page:
    #                     all_users.extend(users_page)
    #                     page_count += 1
                        
    #                     # Safety check to prevent infinite loops
    #                     if page_count > 50:
    #                         if ctx:
    #                             logger.warning("Reached maximum page limit (50), stopping pagination")
    #                         break
    #                 else:
    #                     break
                        
    #             except StopAsyncIteration:
    #                 # This is expected when there are no more pages
    #                 if ctx:
    #                     logger.info("Reached end of pagination")
    #                 break
    #             except Exception as pagination_error:
    #                 if ctx:
    #                     logger.error(f"Pagination error: {pagination_error}")
    #                 break
    
    #         if ctx:
    #             logger.info(f"Retrieved {len(all_users)} users across {page_count} pages")
    #             await ctx.report_progress(100, 100)
            
    #         # Format and return results
    #         result = {
    #             "users": [user.as_dict() for user in all_users],
    #             "pagination": {
    #                 "total_pages": page_count,
    #                 "total_results": len(all_users),
    #                 "limit_per_page": limit
    #             }
    #         }
            
    #         # Add AI conversion info if applicable
    #         if ai_converted:
    #             result["ai_enhanced"] = {
    #                 "query_converted": True,
    #                 "original_query": original_query,
    #                 "converted_scim": search
    #             }
            
    #         return result
        
    #     except Exception as e:       
    #         logger.exception("Error in list_users tool")
    #         if ctx:
    #             logger.error(f"Error in list_users tool: {str(e)}")
    #         return handle_okta_result(e, "list_users")