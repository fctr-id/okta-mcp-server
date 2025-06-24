"""Group management tools for Okta MCP server."""

import anyio
import logging
from typing import List, Dict, Any, Optional
from fastmcp import FastMCP, Context
from pydantic import Field
import asyncio

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response

logger = logging.getLogger("okta_mcp_server")

def register_group_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all group-related tools with the MCP server."""
    
    @server.tool()
    async def list_okta_groups(
        query: str = Field(default="", description="Simple text search matched against group name"),
        search: str = Field(default="", description="SCIM filter syntax - see docstring for complete syntax"),
        filter_type: str = Field(default="", description="Filter type (type, status, etc.)"),
        max_results: int = Field(default=50, description="Maximum groups to return (1-100). Limited for LLM context window."),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta groups with filtering - limited to 50 groups by default for context efficiency.
        
        IMPORTANT LIMITATIONS:
        Limited to 50 groups by default (max 100) to stay within LLM context limits.
        Use search filters to find specific groups rather than browsing all groups.
        
        Search Parameters (priority order):
        1. search - SCIM filter syntax (recommended for precise filtering)
        2. query - Simple text search against group name
        3. filter_type - Basic type/status filtering
        
        SCIM Filter Syntax (search parameter):
        Uses SCIM filter expressions for precise group filtering.
        
        Supported Operators:
        • eq (equals), ne (not equals), gt (greater than), lt (less than)
        • ge (greater than or equal), le (less than or equal)
        • sw (starts with), co (contains), pr (present)
        • and (logical AND), or (logical OR)
        
        Common Group Profile Fields:
        • profile.name - Group name
        • profile.description - Group description
        • type - Group type (OKTA_GROUP, BUILT_IN, etc.)
        • created, lastUpdated, lastMembershipUpdated
        • Custom profile attributes
        
        Example SCIM Filters:
        • Engineering groups: 'profile.name co "Engineering"'
        • Groups starting with Admin: 'profile.name sw "Admin"'
        • Multiple departments: 'profile.name co "Engineering" or profile.name co "Sales"'
        • Built-in groups: 'type eq "BUILT_IN"'
        • Groups with descriptions: 'profile.description pr'
        • Recent groups: 'created gt "2024-01-01T00:00:00.000Z"'
        
        Query Parameter:
        Simple text search that matches against group name.
        Use when you want broad matching without specific SCIM syntax.
        
        Filter Type Parameter:
        Basic filtering for type or status. Examples: 'type eq "OKTA_GROUP"'
        
        Group Types:
        • OKTA_GROUP - Standard Okta groups
        • BUILT_IN - System built-in groups (Everyone, etc.)
        • APP_GROUP - Application-specific groups
        
        Common Use Cases:
        • Find department or team groups
        • Audit security and admin groups
        • Locate application-specific groups
        • Review group membership structures
        • Compliance and access reviews
        """
        try:
            logger.info("SERVER: Executing list_okta_groups")
            if ctx:
                await ctx.info("Executing list_okta_groups")
                await ctx.report_progress(10, 100)
                
            # Validate max_results parameter
            if max_results < 1 or max_results > 100:
                raise ValueError("max_results must be between 1 and 100")
            
            if ctx:
                await ctx.info(f"Listing groups with query={query}, search={search}, max_results={max_results}")
                await ctx.report_progress(30, 100)
            
            # Prepare request parameters
            params = {'limit': min(max_results, 100)}
            
            # Priority: search > query > filter
            if search:
                params['search'] = search
            elif query:
                params['q'] = query
                
            if filter_type and not search:
                params['filter'] = filter_type
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
                await ctx.report_progress(50, 100)
            
            # Execute single Okta API request (no pagination)
            raw_response = await okta_client.client.list_groups(params)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups: {err}")
                if ctx:
                    await ctx.error(f"Error listing groups: {err}")
                return handle_okta_result(err, "list_groups")
            
            if ctx:
                await ctx.report_progress(80, 100)
            
            # Get groups up to max_results limit
            all_groups = groups[:max_results] if groups else []
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_groups)} groups (limited to {max_results})")
                await ctx.report_progress(100, 100)
            
            # Determine if there are more results available
            has_more = resp and resp.has_next() and len(groups) == params['limit']
            
            # Format and return results
            result = {
                "groups": [group.as_dict() for group in all_groups],
                "summary": {
                    "returned_count": len(all_groups),
                    "max_requested": max_results,
                    "context_limited": True,
                    "has_more": has_more
                }
            }
            
            # Add helpful messaging
            if has_more:
                result["message"] = (
                    f"Showing first {len(all_groups)} groups (limited for LLM context). "
                    f"Use search filters like 'profile.name co \"Engineering\"' to find specific groups."
                )
            elif len(all_groups) == 0:
                result["message"] = (
                    "No groups found. Try broader search criteria or check your filters."
                )
            else:
                result["message"] = f"Found {len(all_groups)} groups matching your criteria."
            
            return result
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_groups. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_groups")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_groups'
                }
            
            logger.exception("Error in list_groups tool")
            if ctx:
                await ctx.error(f"Error in list_groups tool: {str(e)}")
            return handle_okta_result(e, "list_groups")
    
    @server.tool()
    async def get_okta_group(
        group_id: str = Field(..., description="The ID of the group to retrieve"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get detailed information about a specific Okta group.
        
        Returns comprehensive group information including:
        • Group profile (name, description, custom attributes)
        • Group type and classification
        • Membership statistics
        • Creation and modification timestamps
        • Group settings and configuration
        
        Group Information Includes:
        • Basic details (ID, name, description)
        • Group type (OKTA_GROUP, BUILT_IN, APP_GROUP)
        • Profile attributes and custom fields
        • Administrative metadata
        • Object class and schema information
        
        Group Types:
        • OKTA_GROUP - Standard organizational groups
        • BUILT_IN - System groups like "Everyone"
        • APP_GROUP - Application-specific groups
        
        Common Use Cases:
        • Verify group configuration
        • Audit group settings and metadata
        • Get group details for membership operations
        • Compliance and access reviews
        • Troubleshoot group-related issues
        """
        try:
            logger.info("SERVER: Executing get_okta_group")
            if ctx:
                await ctx.info("Executing get_okta_group")
                await ctx.report_progress(10, 100)
            
            # Validate input
            if not group_id or not group_id.strip():
                raise ValueError("group_id cannot be empty")
            
            group_id = group_id.strip()
            
            if ctx:
                await ctx.info(f"Getting group info for: {group_id}")
                await ctx.report_progress(50, 100)
            
            # Execute API call
            raw_response = await okta_client.client.get_group(group_id)
            group, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting group {group_id}: {err}")
                if ctx:
                    await ctx.error(f"Error getting group {group_id}: {err}")
                return handle_okta_result(err, "get_group")
            
            if ctx:
                await ctx.info(f"Successfully retrieved group data for {group_id}")
                await ctx.report_progress(100, 100)
            
            return group.as_dict()
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during get_okta_group. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in get_okta_group")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'get_okta_group'
                }
            
            logger.exception(f"Error in get_group tool for group_id {group_id}")
            if ctx:
                await ctx.error(f"Error in get_group tool for group_id {group_id}: {str(e)}")
            return handle_okta_result(e, "get_group")
    
    @server.tool()
    async def list_okta_group_users(
        group_id: str = Field(..., description="The ID of the group to list users for"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all users in a specific Okta group with full pagination for complete results.
        
        Returns complete group membership including:
        • All users currently in the group
        • User profile information
        • Membership timestamps and details
        • User status and account information
        
        Pagination Handling:
        This tool automatically handles pagination to return ALL users in the group,
        not just the first page. For large groups, this ensures complete membership visibility.
        
        User Information Includes:
        • Basic user profile (name, email, username)
        • User status (ACTIVE, SUSPENDED, etc.)
        • User ID for further operations
        • Profile attributes relevant to group membership
        
        Group Membership Details:
        • Current active memberships only
        • No historical membership data
        • Real-time membership status
        • Direct group membership (not inherited)
        
        Performance Considerations:
        • Large groups may take longer to process
        • Automatic rate limiting to prevent API throttling
        • Progress reporting for long-running operations
        • Graceful handling of pagination errors
        
        Common Use Cases:
        • Complete group membership audit
        • User access reviews and compliance
        • Group cleanup and optimization
        • Security group verification
        • Bulk user operations on group members
        """
        try:
            logger.info("SERVER: Executing list_okta_group_users")
            if ctx:
                await ctx.info("Executing list_okta_group_users")
                await ctx.report_progress(10, 100)
            
            # Validate input
            if not group_id or not group_id.strip():
                raise ValueError("group_id cannot be empty")
            
            group_id = group_id.strip()
            
            if ctx:
                await ctx.info(f"Listing users in group: {group_id}")
                await ctx.report_progress(30, 100)
            
            # Prepare request parameters
            params = {'limit': 200}
            
            if ctx:
                await ctx.info(f"Fetching users for group ID: {group_id}")
                await ctx.report_progress(40, 100)
                
            # Execute Okta API request with full pagination
            raw_response = await okta_client.client.list_group_users(group_id, params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing users for group {group_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing users for group {group_id}: {err}")
                return handle_okta_result(err, "list_group_users")
            
            # Apply full pagination for complete results
            all_users = users if users else []
            page_count = 1
            
            while resp and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(min(50 + (page_count * 5), 90), 100)
                
                try:
                    await asyncio.sleep(0.2)  # Rate limit protection
                    users_page, err = await resp.next()
                    
                    if err:
                        if ctx:
                            await ctx.error(f"Error during pagination: {err}")
                        break
                    
                    if users_page:
                        all_users.extend(users_page)
                        page_count += 1
                        
                        # Safety check
                        if page_count > 50:
                            if ctx:
                                await ctx.warning("Reached maximum page limit (50), stopping")
                            break
                    else:
                        break
                        
                except Exception as pagination_error:
                    if ctx:
                        await ctx.error(f"Pagination error: {pagination_error}")
                    break
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_users)} total users in {page_count} pages")
                await ctx.report_progress(100, 100)
            
            return {
                "users": [user.as_dict() for user in all_users],
                "group_id": group_id,
                "pagination": {
                    "total_pages": page_count,
                    "total_results": len(all_users)
                }
            }
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_group_users. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_group_users")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_group_users'
                }
            
            logger.exception(f"Error in list_group_users tool for group_id {group_id}")
            if ctx:
                await ctx.error(f"Error in list_group_users tool for group_id {group_id}: {str(e)}")
            return handle_okta_result(e, "list_group_users")