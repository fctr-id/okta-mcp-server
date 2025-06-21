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
        search: str = Field(default="", description="SCIM filter syntax like - profile.name eq \"Engineering\""),
        filter_type: str = Field(default="", description="Filter type (type, status, etc.)"),
        max_results: int = Field(default=50, description="Maximum groups to return (1-100). Limited for LLM context window."),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List Okta groups with filtering - limited to 50 groups by default for context efficiency. Use search filters like 'profile.name co \"Engineering\"' to find specific groups."""
        try:
            # Validate max_results parameter
            if max_results < 1 or max_results > 100:
                raise ValueError("max_results must be between 1 and 100")
            
            if ctx:
                logger.info(f"Listing groups with query={query}, search={search}, max_results={max_results}")
            
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
                logger.info(f"Executing Okta API request with params: {params}")
            
            # Execute single Okta API request (no pagination)
            raw_response = await okta_client.client.list_groups(params)
            groups, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing groups: {err}")
                return handle_okta_result(err, "list_groups")
            
            # Get groups up to max_results limit
            all_groups = groups[:max_results] if groups else []
            
            if ctx:
                logger.info(f"Retrieved {len(all_groups)} groups (limited to {max_results})")
                await ctx.report_progress(100, 100)
            
            # Determine if there are more results available
            has_more = resp and resp.has_next() and len(groups) == params['limit']
            
            # Format and return results
            result = {
                "groups": [group.as_dict() for group in all_groups],
                "summary": {
                    "returned_count": len(all_groups),
                    "max_requested": max_results,
                    "context_limited": True
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
            return handle_okta_result(e, "list_groups")
    
    @server.tool()
    async def get_okta_group(
        group_id: str = Field(..., description="The ID of the group to retrieve"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get detailed information about a specific Okta group."""
        try:
            if ctx:
                logger.info(f"Getting group info for: {group_id}")
            
            # Validate input
            if not group_id or not group_id.strip():
                raise ValueError("group_id cannot be empty")
            
            group_id = group_id.strip()
            
            # Execute API call
            raw_response = await okta_client.client.get_group(group_id)
            group, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error getting group {group_id}: {err}")
                return handle_okta_result(err, "get_group")
            
            if ctx:
                logger.info(f"Successfully retrieved group data for {group_id}")
            
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
            return handle_okta_result(e, "get_group")
    
    @server.tool()
    async def list_okta_group_users(
        group_id: str = Field(..., description="The ID of the group to list users for"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all users in a specific Okta group with full pagination for complete results."""
        try:
            if ctx:
                logger.info(f"Listing users in group: {group_id}")
            
            # Validate input
            if not group_id or not group_id.strip():
                raise ValueError("group_id cannot be empty")
            
            group_id = group_id.strip()
            
            # Prepare request parameters
            params = {'limit': 200}
            
            if ctx:
                logger.info(f"Fetching users for group ID: {group_id}")
                
            # Execute Okta API request with full pagination
            raw_response = await okta_client.client.list_group_users(group_id, params)
            users, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing users for group {group_id}: {err}")
                return handle_okta_result(err, "list_group_users")
            
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
            return handle_okta_result(e, "list_group_users")