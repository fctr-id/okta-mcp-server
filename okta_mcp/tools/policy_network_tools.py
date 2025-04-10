"""Policy and network management tools for Okta MCP server."""

import logging
import os
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
from dotenv import load_dotenv

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

load_dotenv()
logger = logging.getLogger("okta_mcp_server")

async def make_async_request(method: str, url: str, headers: Dict = None, json_data: Dict = None):
    """Make an async HTTP request to the Okta API.
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        url: Full URL to call
        headers: HTTP headers
        json_data: JSON payload for POST/PUT requests
        
    Returns:
        Dictionary containing the JSON response
    """
    try:
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data
            ) as response:
                # Raise exception for HTTP errors
                response.raise_for_status()
                
                # Return the JSON response
                return await response.json()
    except Exception as e:
        logger.error(f"Error making async HTTP request: {str(e)}")
        raise

def register_policy_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all policy-related tools with the MCP server.
    
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def list_policy_rules(
        policy_id: str,
        after: str = None,
        limit: int = 50,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all rules for a specific Okta policy.
        All policy rule objects in the response include complete nested properties that can be accessed using standard JSON path notation. 
        Common properties to pay attention to include: name, priority (lower is higher), conditions, actions (factormode) and constranints (what type is required) and zone Ids(network.connection.include) which is an array of zone ids.
        Once you extract the details , create a human readable summary to return to the user. Use list_network_zones tool to get the details of the network zone details by using the zone id .
                For example, list_network_zones(args='{"filter_type":"id eq \"nzondmw5liMu8IdyB5d7\""}')
        -you MUST alwaus use the get_policy_rule tool to to fetch the details of the rule and look at actions.appSignOn.constraints and fetch the method values under authenticationMethods 
        
        Args:
            policy_id: The ID of the policy to list rules for
            after: Pagination cursor
            limit: Max number of results to return (1-200)
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing policy rules and pagination information
        """
        try:
            if ctx:
                await ctx.info(f"Listing rules for policy: {policy_id}")
            
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
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_policy_rules(policy_id, params)
            rules, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing rules for policy {policy_id}: {err}")
                if ctx:
                    await ctx.error(f"Error listing rules for policy {policy_id}: {err}")
                return handle_okta_result(err, "list_policy_rules")
            
            # Apply pagination based on environment variable
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_rules = []
            page_count = 0
            
            # Process first page
            if rules:
                all_rules.extend(rules)
                page_count += 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.get_next_page(resp)
                rules, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        await ctx.error(f"Error during pagination: {err}")
                    break
                
                if rules:
                    all_rules.extend(rules)
                    page_count += 1
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_rules)} policy rules across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "rules": [rule.as_dict() for rule in all_rules],
                "policy_id": policy_id,
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_rules),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_policy_rules tool for policy_id {policy_id}")
            if ctx:
                await ctx.error(f"Error in list_policy_rules tool: {str(e)}")
            return handle_okta_result(e, "list_policy_rules")
        
    @server.tool()
    async def get_policy_rule(
        policy_id: str,
        rule_id: str,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get detailed information about a specific Okta policy rule.
        
        Policy rules define the conditions and actions applied to authentication, authorization,
        and other security behaviors in Okta. This tool allows you to retrieve complete details
        about a specific rule within a policy, including all nested properties accessible via JSON path notation.
        
        Common rule properties include:
        - name: Display name of the rule
        - priority: Order of evaluation (lower is higher priority)
        - conditions: Authentication contexts where the rule applies (IP, user, device, etc.)
        - actions: What happens when the rule matches (factor requirements, session settings)
        
        Args:
            policy_id: The ID of the policy that contains the rule
            rule_id: The ID of the specific rule to retrieve
            ctx: MCP Context for logging
            
        Returns:
            Dictionary containing detailed policy rule information
        """
        try:
            if ctx:
                await ctx.info(f"Getting rule {rule_id} for policy: {policy_id}")
            
            # Get the Okta organization URL and API token
            org_url = os.getenv('OKTA_CLIENT_ORGURL')
            api_token = os.getenv('OKTA_API_TOKEN')
            
            if not org_url:
                raise ValueError("OKTA_CLIENT_ORGURL environment variable not set")
            if not api_token:
                raise ValueError("OKTA_API_TOKEN environment variable not set")
                
            # Remove trailing slash if present
            if org_url.endswith('/'):
                org_url = org_url[:-1]
            
            # Setup headers for direct API call
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'SSWS {api_token}'
            }
            
            # Make the direct API request
            url = f"{org_url}/api/v1/policies/{policy_id}/rules/{rule_id}"
            
            if ctx:
                await ctx.info(f"Making direct API call to: {url}")
            
            # Use the module-level make_async_request function
            response = await make_async_request(
                method="GET",
                url=url,
                headers=headers,
                json_data=None
            )
            
            # Parse the JSON response
            rule_data = response
            
            if ctx:
                await ctx.info(f"Successfully retrieved rule information using direct API call")
            
            # Return the raw JSON response
            return rule_data
        
        except Exception as e:
            logger.exception(f"Error in get_policy_rule tool for policy_id {policy_id}, rule_id {rule_id}")
            if ctx:
                await ctx.error(f"Error in get_policy_rule tool: {str(e)}")
            return handle_okta_result(e, "get_policy_rule")    
        
    @server.tool()
    async def list_network_zones(
        filter_type: str = None,
        after: str = None,
        limit: int = 50,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all network zones defined in the Okta organization.
        Network zones define trusted IP addresses, ranges, or locations for authentication.
        All network zone objects in the response include complete nested properties that can be 
        accessed using standard JSON path notation.
        
        Common network zone properties:
        - id: Unique identifier for the zone
        - name: Display name of the zone
        - type: Type of zone (IP, DYNAMIC)
        - gateways: IP address ranges (CIDR notation)
        - proxies: Proxy details if relevant
        - status: ACTIVE or INACTIVE
        
        Args:
            filter_type: Filter zones by type (IP, DYNAMIC) or status (ACTIVE, INACTIVE)
            after: Pagination cursor
            limit: Max number of results to return (1-200)
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing network zones and pagination information
        """
        try:
            if ctx:
                await ctx.info(f"Listing network zones with filter: {filter_type}")
            
            # Validate parameters
            if limit < 1 or limit > 200:
                raise ValueError("Limit must be between 1 and 200")
            
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if after:
                params['after'] = after
                
            if filter_type:
                params['filter'] = filter_type
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_network_zones(params)
            zones, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing network zones: {err}")
                if ctx:
                    await ctx.error(f"Error listing network zones: {err}")
                return handle_okta_result(err, "list_network_zones")
            
            # Apply pagination
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_zones = []
            page_count = 0
            
            # Process first page
            if zones:
                all_zones.extend(zones)
                page_count += 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                raw_response = await okta_client.client.get_next_page(resp)
                zones, resp, err = normalize_okta_response(raw_response)
                
                if err:
                    if ctx:
                        await ctx.error(f"Error during pagination: {err}")
                    break
                
                if zones:
                    all_zones.extend(zones)
                    page_count += 1
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_zones)} network zones across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "zones": [zone.as_dict() for zone in all_zones],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_zones),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception(f"Error in list_network_zones tool")
            if ctx:
                await ctx.error(f"Error in list_network_zones tool: {str(e)}")
            return handle_okta_result(e, "list_network_zones")        
    
    logger.info("Registered policy management tools")