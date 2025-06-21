"""Policy and network management tools for Okta MCP server."""

import logging
import os
import anyio
from typing import List, Dict, Any, Optional
from fastmcp import FastMCP, Context
from pydantic import Field
from dotenv import load_dotenv

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

load_dotenv()
logger = logging.getLogger("okta_mcp_server")

async def make_async_request(method: str, url: str, headers: Dict = None, json_data: Dict = None):
    """Make an async HTTP request to the Okta API."""
    try:
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data
            ) as response:
                response.raise_for_status()
                return await response.json()
    except Exception as e:
        logger.error(f"Error making async HTTP request: {str(e)}")
        raise

def register_policy_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all policy-related tools with the MCP server."""
    
    @server.tool()
    async def list_okta_policy_rules(
        policy_id: str = Field(..., description="The ID of the policy to list rules for"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all rules for a specific Okta policy. Returns complete rule details including conditions, actions, and network zone constraints."""
        try:
            if ctx:
                logger.info(f"Listing rules for policy: {policy_id}")
            
            # Validate input
            if not policy_id or not policy_id.strip():
                raise ValueError("policy_id cannot be empty")
            
            policy_id = policy_id.strip()
            
            # Prepare request parameters
            params = {'limit': 50}
            
            if ctx:
                logger.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_policy_rules(policy_id, params)
            rules, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing rules for policy {policy_id}: {err}")
                return handle_okta_result(err, "list_policy_rules")
            
            if ctx:
                logger.info(f"Retrieved {len(rules) if rules else 0} policy rules")
                await ctx.report_progress(100, 100)
            
            return {
                "rules": [rule.as_dict() for rule in rules] if rules else [],
                "policy_id": policy_id,
                "total_rules": len(rules) if rules else 0
            }
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_policy_rules. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_policy_rules")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_policy_rules'
                }
            
            logger.exception(f"Error in list_policy_rules tool for policy_id {policy_id}")
            return handle_okta_result(e, "list_policy_rules")
        
    @server.tool()
    async def get_okta_policy_rule(
        policy_id: str = Field(..., description="The ID of the policy that contains the rule"),
        rule_id: str = Field(..., description="The ID of the specific rule to retrieve"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get detailed information about a specific Okta policy rule including authentication methods, constraints, and network zone details."""
        try:
            if ctx:
                logger.info(f"Getting rule {rule_id} for policy: {policy_id}")
            
            # Validate inputs
            if not policy_id or not policy_id.strip():
                raise ValueError("policy_id cannot be empty")
            if not rule_id or not rule_id.strip():
                raise ValueError("rule_id cannot be empty")
            
            policy_id = policy_id.strip()
            rule_id = rule_id.strip()
            
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
                logger.info(f"Making direct API call to: {url}")
            
            response = await make_async_request(
                method="GET",
                url=url,
                headers=headers,
                json_data=None
            )
            
            if ctx:
                logger.info(f"Successfully retrieved rule information using direct API call")
            
            return response
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during get_okta_policy_rule. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in get_okta_policy_rule")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'get_okta_policy_rule'
                }
            
            logger.exception(f"Error in get_policy_rule tool for policy_id {policy_id}, rule_id {rule_id}")
            return handle_okta_result(e, "get_policy_rule")    
        
    @server.tool()
    async def list_okta_network_zones(
        filter_type: str = Field(default="", description="Filter zones by type (IP, DYNAMIC) or status (ACTIVE, INACTIVE)"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """List all network zones defined in the Okta organization including IP ranges, proxy details, and zone status."""
        try:
            if ctx:
                logger.info(f"Listing network zones with filter: {filter_type}")
            
            # Prepare request parameters
            params = {'limit': 50}
                
            if filter_type:
                params['filter'] = filter_type
            
            if ctx:
                logger.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.list_network_zones(params)
            zones, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error listing network zones: {err}")
                return handle_okta_result(err, "list_network_zones")
            
            if ctx:
                logger.info(f"Retrieved {len(zones) if zones else 0} network zones")
                await ctx.report_progress(100, 100)
            
            return {
                "zones": [zone.as_dict() for zone in zones] if zones else [],
                "total_zones": len(zones) if zones else 0
            }
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during list_okta_network_zones. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in list_okta_network_zones")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'list_okta_network_zones'
                }
            
            logger.exception(f"Error in list_network_zones tool")
            return handle_okta_result(e, "list_network_zones")