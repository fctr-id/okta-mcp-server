"""Log event management tools for Okta MCP server."""

import logging
import csv
import os
import anyio
from typing import Dict, Any, Optional, List
from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

logger = logging.getLogger("okta_mcp_server")

def register_log_events_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all log event-related tools with the MCP server."""
    
    @server.tool()
    async def get_okta_event_logs(
        since: str = Field(default="", description="Starting time for log events (ISO 8601 format)"),
        until: str = Field(default="", description="Ending time for log events (ISO 8601 format)"),
        filter_string: str = Field(default="", description="Filter expression for log events"),
        q: str = Field(default="", description="Search term for log events"),
        sort_order: str = Field(default="DESCENDING", description="Order of results (ASCENDING or DESCENDING)"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get Okta system log events with comprehensive filtering and full pagination for complete audit trails.
        
        Returns detailed log events from Okta system logs including authentication, user management,
        application access, policy changes, and administrative actions with complete audit information.
        
        Time Parameters:
        • since - Start time in ISO 8601 format: "2024-06-01T00:00:00.000Z"
        • until - End time in ISO 8601 format: "2024-06-23T23:59:59.999Z"
        • Use datetime tools to generate proper timestamps: parse_relative_time("24 hours ago")
        
        Filter Parameter:
        Uses Okta expression language for precise event filtering:
        • eventType eq "user.authentication.auth" - Authentication events
        • eventType eq "user.lifecycle.create" - User creation events
        • eventType eq "user.lifecycle.activate" - User activation events
        • eventType eq "user.lifecycle.suspend" - User suspension events
        • eventType eq "application.lifecycle.create" - App creation events
        • outcome.result eq "SUCCESS" - Successful events only
        • outcome.result eq "FAILURE" - Failed events only
        • actor.id eq "user_id" - Events by specific user
        • target.id eq "target_id" - Events targeting specific resource
        
        Common Event Types:
        • user.authentication.auth - User login attempts
        • user.authentication.sso - SSO authentication
        • user.session.start - Session initiation
        • user.session.end - Session termination
        • user.lifecycle.create - User creation
        • user.lifecycle.activate - User activation
        • user.lifecycle.suspend - User suspension
        • user.lifecycle.unsuspend - User reactivation
        • user.lifecycle.deactivate - User deactivation
        • application.user_membership.add - App assignment
        • application.user_membership.remove - App removal
        • group.user_membership.add - Group membership addition
        • group.user_membership.remove - Group membership removal
        • policy.lifecycle.create - Policy creation
        • policy.lifecycle.update - Policy modification
        
        Search Parameter:
        Free-text search across event data:
        • Search for usernames, email addresses, application names
        • Search for IP addresses, client information
        • Search for error messages or specific text in events
        
        Sort Order:
        • DESCENDING - Most recent events first (default)
        • ASCENDING - Oldest events first
        
        Example Filters:
        • Authentication failures: 'eventType eq "user.authentication.auth" and outcome.result eq "FAILURE"'
        • User lifecycle changes: 'eventType sw "user.lifecycle"'
        • Application events: 'eventType sw "application"'
        • Admin actions: 'actor.type eq "User" and eventType sw "policy"'
        • Specific user activity: 'actor.alternateId eq "user@company.com"'
        
        This tool uses full pagination to return complete audit trails for compliance,
        security analysis, and forensic investigation purposes.
        
        Use for security monitoring, compliance auditing, troubleshooting authentication
        issues, and comprehensive log analysis.
        """
        try:
            if ctx:
                logger.info(f"SERVER: Executing get_okta_event_logs with parameters: since={since}, until={until}, filter={filter_string}, q={q}")
                await ctx.report_progress(10, 100)
            
            # Prepare request parameters
            params = {'limit': 500}
            
            if since:
                params['since'] = since
                
            if until:
                params['until'] = until
                
            if filter_string:
                params['filter'] = filter_string
                
            if q:
                params['q'] = q
                
            if sort_order:
                # Validate sort order
                if sort_order.upper() not in ['ASCENDING', 'DESCENDING']:
                    raise ValueError("Sort order must be either 'ASCENDING' or 'DESCENDING'")
                params['sortOrder'] = sort_order.upper()
            
            if ctx:
                logger.info(f"Executing Okta API request with params: {params}")
                await ctx.report_progress(25, 100)
            
            # Execute Okta API request with full pagination
            raw_response = await okta_client.client.get_logs(params)
            log_events, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error retrieving log events: {err}")
                return handle_okta_result(err, "get_logs")
            
            # Apply full pagination for complete audit trail
            all_log_events = log_events if log_events else []
            page_count = 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    logger.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(min(25 + (page_count * 10), 90), 100)
                
                try:
                    next_logs, next_err = await resp.next()
                    
                    if next_err:
                        logger.error(f"Error during pagination: {next_err}")
                        break
                        
                    # Process valid log events
                    valid_logs = [log for log in next_logs if log and hasattr(log, 'as_dict')]
                    
                    if valid_logs:
                        all_log_events.extend(valid_logs)
                        page_count += 1
                        
                        # Safety check
                        if page_count > 20:  # Logs can be large, limit pages
                            if ctx:
                                logger.warning("Reached maximum page limit (20), stopping")
                            break
                    else:
                        break
                    
                except Exception as e:
                    logger.error(f"Exception during pagination: {str(e)}")
                    break
            
            if ctx:
                logger.info(f"Retrieved {len(all_log_events)} log events across {page_count} pages")
                await ctx.report_progress(100, 100)
            
            return {
                "log_events": [event.as_dict() for event in all_log_events],
                "pagination": {
                    "total_pages": page_count,
                    "total_results": len(all_log_events)
                }
            }
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during get_okta_event_logs. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in get_okta_event_logs")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'get_okta_event_logs'
                }
            
            logger.exception("Error in get_logs tool")
            return handle_okta_result(e, "get_logs")