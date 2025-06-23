"""Datetime parsing and formatting utilities for Okta MCP server."""

import logging
import anyio
from datetime import datetime, timedelta, timezone
import dateparser
from typing import Tuple, Optional, Union
from fastmcp import FastMCP, Context
from pydantic import Field

logger = logging.getLogger("okta_mcp_server")

def register_datetime_tools(server: FastMCP, okta_client):
    """Register datetime utility tools with the MCP server."""
    
    @server.tool()
    async def get_current_time(
        buffer_hours: int = Field(default=0, description="Optional number of hours to add/subtract from current time"),
        ctx: Context = None
    ) -> str:
        """Get the current date and time in UTC, formatted for Okta API usage.
        
        Returns current UTC timestamp in ISO 8601 format with microseconds and Z suffix,
        suitable for Okta API date parameters and filtering.
        
        Buffer Hours:
        Use buffer_hours to get times in the past (negative) or future (positive):
        • buffer_hours=0: Current time
        • buffer_hours=-24: 24 hours ago  
        • buffer_hours=-168: 1 week ago (7*24 hours)
        • buffer_hours=24: 24 hours from now
        
        Output Format:
        Returns timestamp in format: YYYY-MM-DDTHH:MM:SS.ffffffZ
        Example: 2024-06-23T14:30:15.123456Z
        
        Use Cases:
        • Log event filtering: since="2024-06-22T00:00:00.000Z"
        • User creation filters: lastUpdated gt "timestamp"
        • Application audit queries with time ranges
        • Policy rule time-based conditions
        
        Perfect for constructing Okta API queries that require precise timestamps.
        """
        try:
            if ctx:
                logger.info(f"SERVER: Executing get_current_time with buffer of {buffer_hours} hours")
                await ctx.report_progress(25, 100)
            
            # Get current UTC time
            now = datetime.now(timezone.utc)
            
            # Add buffer if specified
            if buffer_hours:
                now += timedelta(hours=buffer_hours)
                if ctx:
                    logger.info(f"Applied buffer of {buffer_hours} hours to current time")
                    await ctx.report_progress(75, 100)
                
            # Format with 'Z' to explicitly indicate UTC
            result = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            
            if ctx:
                logger.info(f"Generated timestamp: {result}")
                await ctx.report_progress(100, 100)
            
            return result
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during get_current_time. Server remains healthy.")
            return None
            
        except Exception as e:
            logger.exception("Error in get_current_time tool")
            return None
    
    @server.tool()
    async def parse_relative_time(
        time_expression: str = Field(..., description="Natural language time expression"),
        ctx: Context = None
    ) -> str:
        """Parse natural language time expressions into Okta API-compatible timestamps.
        
        Converts human-readable time expressions into ISO 8601 formatted timestamps
        with microseconds, suitable for Okta API queries and filtering.
        
        Supported Expressions:
        • Relative times: "2 days ago", "1 week ago", "3 months ago"
        • Named times: "yesterday", "last week", "last month"  
        • Precise times: "1 hour ago", "30 minutes ago"
        • Period boundaries: "beginning of today", "end of yesterday"
        • Week/month boundaries: "start of this week", "end of last month"
        
        Output Format:
        Returns timestamp in format: YYYY-MM-DDTHH:MM:SS.ffffffZ
        Example: 2024-06-21T00:00:00.000000Z
        
        Common Use Cases:
        • Log queries: 'since=parse_relative_time("24 hours ago")'
        • User filters: 'lastUpdated gt parse_relative_time("1 week ago")'
        • Application activity: 'created after parse_relative_time("yesterday")'
        • Policy rule conditions with time-based criteria
        
        Perfect for constructing Okta audit queries and date-based filters:
        Example: filter='eventType eq "user.authentication.auth" and published gt "parsed_timestamp"'
        """
        try:
            if ctx:
                logger.info(f"SERVER: Executing parse_relative_time for expression: '{time_expression}'")
                await ctx.report_progress(25, 100)
            
            # Validate input
            if not time_expression or not time_expression.strip():
                raise ValueError("time_expression cannot be empty")
            
            time_expression = time_expression.strip()
            
            if ctx:
                await ctx.report_progress(50, 100)
            
            parsed_time = dateparser.parse(time_expression, settings={'RETURN_AS_TIMEZONE_AWARE': True})
            if parsed_time is None:
                logger.warning(f"Could not parse time expression: {time_expression}")
                if ctx:
                    logger.error(f"Could not parse time expression: '{time_expression}'")
                    await ctx.report_progress(100, 100)
                return None
            
            result = parsed_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            
            if ctx:
                logger.info(f"Successfully parsed '{time_expression}' to: {result}")
                await ctx.report_progress(100, 100)
            
            return result
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during parse_relative_time. Server remains healthy.")
            return None
            
        except Exception as e:
            logger.exception(f"Error parsing time expression '{time_expression}'")
            return None