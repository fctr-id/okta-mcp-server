"""Datetime parsing and formatting utilities for Okta MCP server."""

import logging
import re
from datetime import datetime, timedelta, timezone
import dateparser
from typing import Tuple, Optional, Union
from mcp.server.fastmcp import FastMCP, Context

logger = logging.getLogger("okta_mcp_server")

def register_datetime_tools(server: FastMCP, okta_client):
    """Register datetime utility tools with the MCP server."""
    
    @server.tool()
    async def get_current_time(buffer_hours: int = 0, ctx: Context = None) -> str:
        """
        Returns the current date and time in UTC as a string.
                Example:
            >>> get_current_time()
            '2023-06-15T14:30:15.123456Z'
            >>> get_current_time(buffer_hours=24)
            '2023-06-16T14:30:15.123456Z'
            
        Args:
            buffer_hours: Optional number of hours to add to current time (default: 0)
            ctx: MCP Context for logging
        Returns:
            String containing the current UTC date and time in ISO 8601 format

        """
        try:
            if ctx:
                logger.info(f"Getting current time with buffer of {buffer_hours} hours")
            
            # Get current UTC time
            now = datetime.now(timezone.utc)
            
            # Add buffer if specified
            if buffer_hours:
                now += timedelta(hours=buffer_hours)
                if ctx:
                    logger.info(f"Added buffer of {buffer_hours} hours to current time")
                
            # Format with 'Z' to explicitly indicate UTC
            result = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            
            if ctx:
                logger.info(f"Current time (with buffer): {result}")
            
            return result
            
        except Exception as e:
            logger.exception("Error in get_current_time tool")
            if ctx:
                logger.error(f"Error in get_current_time tool: {str(e)}")
            return None
    
    @server.tool()
    async def parse_relative_time(time_expression: str, ctx: Context = None) -> str:
        """
        Parses a relative time expression and returns the corresponding UTC timestamp.
                Examples:
            >>> parse_relative_time("2 days ago")
            '2025-04-06T08:23:03.170456Z'
            >>> parse_relative_time("last week")
            '2025-04-01T08:23:03.170456Z'
        
        Args:
            time_expression: A natural language time expression (e.g., "2 days ago", "last week")
            ctx: MCP Context for logging
            
        Returns:
            String containing the parsed UTC date and time in ISO 8601 format
            

        """
        try:
            if ctx:
                logger.info(f"Parsing relative time expression: '{time_expression}'")
            
            parsed_time = dateparser.parse(time_expression, settings={'RETURN_AS_TIMEZONE_AWARE': True})
            if parsed_time is None:
                logger.warning(f"Could not parse time expression: {time_expression}")
                if ctx:
                    logger.error(f"Could not parse time expression: '{time_expression}'")
                return None
            
            result = parsed_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            
            if ctx:
                logger.info(f"Successfully parsed '{time_expression}' to: {result}")
            
            return result
            
        except Exception as e:
            logger.exception(f"Error parsing time expression '{time_expression}'")
            if ctx:
                logger.error(f"Error parsing time expression '{time_expression}': {str(e)}")
            return None
    
    #logger.info("Registered datetime utility tools")