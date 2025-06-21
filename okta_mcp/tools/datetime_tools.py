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
        buffer_hours: int = Field(default=0, description="Optional number of hours to add to current time"),
        ctx: Context = None
    ) -> str:
        """Returns the current date and time in UTC as ISO 8601 formatted string. Useful for Okta API date parameters."""
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
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during get_current_time. Server remains healthy.")
            return None
            
        except Exception as e:
            logger.exception("Error in get_current_time tool")
            return None
    
    @server.tool()
    async def parse_relative_time(
        time_expression: str = Field(..., description="Natural language time expression (e.g., '2 days ago', 'last week')"),
        ctx: Context = None
    ) -> str:
        """Parses a relative time expression and returns the corresponding UTC timestamp in ISO 8601 format for Okta API use."""
        try:
            if ctx:
                logger.info(f"Parsing relative time expression: '{time_expression}'")
            
            # Validate input
            if not time_expression or not time_expression.strip():
                raise ValueError("time_expression cannot be empty")
            
            time_expression = time_expression.strip()
            
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
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during parse_relative_time. Server remains healthy.")
            return None
            
        except Exception as e:
            logger.exception(f"Error parsing time expression '{time_expression}'")
            return None