"""Connection monitoring middleware for graceful client disconnect handling."""

import logging
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.exceptions import ToolError
import anyio

logger = logging.getLogger("okta_mcp_server")

class ConnectionMonitorMiddleware(Middleware):
    """Middleware that handles client disconnections gracefully to keep server healthy."""
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Handle tool execution with graceful disconnect detection."""
        
        tool_name = context.message.name
        logger.debug(f"Starting tool execution: {tool_name}")
        
        try:
            # Execute the tool
            result = await call_next(context)
            logger.debug(f"Tool {tool_name} completed successfully")
            return result
            
        except anyio.ClosedResourceError:
            # This is the critical fix - catch client disconnects at middleware level
            logger.warning(f"Client disconnected during {tool_name}. Server remains healthy.")
            # Don't try to return anything - the connection is gone
            return None
            
        except Exception as e:
            logger.error(f"Error in tool {tool_name}: {e}")
            # Re-raise other exceptions normally
            raise

class RateLimitHandlingMiddleware(Middleware):
    """Middleware that converts Okta rate limits to user-friendly errors."""
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Convert rate limit errors to immediate user-friendly responses."""
        
        try:
            return await call_next(context)
            
        except Exception as e:
            error_msg = str(e).lower()
            
            # Check if this is an Okta rate limit error
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                tool_name = context.message.name
                logger.warning(f"Rate limit hit for tool {tool_name}")
                raise ToolError(
                    f"Okta API rate limit exceeded. Please wait a moment and try again. "
                    f"This typically happens when making many requests quickly."
                )
            
            # Re-raise other exceptions
            raise