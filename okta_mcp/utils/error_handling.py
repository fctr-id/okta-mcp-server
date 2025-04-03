"""Error handling utilities for Okta MCP server."""

import logging
from typing import Dict, Any, List, Union
from mcp.types import TextContent

logger = logging.getLogger(__name__)

def is_error_result(result: Any) -> bool:
    """Check if a result represents an error.
    
    Args:
        result: Result to check
        
    Returns:
        True if result is an error, False otherwise
    """
    if isinstance(result, dict) and "errorCode" in result:
        return True
    if isinstance(result, Exception):
        return True
    return False


def normalize_result(result: Any) -> Dict[str, Any]:
    """Normalize a result to a standard format.
    
    Args:
        result: Result to normalize
        
    Returns:
        Normalized result as a dictionary
    """
    if isinstance(result, dict):
        return result
    if isinstance(result, Exception):
        return {
            "errorCode": type(result).__name__,
            "errorSummary": str(result),
            "errorDetail": getattr(result, "args", [])
        }
    if result is None:
        return {"status": "success", "data": None}
    return {"status": "success", "data": result}


def format_error_response(error: Exception, tool_name: str) -> List[TextContent]:
    """Format an error into a user-friendly MCP text response.
    
    Args:
        error: The exception that occurred
        tool_name: Name of the tool that encountered the error
        
    Returns:
        Formatted error message as MCP TextContent
    """
    error_type = type(error).__name__
    error_message = str(error)
    
    response = [
        TextContent(
            type="text",  # Add required type field with value "text"
            text=f"### Error executing tool: {tool_name}\n\n"
                 f"**Type**: {error_type}\n\n"
                 f"**Message**: {error_message}\n\n"
                 f"Please check your Okta credentials and permissions, "
                 f"or try again with different parameters."
        )
    ]
    
    logger.error(f"Error in tool {tool_name}: {error_type} - {error_message}")
    return response


def handle_okta_result(result: Dict[str, Any], tool_name: str) -> Union[Any, List[TextContent]]:
    """Handle a result from an Okta API call, converting errors to friendly responses.
    
    Args:
        result: Result from Okta API call
        tool_name: Name of the tool that made the API call
        
    Returns:
        Either the successful result or a formatted error response
    """
    if is_error_result(result):
        if isinstance(result, Exception):
            return format_error_response(result, tool_name)
        
        # Handle Okta API error response
        error = Exception(
            f"Okta API Error: {result.get('errorCode', 'Unknown')}: "
            f"{result.get('errorSummary', 'Unknown error')}"
        )
        return format_error_response(error, tool_name)
    
    return result