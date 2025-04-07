"""Admin API routes for managing the MCP server."""

import logging
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

from okta_mcp.tools.tool_registry import ToolRegistry
from okta_mcp.server import create_server
from okta_mcp.utils.okta_client import create_okta_client, OktaMcpClient
import os

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    responses={404: {"description": "Not found"}},
)

# Helper to get the current server instance
def get_mcp_server():
    # This could be improved to reference a global server instance
    # instead of creating a new one
    return create_server()

@router.post("/refresh-tools")
async def refresh_tools():
    """
    Refresh all tool definitions and notify connected clients.
    
    This endpoint allows updating tool definitions without server restart.
    """
    try:
        # Get the registry singleton
        registry = ToolRegistry()
        
        # Create a client for refreshing tools
        okta_client = create_okta_client(
            org_url=os.getenv("OKTA_CLIENT_ORGURL"),
            api_token=os.getenv("OKTA_API_TOKEN")
        )
        okta_mcp_client = OktaMcpClient(okta_client)
        
        # Get the server
        server = get_mcp_server()
        
        # Refresh the tools
        success = await registry.refresh_tools(server, okta_mcp_client)
        
        if success:
            return JSONResponse(
                status_code=200,
                content={"status": "success", "message": "Tool definitions refreshed successfully"}
            )
        else:
            raise HTTPException(
                status_code=500, 
                detail="Failed to refresh tool definitions"
            )
    
    except Exception as e:
        logger.exception("Error refreshing tools")
        raise HTTPException(
            status_code=500,
            detail=f"Error refreshing tools: {str(e)}"
        )