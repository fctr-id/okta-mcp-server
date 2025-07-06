"""
MCP Protocol Version Compatibility Adapter

This module provides backward compatibility between different MCP protocol versions
to ensure the Okta MCP Server works with both Claude Desktop (2025-03-26) and
modern MCP clients like VS Code and MCP Inspector (2025-06-18).

The main differences between protocol versions:
- 2025-03-26 (Claude Desktop): Expects certain metadata fields and instructions
- 2025-06-18 (VS Code/MCP Inspector): Uses newer response format

This adapter detects the client protocol version and adjusts responses accordingly.
"""

import logging
import os
from typing import Dict, Any, Optional
from fastmcp import FastMCP

logger = logging.getLogger("okta_mcp")

# Supported protocol versions (from MCP spec)
SUPPORTED_PROTOCOL_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
DEFAULT_NEGOTIATED_VERSION = "2025-03-26"  # Claude Desktop default
LATEST_PROTOCOL_VERSION = "2025-06-18"     # Current standard

class MCPProtocolAdapter:
    """Adapter to handle MCP protocol version compatibility."""
    
    def __init__(self, server_name: str = "Okta MCP Server", server_version: str = "0.1.0-BETA"):
        self.server_name = server_name
        self.server_version = server_version
        self.detected_version = None
        
    def create_compatible_server(self, enable_auth: bool = True) -> FastMCP:
        """
        Create a FastMCP server with enhanced compatibility for different protocol versions.
        
        NOTE: This method is deprecated in favor of the unified FastMCP OAuth server.
        It is kept for backward compatibility with older entry points.
        """
        logger.warning("protocol_adapter.create_compatible_server() is deprecated")
        logger.warning("Use FastMCPOAuthServer from okta_mcp.fastmcp_oauth_server instead")
        
        # Redirect to the new unified OAuth server
        from okta_mcp.fastmcp_oauth_server import FastMCPOAuthServer
        
        try:
            oauth_server = FastMCPOAuthServer()
            
            # Store adapter reference for protocol compatibility detection
            oauth_server.mcp._protocol_adapter = self
            
            logger.info(f"Redirecting to unified FastMCP OAuth server (auth={enable_auth})")
            return oauth_server.mcp
            
        except Exception as e:
            logger.error(f"Error creating unified OAuth server: {e}")
            raise
    
    def _get_enhanced_instructions(self) -> str:
        """
        Get enhanced instructions that work well with both protocol versions.
        
        NOTE: This is kept for potential future protocol compatibility needs.
        Claude Desktop seems to prefer more detailed instructions in the initialization.
        """
        return """
This server provides comprehensive Okta Identity Cloud management capabilities through the Model Context Protocol (MCP).

🔧 **Core Functions:**
- User Management: Search, retrieve, and analyze Okta users with advanced SCIM filtering
- Group Operations: Manage groups and group memberships
- Application Management: List and analyze Okta applications and assignments
- Log Analysis: Query Okta system logs and event data with filtering
- Policy Management: Review network zones, policies, and security configurations

📝 **Key Tools:**
- list_okta_users(): Search users with SCIM expressions (e.g., 'status eq "ACTIVE"')
- get_okta_user(): Get detailed user information by ID or login
- list_okta_groups(): Retrieve groups with filtering and pagination
- get_okta_event_logs(): Query system logs with date ranges and filters
- list_okta_applications(): Analyze applications and their configurations

🔑 **Authentication:**
All operations require proper Okta API credentials configured in environment variables.
The server supports both direct API access and OAuth-protected proxy modes.

📊 **Advanced Features:**
- AI-powered data analysis and anomaly detection
- Real-time event log monitoring
- Comprehensive user lifecycle management
- Security policy analysis and recommendations

Use natural language to describe what you want to accomplish with your Okta tenant,
and the assistant will use the appropriate tools to help you achieve your goals.
        """.strip()
    
    def detect_client_version(self, request_data: Dict[str, Any]) -> Optional[str]:
        """
        Detect the MCP protocol version from client request.
        
        This is called when the client sends an initialize request.
        """
        try:
            # Extract protocol version from initialize request
            if isinstance(request_data, dict):
                if 'protocolVersion' in request_data:
                    version = request_data['protocolVersion']
                elif 'params' in request_data and 'protocolVersion' in request_data['params']:
                    version = request_data['params']['protocolVersion']
                else:
                    # Default to older version for Claude Desktop compatibility
                    version = DEFAULT_NEGOTIATED_VERSION
                
                # Validate version
                if version in SUPPORTED_PROTOCOL_VERSIONS:
                    self.detected_version = version
                    logger.info(f"Detected MCP protocol version: {version}")
                    return version
                else:
                    # Fallback to closest supported version
                    self.detected_version = DEFAULT_NEGOTIATED_VERSION
                    logger.warning(f"Unsupported protocol version {version}, falling back to {DEFAULT_NEGOTIATED_VERSION}")
                    return DEFAULT_NEGOTIATED_VERSION
                    
        except Exception as e:
            logger.error(f"Error detecting client version: {e}")
            self.detected_version = DEFAULT_NEGOTIATED_VERSION
            
        return self.detected_version
    
    def is_legacy_client(self) -> bool:
        """Check if the detected client is using legacy protocol (Claude Desktop)."""
        return self.detected_version == "2025-03-26" or self.detected_version == "2024-11-05"
    
    def is_modern_client(self) -> bool:
        """Check if the detected client is using modern protocol (VS Code, MCP Inspector)."""
        return self.detected_version == "2025-06-18"
    
    def format_response_for_client(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format response data based on detected client version.
        
        This method can be used to add/remove fields based on protocol version.
        """
        if self.is_legacy_client():
            # Add any legacy-specific metadata if needed
            return self._format_legacy_response(response_data)
        else:
            # Modern client format
            return self._format_modern_response(response_data)
    
    def _format_legacy_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format response for legacy clients (Claude Desktop)."""
        # Claude Desktop might expect certain metadata fields
        # Add them if they're missing
        if isinstance(response_data, dict):
            # Ensure _meta field is present if expected
            if '_meta' not in response_data:
                response_data['_meta'] = {}
            
            # Add any other legacy-specific fields here if needed
            
        return response_data
    
    def _format_modern_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format response for modern clients (VS Code, MCP Inspector)."""
        # Modern clients use the standard format
        return response_data
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information formatted for the detected client version."""
        base_info = {
            "name": self.server_name,
            "version": self.server_version
        }
        
        if self.is_legacy_client():
            # Legacy clients might expect additional fields
            base_info.update({
                "description": "Okta Identity Cloud management via MCP",
                "author": "fctr.io",
                "license": "Apache-2.0"
            })
        
        return base_info


# Global adapter instance
_adapter_instance: Optional[MCPProtocolAdapter] = None

def get_adapter() -> MCPProtocolAdapter:
    """Get the global protocol adapter instance."""
    global _adapter_instance
    if _adapter_instance is None:
        _adapter_instance = MCPProtocolAdapter()
    return _adapter_instance

def create_compatible_server(enable_auth: bool = True) -> FastMCP:
    """
    Create a compatible MCP server that works with both Claude Desktop and modern clients.
    
    NOTE: This function is deprecated in favor of the unified FastMCP OAuth server.
    It redirects to FastMCPOAuthServer for full OAuth and RBAC support.
    """
    logger.warning("create_compatible_server() is deprecated - redirecting to FastMCPOAuthServer")
    
    adapter = get_adapter()
    return adapter.create_compatible_server(enable_auth)
