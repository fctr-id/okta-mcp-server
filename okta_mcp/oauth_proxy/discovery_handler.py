"""
Discovery Handler for OAuth Proxy Server

Handles OAuth 2.0 discovery endpoints and well-known URIs.
"""

import logging
import httpx
from typing import Dict, Any
from datetime import datetime, timezone
from aiohttp import web

from okta_mcp.auth.oauth_provider import OAuthConfig

logger = logging.getLogger("oauth_proxy.discovery")


class DiscoveryHandler:
    """Handles OAuth 2.0 discovery endpoints and metadata"""
    
    def __init__(self, config):
        self.config = config
        self._jwks_cache = {}  # Simple in-memory cache for JWKS
        
    async def oauth_protected_resource_metadata(self, request: web.Request) -> web.Response:
        """OAuth 2.0 Protected Resource Metadata (RFC 9728)"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version"
                }
            )
        
        try:
            base_url = f"{request.scheme}://{request.host}"
            
            metadata = {
                "resource": base_url,
                "authorization_servers": [base_url],  # Point to our proxy, not Okta directly
                "scopes_supported": self.config.get_all_scopes(),
                "bearer_methods_supported": ["header"],
                "resource_documentation": f"{base_url}/docs",
                "mcp_protocol_version": "2025-06-18",
                "resource_type": "mcp-server"
            }
            
            logger.debug("Serving OAuth protected resource metadata")
            response = web.json_response(metadata)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
            
        except Exception as e:
            logger.error(f"Error serving protected resource metadata: {e}")
            response = web.json_response(
                {"error": "Failed to retrieve protected resource metadata"}, 
                status=503
            )
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    
    async def oauth_authorization_server_metadata(self, request: web.Request) -> web.Response:
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version"
                }
            )
        
        try:
            # Try Okta's OpenID Connect discovery endpoint first (most common)
            metadata_urls = [
                f"{self.config.org_url}/.well-known/openid-configuration"
            ]
            
            okta_metadata = None
            for metadata_url in metadata_urls:
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.get(metadata_url, timeout=10.0)
                        if response.status_code == 200:
                            okta_metadata = response.json()
                            logger.debug(f"Successfully fetched Okta metadata from {metadata_url}")
                            break
                        else:
                            logger.debug(f"Failed to fetch from {metadata_url}: HTTP {response.status_code}")
                except Exception as e:
                    logger.debug(f"Failed to fetch from {metadata_url}: {e}")
                    continue
            
            if okta_metadata:
                # Replace key endpoints with our proxy endpoints where we have proxies
                base_url = f"{request.scheme}://{request.host}"
                okta_metadata["authorization_endpoint"] = f"{base_url}/oauth2/v1/authorize"
                okta_metadata["token_endpoint"] = f"{base_url}/oauth2/v1/token"
                okta_metadata["registration_endpoint"] = f"{base_url}/oauth2/v1/clients"
                
                # Return Okta's metadata with our proxy endpoints
                response = web.json_response(okta_metadata)
                response.headers["Access-Control-Allow-Origin"] = "*"
                return response
            else:
                raise Exception("All metadata URLs failed")
            
        except Exception as e:
            logger.error(f"Error fetching Okta metadata: {e}")
            # Fallback metadata with our proxy endpoints where available
            base_url = f"{request.scheme}://{request.host}"
            fallback_metadata = {
                "issuer": self.config.org_url,
                "authorization_endpoint": f"{base_url}/oauth2/v1/authorize",
                "token_endpoint": f"{base_url}/oauth2/v1/token", 
                "userinfo_endpoint": f"{self.config.org_url}/oauth2/v1/userinfo",
                "registration_endpoint": f"{base_url}/oauth2/v1/clients",
                "jwks_uri": f"{self.config.org_url}/oauth2/v1/keys",
                "scopes_supported": self.config.get_all_scopes() + ["openid", "profile", "email"],
                "response_types_supported": ["code", "token"],
                "grant_types_supported": ["authorization_code", "client_credentials"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                "code_challenge_methods_supported": ["S256"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            }
            
            logger.warning("Using fallback authorization server metadata")
            response = web.json_response(fallback_metadata)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    
    async def oauth_jwks_proxy(self, request: web.Request) -> web.Response:
        """Proxy to Okta's JWKS endpoint with caching"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                }
            )
        
        try:
            # Simple in-memory cache (in production, use Redis or similar)
            cache_key = "okta_jwks"
            cache_ttl = 300  # 5 minutes
            now = datetime.now(timezone.utc)
            
            # Check if we have cached JWKS
            if hasattr(self, '_jwks_cache'):
                cached_time, cached_data = self._jwks_cache.get(cache_key, (None, None))
                if cached_time and (now - cached_time).total_seconds() < cache_ttl:
                    logger.debug("Serving cached JWKS")
                    response = web.json_response(cached_data)
                    response.headers["Access-Control-Allow-Origin"] = "*"
                    return response
            
            # Fetch fresh JWKS from Okta
            jwks_url = f"{self.config.org_url}/oauth2/v1/keys"
            
            async with httpx.AsyncClient() as client:
                jwks_response = await client.get(jwks_url, timeout=10.0)
                jwks_response.raise_for_status()
                jwks_data = jwks_response.json()
            
            # Cache the result
            if not hasattr(self, '_jwks_cache'):
                self._jwks_cache = {}
            self._jwks_cache[cache_key] = (now, jwks_data)
            
            logger.info(f"Serving fresh JWKS with {len(jwks_data.get('keys', []))} keys")
            response = web.json_response(jwks_data)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
            
        except Exception as e:
            logger.error(f"Error fetching JWKS from Okta: {e}")
            response = web.json_response(
                {"error": "Failed to retrieve JWKS"}, 
                status=503
            )
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response

    async def permissions_info(self, request: web.Request) -> web.Response:
        """Display information about permissions requested"""
        scopes = self.config.okta_scopes
        
        scope_descriptions = {
            'openid': 'Verify your identity',
            'profile': 'Access your basic profile information (name, etc.)',
            'email': 'Access your email address',
            'okta.users.read': 'Read user information from your Okta organization',
            'okta.groups.read': 'Read group information from your Okta organization', 
            'okta.apps.read': 'Read application information from your Okta organization',
            'okta.events.read': 'Read event information from your Okta organization',
            'okta.logs.read': 'Read log information from your Okta organization',
            'okta.policies.read': 'Read policy information from your Okta organization',
            'okta.devices.read': 'Read device information from your Okta organization',
            'okta.factors.read': 'Read authentication factor information from your Okta organization'
        }
        
        scope_list = ""
        for scope in scopes:
            description = scope_descriptions.get(scope, f"Access {scope}")
            scope_list += f"<li><strong>{scope}</strong>: {description}</li>"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Permissions - Okta MCP Server</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .permissions {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .note {{ background: #e7f3ff; padding: 15px; border-left: 4px solid #2196F3; margin: 20px 0; }}
                .actions {{ text-align: center; margin: 30px 0; }}
                .btn {{ padding: 12px 24px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
                .btn-primary {{ background: #007bff; color: white; }}
                .btn-secondary {{ background: #6c757d; color: white; }}
                ul {{ line-height: 1.6; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 OAuth Permissions</h1>
                <p>The Okta MCP Server is requesting the following permissions:</p>
            </div>
            
            <div class="permissions">
                <h3>Requested Permissions:</h3>
                <ul>
                    {scope_list}
                </ul>
            </div>
            
            <div class="note">
                <strong>Note:</strong> This application uses Okta's organization authorization server to access API resources. 
                You will be prompted to explicitly grant consent for each virtual client that requests access to your Okta data.
            </div>
            
            <div class="actions">
                <a href="/oauth/login" class="btn btn-primary">Continue to Login</a>
                <a href="/" class="btn btn-secondary">Cancel</a>
            </div>
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
                <small>For more information about OAuth security, see our <a href="/docs">documentation</a>.</small>
            </div>
        </body>
        </html>
        """
        
        return web.Response(text=html, content_type='text/html')
        
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        base_url = f"{request.scheme}://{request.host}"
        
        return web.json_response({
            "status": "healthy",
            "oauth_configured": bool(self.config.okta_client_id),
            "timestamp": datetime.utcnow().isoformat(),
            "oauth_discovery": {
                "protected_resource": f"{base_url}/.well-known/oauth-protected-resource",
                "authorization_server": f"{base_url}/.well-known/oauth-authorization-server", 
                "jwks": f"{base_url}/.well-known/jwks.json"
            },
            "mcp_endpoints": {
                "tools": f"{base_url}/mcp/tools",
                "resources": f"{base_url}/mcp/resources",
                "prompts": f"{base_url}/mcp/prompts"
            }
        })
