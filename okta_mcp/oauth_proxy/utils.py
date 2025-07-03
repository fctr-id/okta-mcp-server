"""
Utility functions for OAuth Proxy Server
"""

import secrets
import hashlib
import base64
import logging
from typing import Dict, Any
from aiohttp import web


def generate_secure_session_key() -> bytes:
    """Generate a secure session key for cookie encryption"""
    return secrets.token_bytes(32)


def generate_secure_state() -> str:
    """Generate a secure random state for OAuth flow"""
    return secrets.token_urlsafe(32)


def generate_secure_code_verifier() -> str:
    """Generate a secure code verifier for PKCE"""
    return secrets.token_urlsafe(96)


def create_user_bound_session_key(user_id: str, session_id: str) -> str:
    """Create a user-bound session key for enhanced security"""
    return hashlib.sha256(f"{user_id}:{session_id}".encode()).hexdigest()


def create_401_response(request: web.Request, error_description: str) -> web.Response:
    """
    Create RFC 6750 compliant 401 response with WWW-Authenticate header
    """
    # Get the base URL for the resource metadata
    scheme = request.scheme
    host = request.host
    base_url = f"{scheme}://{host}"
    
    # RFC 6750 compliant WWW-Authenticate header
    www_authenticate = (
        f'Bearer realm="{base_url}", '
        f'error="invalid_token", '
        f'error_description="{error_description}", '
        f'resource="{base_url}/.well-known/oauth-protected-resource"'
    )
    
    return web.json_response(
        {
            "error": "invalid_token",
            "error_description": error_description,
            "resource_metadata": f"{base_url}/.well-known/oauth-protected-resource"
        },
        status=401,
        headers={'WWW-Authenticate': www_authenticate}
    )


def validate_token_audience(token: Dict[str, Any], expected_audience: str, okta_domain: str) -> bool:
    """
    Validate JWT token audience with flexibility for Okta's behavior
    
    Okta's org authorization server always issues tokens with the org URL as audience,
    even when a different audience is requested. We accept both the configured 
    audience and the Okta org URL to handle this properly.
    """
    token_audience = token.get('aud', [])
    
    # Ensure audience is a list
    if isinstance(token_audience, str):
        token_audience = [token_audience]
    
    # Accept either the configured audience or the Okta org URL
    valid_audiences = [expected_audience, f"https://{okta_domain}"]
    
    # Check if any valid audience is present in the token
    return any(aud in token_audience for aud in valid_audiences)


def audit_log(event_type: str, user_id: str = None, details: Dict[str, Any] = None):
    """Log security-relevant events for audit purposes"""
    logger = logging.getLogger("oauth_proxy.audit")
    
    log_entry = {
        "event_type": event_type,
        "user_id": user_id,
        "details": details or {}
    }
    
    logger.info(f"AUDIT: {log_entry}")


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create specific loggers
    oauth_logger = logging.getLogger("oauth_proxy")
    oauth_logger.setLevel(logging.INFO)
    
    audit_logger = logging.getLogger("oauth_proxy.audit")
    audit_logger.setLevel(logging.INFO)
