"""OAuth provider configuration for Okta MCP Server"""

import os
import logging
from typing import List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class OAuthConfig:
    """OAuth configuration for Okta integration"""
    
    # OAuth Client Configuration
    client_id: str
    client_secret: str
    org_url: str
    
    # OAuth Endpoints (auto-generated from org_url)
    authorization_url: str = field(init=False)
    token_url: str = field(init=False)
    jwks_uri: str = field(init=False)
    
    # Scopes and Permissions
    default_scopes: List[str] = field(default_factory=lambda: [
        "openid", "profile", "email",
        "okta.users.read", "okta.groups.read", "okta.apps.read",
        "okta.events.read", "okta.logs.read", "okta.policies.read",
        "okta.devices.read", "okta.factors.read"
    ])
    
    admin_scopes: List[str] = field(default_factory=lambda: [])  # Empty for now
    
    # Security Settings
    require_https: bool = True
    token_validation: bool = True
    audience: Optional[str] = None
    redirect_uri: Optional[str] = None
    
    def __post_init__(self):
        """Generate OAuth endpoints from org URL"""
        # Allow HTTP for local development (localhost)
        if not self.org_url.startswith("https://"):
            if self.require_https and not ("localhost" in self.org_url or "127.0.0.1" in self.org_url):
                raise ValueError("HTTPS required for OAuth endpoints (except localhost)")
        
        # Use ORG authorization server for Okta API scopes (not default)
        # Only the org authorization server can mint access tokens with Okta API scopes
        base_url = f"{self.org_url}/oauth2/v1"  # NOT /oauth2/default/v1
        self.authorization_url = f"{base_url}/authorize"
        self.token_url = f"{base_url}/token"
        self.jwks_uri = f"{base_url}/keys"
        
        # Set default audience if not provided
        if not self.audience:
            self.audience = "okta-mcp-server"
    
    @property
    def okta_domain(self) -> str:
        """Extract the Okta domain from the org URL"""
        # Remove protocol and any path
        domain = self.org_url.replace("https://", "").replace("http://", "")
        if "/" in domain:
            domain = domain.split("/")[0]
        return domain
    
    @classmethod
    def from_environment(cls) -> 'OAuthConfig':
        """Create OAuth config from environment variables"""
        try:
            # Support both new and legacy environment variable names
            config = cls(
                client_id=os.getenv("OKTA_CLIENT_ID") or os.getenv("OKTA_OAUTH_CLIENT_ID", ""),
                client_secret=os.getenv("OKTA_CLIENT_SECRET") or os.getenv("OKTA_OAUTH_CLIENT_SECRET", ""),
                org_url=os.getenv("OKTA_ORG_URL") or os.getenv("OKTA_CLIENT_ORGURL", ""),
                audience=os.getenv("OKTA_OAUTH_AUDIENCE", "fctrid-okta-mcp-server"),  # Updated default
                redirect_uri=os.getenv("OAUTH_REDIRECT_URI", "http://localhost:3001/oauth/callback"),
                require_https=os.getenv("OAUTH_REQUIRE_HTTPS", "true").lower() == "true"
            )
            
            # Override default scopes if specified
            oauth_scopes = os.getenv("OAUTH_SCOPES", "")
            if oauth_scopes:
                config.default_scopes = oauth_scopes.split()
                logger.info(f"Using custom OAuth scopes: {config.default_scopes}")
            else:
                logger.info(f"Using default OAuth scopes: {config.default_scopes}")
            
            # Validate required fields
            missing_fields = []
            if not config.client_id:
                missing_fields.append("OKTA_CLIENT_ID")
            if not config.client_secret:
                missing_fields.append("OKTA_CLIENT_SECRET")
            if not config.org_url:
                missing_fields.append("OKTA_ORG_URL")
            
            if missing_fields:
                raise ValueError(
                    f"Missing required environment variables: {', '.join(missing_fields)}"
                )
            
            logger.info(f"OAuth configuration loaded: {config.org_url}")
            return config
            
        except Exception as e:
            logger.error(f"Failed to load OAuth configuration: {e}")
            raise
    
    def get_all_scopes(self) -> List[str]:
        """Get all available scopes (only default scopes for now)"""
        return self.default_scopes


def create_okta_oauth_provider():
    """Create OAuth provider for Okta authorization"""
    from fastmcp.server.auth import OAuthProvider  # Import here to avoid circular imports
    
    try:
        # Load OAuth configuration
        config = OAuthConfig.from_environment()
        
        # Create OAuth provider
        oauth_provider = OAuthProvider(
            client_id=config.client_id,
            client_secret=config.client_secret,
            authorization_url=config.authorization_url,
            token_url=config.token_url,
            scopes=config.get_all_scopes()
        )
        
        logger.info(f"OAuth provider created for {config.org_url}")
        return oauth_provider
        
    except Exception as e:
        logger.error(f"Failed to create OAuth provider: {e}")
        raise


def validate_oauth_token(token: str, config: Optional[OAuthConfig] = None) -> dict:
    """Validate OAuth token and extract user information"""
    import jwt
    
    if not config:
        config = OAuthConfig.from_environment()
    
    try:
        # SECURITY FIX: This function should NOT be used for token validation
        # Use the proper JWT verification in oauth_proxy.py instead
        # This is here for backward compatibility only
        logger.warning("validate_oauth_token called - use _verify_and_decode_jwt in oauth_proxy for proper validation")
        
        # For basic information extraction only (NOT for security validation)
        decoded = jwt.decode(
            token, 
            options={"verify_signature": False}  # INSECURE: For info extraction only
        )
        
        # Extract user information
        user_info = {
            "user_id": decoded.get("sub"),
            "email": decoded.get("email"),
            "name": decoded.get("name"),
            "roles": decoded.get("roles", []),
            "scopes": decoded.get("scope", "").split(),
            "audience": decoded.get("aud"),
            "issuer": decoded.get("iss")
        }
        
        logger.debug(f"Token info extracted for user: {user_info['email']}")
        return user_info
        
    except Exception as e:
        logger.error(f"Token info extraction failed: {e}")
        raise