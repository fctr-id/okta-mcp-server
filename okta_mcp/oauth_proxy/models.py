"""
Data models and configuration for OAuth Proxy Server
"""

import os
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class VirtualClient:
    """Represents a virtual OAuth client (like VS Code, Claude Desktop)"""
    client_id: str
    redirect_uri: str
    scopes: List[str]
    created_at: datetime
    name: Optional[str] = None
    
    
@dataclass
class AuthorizationCode:
    """Represents an OAuth authorization code"""
    code: str
    client_id: str
    user_id: str
    scopes: List[str]
    code_challenge: str
    code_challenge_method: str
    redirect_uri: str
    created_at: datetime
    expires_at: datetime
    rbac_role: str = "viewer"  # Default role for RBAC
    used: bool = False


@dataclass
class UserConsent:
    """Represents user consent for a virtual client"""
    user_id: str
    virtual_client_id: str
    scopes: List[str]
    granted_at: datetime
    expires_at: datetime


@dataclass
class OAuthConfig:
    """OAuth configuration from environment variables"""
    
    def __init__(self):
        self.okta_client_id = os.getenv('OKTA_CLIENT_ID')
        self.okta_client_secret = os.getenv('OKTA_CLIENT_SECRET') 
        self.okta_domain = os.getenv('OKTA_DOMAIN')
        self.okta_oauth_audience = os.getenv('OKTA_OAUTH_AUDIENCE')
        self.oauth_redirect_uri = os.getenv('OAUTH_REDIRECT_URI', 'http://localhost:3001/oauth/callback')
        self.okta_scopes = os.getenv('OKTA_SCOPES', 'openid profile email okta.users.read').split()
        
        # Validate required settings
        if not all([self.okta_client_id, self.okta_client_secret, self.okta_domain]):
            raise ValueError("Missing required OAuth environment variables")
            
    @property
    def authorization_endpoint(self) -> str:
        return f"https://{self.okta_domain}/oauth2/v1/authorize"
        
    @property  
    def token_endpoint(self) -> str:
        return f"https://{self.okta_domain}/oauth2/v1/token"
        
    @property
    def userinfo_endpoint(self) -> str:
        return f"https://{self.okta_domain}/oauth2/v1/userinfo"
        
    @property
    def jwks_uri(self) -> str:
        return f"https://{self.okta_domain}/oauth2/v1/keys"
        
    @property
    def issuer(self) -> str:
        return f"https://{self.okta_domain}"


class ProxyConfig:
    """Configuration for the OAuth proxy server"""
    
    def __init__(self):
        self.host = os.getenv('OAUTH_PROXY_HOST', 'localhost')
        self.port = int(os.getenv('OAUTH_PROXY_PORT', '3001'))
        self.backend_server_path = os.getenv('BACKEND_SERVER_PATH', './main.py')
        self.session_timeout_hours = int(os.getenv('SESSION_TIMEOUT_HOURS', '24'))
        self.cleanup_interval_minutes = int(os.getenv('CLEANUP_INTERVAL_MINUTES', '60'))
        self.cors_origins = os.getenv('CORS_ORIGINS', '*').split(',')
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
